import { PRIORITY_THRESHOLDS } from "../domain/priority";
import { INTELLIGENCE_WINDOW_MONTHS } from "../ingestion/operational-policy";
import { queryCanonicalProjectionParity, type ProjectionParityMetrics } from "../api/dashboard-query";

export const DASHBOARD_PROJECTION_VERSION = 1;

export interface DashboardProjectionResult {
  status: "success";
  version: number;
  generatedAt: string;
  cveCount: number;
  parity: { status: "passed"; checkedAt: string; canonical: ProjectionParityMetrics; projected: ProjectionParityMetrics };
}

/**
 * Atomically publishes a disposable read model derived only from authoritative
 * normalized tables. A failed batch leaves the previous projection intact.
 */
export async function refreshDashboardProjection(
  db: D1Database,
  sourceRunId: string | null = null,
  now = new Date(),
): Promise<DashboardProjectionResult> {
  const generatedAt = now.toISOString();
  const holder = crypto.randomUUID();
  if (!(await acquireProjectionLease(db, holder, now))) throw new Error("Dashboard projection refresh is already running");
  try {
    await db.prepare("UPDATE dashboard_projection_state SET last_attempt_at=?,last_attempt_status='running',last_attempt_error=NULL WHERE id='current'").bind(generatedAt).run();
    await db.batch([
      db.prepare("DELETE FROM cve_dashboard_facts_staging"),
      db.prepare(projectionUpsertSql("cve_dashboard_facts_staging")).bind(
        PRIORITY_THRESHOLDS.criticalHighEpssPercentile,
        PRIORITY_THRESHOLDS.highVeryHighEpssPercentile,
        generatedAt,
      ),
    ]);
    const [canonical, projected] = await Promise.all([
      queryCanonicalProjectionParity(db),
      queryStoredProjectionParity(db, "cve_dashboard_facts_staging"),
    ]);
    const differences = parityDifferences(canonical, projected);
    if (differences.length > 0) throw new Error(`Dashboard projection parity failed: ${differences.join(", ")}`);
    const parity = { status: "passed" as const, checkedAt: generatedAt, canonical, projected };
    const parityJson = JSON.stringify(parity);
    await db.batch([
      db.prepare("DELETE FROM cve_dashboard_facts WHERE NOT EXISTS(SELECT 1 FROM cve_dashboard_facts_staging s WHERE s.cve_id=cve_dashboard_facts.cve_id)"),
      db.prepare(`INSERT OR IGNORE INTO cve_dashboard_facts (${FACT_COLUMNS}) SELECT ${FACT_COLUMNS} FROM cve_dashboard_facts_staging`),
      db.prepare(staticFactsUpdateSql()),
      db.prepare(volatileFactsUpdateSql()),
      db.prepare(`INSERT INTO dashboard_projection_state
        (id,projection_version,generated_at,source_run_id,cve_count,status,parity_checked_at,parity_status,parity_json,last_attempt_at,last_attempt_status,last_attempt_error)
        SELECT 'current',?,?,?,COUNT(*),'published',?,'passed',?,?,'success',NULL FROM cve_dashboard_facts_staging WHERE 1=1
        ON CONFLICT(id) DO UPDATE SET projection_version=excluded.projection_version,
          generated_at=excluded.generated_at,source_run_id=excluded.source_run_id,cve_count=excluded.cve_count,
          status=excluded.status,parity_checked_at=excluded.parity_checked_at,parity_status=excluded.parity_status,
          parity_json=excluded.parity_json,last_attempt_at=excluded.last_attempt_at,last_attempt_status=excluded.last_attempt_status,last_attempt_error=NULL`)
        .bind(DASHBOARD_PROJECTION_VERSION, generatedAt, sourceRunId, generatedAt, parityJson, generatedAt),
      db.prepare("DELETE FROM cve_dashboard_facts_staging"),
    ]);
    return { status: "success", version: DASHBOARD_PROJECTION_VERSION, generatedAt, cveCount: projected.total, parity };
  } catch (error) {
    const message = error instanceof Error ? error.message.slice(0, 500) : "Unknown projection failure";
    await db.prepare("UPDATE dashboard_projection_state SET last_attempt_at=?,last_attempt_status='failed',last_attempt_error=? WHERE id='current'").bind(generatedAt, message).run();
    throw error;
  } finally {
    await db.prepare("DELETE FROM dashboard_projection_leases WHERE id='current' AND holder=?").bind(holder).run();
  }
}

const FACT_COLUMNS = "cve_id,title,vendor,vendor_ids,product,severity_rank,cvss,epss,epss_percentile,kev,known_exploited,zero_day,patch_available,mitigation_available,workaround_available,published_at,modified_at,cwe,priority,projected_at";

const STATIC_FACT_COLUMNS = ["title", "vendor", "vendor_ids", "product", "severity_rank", "cvss", "kev", "known_exploited", "zero_day", "patch_available", "mitigation_available", "workaround_available", "published_at", "modified_at", "cwe"] as const;

function staticFactsUpdateSql(): string {
  const assignments = [...STATIC_FACT_COLUMNS, "epss", "epss_percentile", "priority", "projected_at"]
    .map((column) => `${column}=(SELECT s.${column} FROM cve_dashboard_facts_staging s WHERE s.cve_id=cve_dashboard_facts.cve_id)`).join(",");
  const changed = STATIC_FACT_COLUMNS
    .map((column) => `cve_dashboard_facts.${column} IS NOT s.${column}`).join(" OR ");
  return `UPDATE cve_dashboard_facts SET ${assignments} WHERE EXISTS(
    SELECT 1 FROM cve_dashboard_facts_staging s WHERE s.cve_id=cve_dashboard_facts.cve_id AND (${changed})
  )`;
}

function volatileFactsUpdateSql(): string {
  return `UPDATE cve_dashboard_facts SET
    epss=(SELECT s.epss FROM cve_dashboard_facts_staging s WHERE s.cve_id=cve_dashboard_facts.cve_id),
    epss_percentile=(SELECT s.epss_percentile FROM cve_dashboard_facts_staging s WHERE s.cve_id=cve_dashboard_facts.cve_id),
    priority=(SELECT s.priority FROM cve_dashboard_facts_staging s WHERE s.cve_id=cve_dashboard_facts.cve_id),
    projected_at=(SELECT s.projected_at FROM cve_dashboard_facts_staging s WHERE s.cve_id=cve_dashboard_facts.cve_id)
    WHERE EXISTS(SELECT 1 FROM cve_dashboard_facts_staging s
      WHERE s.cve_id=cve_dashboard_facts.cve_id AND (
        cve_dashboard_facts.epss IS NOT s.epss OR
        cve_dashboard_facts.epss_percentile IS NOT s.epss_percentile OR
        cve_dashboard_facts.priority IS NOT s.priority
      ))`;
}

function projectionUpsertSql(table: "cve_dashboard_facts_staging"): string { return `INSERT INTO ${table} (${FACT_COLUMNS})
WITH current_epss AS (
  SELECT eo.cve_id,eo.score,eo.percentile
  FROM epss_observations eo JOIN epss_datasets ed ON ed.score_date=eo.score_date
  WHERE ed.is_current=1 AND ed.status='published'
), latest_revisions AS (
  SELECT ar.id,ar.advisory_id FROM advisory_revisions ar
  WHERE ar.id=(SELECT ar2.id FROM advisory_revisions ar2 WHERE ar2.advisory_id=ar.advisory_id ORDER BY ar2.observed_at DESC LIMIT 1)
), current_product_rows AS (
  SELECT ap.cve_id,ap.advisory_id,p.name FROM affected_products ap
  JOIN latest_revisions lr ON lr.id=ap.advisory_revision_id JOIN products p ON p.id=ap.product_id
  JOIN advisories pa ON pa.id=ap.advisory_id
  WHERE COALESCE(pa.published_at,pa.source_updated_at)>=date('now','-${INTELLIGENCE_WINDOW_MONTHS} months')
), product_assertions AS (
  SELECT cve_id,name FROM current_product_rows WHERE cve_id IS NOT NULL
  UNION ALL
  SELECT ac.cve_id,pr.name FROM current_product_rows pr JOIN advisory_cves ac ON ac.advisory_id=pr.advisory_id
  WHERE pr.cve_id IS NULL
), product_names AS (
  SELECT cve_id,GROUP_CONCAT(DISTINCT name) product FROM product_assertions GROUP BY cve_id
), current_remediation_rows AS (
  SELECT r.cve_id,r.advisory_id,r.patch_available,r.kind
  FROM remediations r JOIN latest_revisions lr ON lr.id=r.advisory_revision_id
), remediation_assertions AS (
  SELECT cve_id,patch_available,kind FROM current_remediation_rows WHERE cve_id IS NOT NULL
  UNION ALL
  SELECT ac.cve_id,r.patch_available,r.kind FROM current_remediation_rows r
  JOIN advisory_cves ac ON ac.advisory_id=r.advisory_id WHERE r.cve_id IS NULL
), remediation_flags AS (
  SELECT cve_id,
    MAX(CASE WHEN patch_available=1 THEN 1 WHEN patch_available=0 THEN 0 END) patch_available,
    MAX(kind='mitigation') mitigation_available,
    MAX(kind='workaround') workaround_available
  FROM remediation_assertions GROUP BY cve_id
), scoped AS (
  SELECT c.id cve_id,
    COALESCE(c.description,MAX(CASE WHEN a.id IS NOT NULL THEN ac.vendor_description END),MAX(a.title),c.id) title,
    COALESCE(GROUP_CONCAT(DISTINCT v.name),'CISA KEV') vendor,
    '|' || COALESCE(REPLACE(GROUP_CONCAT(DISTINCT a.vendor_id),',','|'),'cisa') || '|' vendor_ids,
    pn.product,
    MAX(CASE WHEN a.id IS NULL THEN 0 ELSE CASE ac.normalized_severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END END) severity_rank,
    MAX(CASE WHEN a.id IS NOT NULL THEN ac.vendor_cvss_score END) cvss,ce.score epss,ce.percentile epss_percentile,
    EXISTS(SELECT 1 FROM kev_entries k WHERE k.cve_id=c.id AND k.active=1) kev,
    EXISTS(SELECT 1 FROM exploit_evidence ee WHERE ee.cve_id=c.id AND ee.evidence_type='known_exploitation' AND ee.status='confirmed') known_exploited,
    EXISTS(SELECT 1 FROM exploit_evidence ee WHERE ee.cve_id=c.id AND ee.evidence_type='zero_day' AND ee.status='confirmed') zero_day,
    MAX(rf.patch_available) patch_available,COALESCE(MAX(rf.mitigation_available),0) mitigation_available,
    COALESCE(MAX(rf.workaround_available),0) workaround_available,
    MIN(a.published_at) published_at,MAX(a.source_updated_at) modified_at,c.cwe
  FROM cves c LEFT JOIN advisory_cves ac ON ac.cve_id=c.id
  LEFT JOIN advisories a ON a.id=ac.advisory_id AND COALESCE(a.published_at,a.source_updated_at)>=date('now','-${INTELLIGENCE_WINDOW_MONTHS} months')
  LEFT JOIN vendors v ON v.id=a.vendor_id LEFT JOIN current_epss ce ON ce.cve_id=c.id
  LEFT JOIN product_names pn ON pn.cve_id=c.id
  LEFT JOIN remediation_flags rf ON rf.cve_id=c.id
  WHERE a.id IS NOT NULL OR EXISTS(SELECT 1 FROM kev_entries k WHERE k.cve_id=c.id AND k.active=1 AND date(k.date_added)>=date('now','-${INTELLIGENCE_WINDOW_MONTHS} months'))
  GROUP BY c.id,ce.score,ce.percentile,pn.product
)
SELECT cve_id,title,vendor,vendor_ids,product,severity_rank,cvss,epss,epss_percentile,
  kev,known_exploited,zero_day,patch_available,mitigation_available,workaround_available,
  published_at,modified_at,cwe,
  CASE WHEN kev=1 OR known_exploited=1 THEN 'P1'
    WHEN (severity_rank=4 AND COALESCE(epss_percentile,0)>=?) OR (severity_rank=3 AND COALESCE(epss_percentile,0)>=?) THEN 'P2'
    ELSE 'P3' END,?
FROM scoped WHERE 1=1
ON CONFLICT(cve_id) DO UPDATE SET title=excluded.title,vendor=excluded.vendor,vendor_ids=excluded.vendor_ids,
  product=excluded.product,severity_rank=excluded.severity_rank,cvss=excluded.cvss,epss=excluded.epss,
  epss_percentile=excluded.epss_percentile,kev=excluded.kev,known_exploited=excluded.known_exploited,
  zero_day=excluded.zero_day,patch_available=excluded.patch_available,mitigation_available=excluded.mitigation_available,
  workaround_available=excluded.workaround_available,published_at=excluded.published_at,modified_at=excluded.modified_at,
  cwe=excluded.cwe,priority=excluded.priority,projected_at=excluded.projected_at`; }

async function acquireProjectionLease(db: D1Database, holder: string, now: Date): Promise<boolean> {
  const acquiredAt = now.toISOString(); const expiresAt = new Date(now.getTime() + 10 * 60_000).toISOString();
  await db.prepare("INSERT INTO dashboard_projection_leases(id,holder,acquired_at,expires_at) VALUES('current',?,?,?) ON CONFLICT(id) DO UPDATE SET holder=excluded.holder,acquired_at=excluded.acquired_at,expires_at=excluded.expires_at WHERE dashboard_projection_leases.expires_at < ?").bind(holder, acquiredAt, expiresAt, acquiredAt).run();
  const row = await db.prepare("SELECT holder FROM dashboard_projection_leases WHERE id='current'").first<{ holder: string }>();
  return row?.holder === holder;
}

async function queryStoredProjectionParity(db: D1Database, table: "cve_dashboard_facts_staging"): Promise<ProjectionParityMetrics> {
  const row = await db.prepare(`SELECT COUNT(*) total,COALESCE(SUM(severity_rank=4),0) critical,COALESCE(SUM(severity_rank=3),0) high,
    COALESCE(SUM(known_exploited),0) known_exploited,COALESCE(SUM(kev),0) kev,COALESCE(SUM(zero_day),0) zero_day,
    COALESCE(SUM(patch_available=1),0) patch_available,COALESCE(SUM(priority='P1'),0) p1,COALESCE(SUM(priority='P2'),0) p2,
    COALESCE(SUM(instr(vendor_ids,'|microsoft|')>0),0) microsoft,COALESCE(SUM(instr(vendor_ids,'|cisco|')>0),0) cisco FROM ${table}`).first<Record<string, number>>();
  return normalizeParityMetrics(row);
}

function normalizeParityMetrics(row: Record<string, number> | null): ProjectionParityMetrics {
  const total = Number(row?.total ?? 0); const p1 = Number(row?.p1 ?? 0); const p2 = Number(row?.p2 ?? 0);
  return { total, critical: Number(row?.critical ?? 0), high: Number(row?.high ?? 0), knownExploited: Number(row?.known_exploited ?? 0), kev: Number(row?.kev ?? 0), zeroDay: Number(row?.zero_day ?? 0), patchAvailable: Number(row?.patch_available ?? 0), p1, p2, p3: Math.max(0, total - p1 - p2), microsoft: Number(row?.microsoft ?? 0), cisco: Number(row?.cisco ?? 0) };
}

function parityDifferences(canonical: ProjectionParityMetrics, projected: ProjectionParityMetrics): string[] {
  return (Object.keys(canonical) as Array<keyof ProjectionParityMetrics>).filter((key) => canonical[key] !== projected[key]).map((key) => `${key} canonical=${canonical[key]} projected=${projected[key]}`);
}
