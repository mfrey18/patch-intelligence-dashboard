import { PRIORITY_THRESHOLDS } from "../domain/priority";
import { INTELLIGENCE_WINDOW_MONTHS } from "../ingestion/operational-policy";

export const DASHBOARD_PROJECTION_VERSION = 1;

export interface DashboardProjectionResult {
  status: "success";
  version: number;
  generatedAt: string;
  cveCount: number;
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
  await db.batch([
    db.prepare(PROJECTION_UPSERT_SQL).bind(
      PRIORITY_THRESHOLDS.criticalHighEpssPercentile,
      PRIORITY_THRESHOLDS.highVeryHighEpssPercentile,
      generatedAt,
    ),
    db.prepare(`DELETE FROM cve_dashboard_facts
      WHERE cve_id NOT IN (
        SELECT ac.cve_id FROM advisories a JOIN advisory_cves ac ON ac.advisory_id=a.id
        WHERE COALESCE(a.published_at,a.source_updated_at)>=date('now','-${INTELLIGENCE_WINDOW_MONTHS} months')
        UNION
        SELECT cve_id FROM kev_entries
        WHERE active=1 AND date(date_added)>=date('now','-${INTELLIGENCE_WINDOW_MONTHS} months')
      )`),
    db.prepare(`INSERT INTO dashboard_projection_state
      (id,projection_version,generated_at,source_run_id,cve_count,status)
      SELECT 'current',?,?,?,COUNT(*),'published' FROM cve_dashboard_facts WHERE 1=1
      ON CONFLICT(id) DO UPDATE SET projection_version=excluded.projection_version,
        generated_at=excluded.generated_at,source_run_id=excluded.source_run_id,
        cve_count=excluded.cve_count,status=excluded.status`)
      .bind(DASHBOARD_PROJECTION_VERSION, generatedAt, sourceRunId),
  ]);
  const count = Number(await db.prepare("SELECT COUNT(*) count FROM cve_dashboard_facts").first("count") ?? 0);
  return { status: "success", version: DASHBOARD_PROJECTION_VERSION, generatedAt, cveCount: count };
}

const PROJECTION_UPSERT_SQL = `INSERT INTO cve_dashboard_facts (
  cve_id,title,vendor,vendor_ids,product,severity_rank,cvss,epss,epss_percentile,
  kev,known_exploited,zero_day,patch_available,mitigation_available,workaround_available,
  published_at,modified_at,cwe,priority,projected_at
)
WITH current_epss AS (
  SELECT eo.cve_id,eo.score,eo.percentile
  FROM epss_observations eo JOIN epss_datasets ed ON ed.score_date=eo.score_date
  WHERE ed.is_current=1 AND ed.status='published'
), latest_revisions AS (
  SELECT ar.id,ar.advisory_id FROM advisory_revisions ar
  WHERE ar.id=(SELECT ar2.id FROM advisory_revisions ar2 WHERE ar2.advisory_id=ar.advisory_id ORDER BY ar2.observed_at DESC LIMIT 1)
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
    (SELECT GROUP_CONCAT(DISTINCT pp.name)
      FROM advisory_cves pac JOIN advisories pa ON pa.id=pac.advisory_id
      JOIN latest_revisions par ON par.advisory_id=pa.id
      JOIN affected_products pap ON pap.advisory_id=pa.id AND pap.advisory_revision_id=par.id
        AND (pap.cve_id=c.id OR pap.cve_id IS NULL)
      JOIN products pp ON pp.id=pap.product_id
      WHERE pac.cve_id=c.id AND COALESCE(pa.published_at,pa.source_updated_at)>=date('now','-${INTELLIGENCE_WINDOW_MONTHS} months')) product,
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
  LEFT JOIN remediation_flags rf ON rf.cve_id=c.id
  WHERE a.id IS NOT NULL OR EXISTS(SELECT 1 FROM kev_entries k WHERE k.cve_id=c.id AND k.active=1 AND date(k.date_added)>=date('now','-${INTELLIGENCE_WINDOW_MONTHS} months'))
  GROUP BY c.id,ce.score,ce.percentile
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
  cwe=excluded.cwe,priority=excluded.priority,projected_at=excluded.projected_at`;
