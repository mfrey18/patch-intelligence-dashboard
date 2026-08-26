import type { DashboardAnalyticsPanel, DashboardAnalyticsResponse, DashboardResponse, PatchTuesdayReleaseEvent, SourceHealth } from "./contracts";
import type { DashboardVulnerabilityRow, NormalizedSeverity } from "../domain/types";
import { calculatePriority, PRIORITY_THRESHOLDS } from "../domain/priority";
import { EMERGING_CHANGE_WINDOW_DAYS, EPSS_MOVER_DATE_TOLERANCE_DAYS, EPSS_MOVER_LOOKBACK_DAYS, HIGH_EPSS_PERCENTILE, MIN_EPSS_PERCENTILE_DELTA, emergingReasons, intelligenceChangeCategory } from "../domain/intelligence";
import { INTELLIGENCE_WINDOW_MONTHS } from "../ingestion/operational-policy";

interface BaseRow {
  cve_id: string; title: string; vendor: string; product: string | null; severity_rank: number; cvss: number | null; epss: number | null; epss_percentile: number | null; kev: number; known_exploited: number; zero_day: number; patch_available: number | null; mitigation_available: number; workaround_available: number; published_at: string | null; modified_at: string | null;
}

export async function queryDashboard(db: D1Database, url: URL): Promise<DashboardResponse> {
  const startedAt = performance.now();
  const params = url.searchParams;
  const projection = await hasPublishedProjection(db);
  const { cte, bindings } = projection ? buildProjectedFilteredCte(params) : buildCanonicalFilteredCte(params);
  const coreOnly = params.get("include") === "core";
  const limit = clamp(Number(params.get("limit") ?? 50), 1, 100);
  const offset = decodeCursor(params.get("cursor"));
  const sort = sortSql(params.get("sort"));
  const [
    rowsResult, summary, severityRows, vendorRows, productSeries, changes,
    recentChanges, sourceHealth, latestReleaseEvent, activity, epssMovers,
    emergingVulnerabilities, vendorThreatSeries, changeCategoryCounts, cweAnalytics,
  ] = await Promise.all([
    db.prepare(`${cte} SELECT * FROM filtered ORDER BY ${sort} LIMIT ? OFFSET ?`).bind(...bindings, limit + 1, offset).all<BaseRow>(),
    db.prepare(`${cte} SELECT COUNT(*) total, COALESCE(SUM(severity_rank=4),0) critical, COALESCE(SUM(severity_rank=3),0) high, COALESCE(SUM(known_exploited),0) known_exploited, COALESCE(SUM(kev),0) kev, COALESCE(SUM(zero_day),0) zero_day, COALESCE(SUM(patch_available=1),0) patch_available, COALESCE(SUM(kev=1 OR known_exploited=1),0) p1, COALESCE(SUM(kev=0 AND known_exploited=0 AND ((severity_rank=4 AND epss_percentile>=?) OR (severity_rank=3 AND epss_percentile>=?))),0) p2 FROM filtered`).bind(...bindings, PRIORITY_THRESHOLDS.criticalHighEpssPercentile, PRIORITY_THRESHOLDS.highVeryHighEpssPercentile).first<Record<string, number>>(),
    db.prepare(`${cte} SELECT severity_rank, COUNT(*) value FROM filtered GROUP BY severity_rank ORDER BY severity_rank DESC`).bind(...bindings).all<{ severity_rank: number; value: number }>(),
    db.prepare(`${cte} SELECT vendor, COUNT(*) value FROM filtered GROUP BY vendor ORDER BY value DESC LIMIT 12`).bind(...bindings).all<{ vendor: string; value: number }>(),
    coreOnly ? Promise.resolve([]) : queryProductSeries(db, cte, bindings, params.get("vendor")),
    queryChanges(db, cte, bindings),
    queryRecentChanges(db, cte, bindings),
    querySourceHealth(db),
    coreOnly ? Promise.resolve(null) : queryLatestReleaseEvent(db),
    coreOnly ? Promise.resolve({ vulnerabilityActivity: [], threatSignalActivity: [] }) : queryActivity(db, cte, bindings),
    coreOnly ? Promise.resolve([]) : queryEpssMovers(db, cte, bindings),
    coreOnly ? Promise.resolve([]) : queryEmergingVulnerabilities(db, cte, bindings),
    coreOnly ? Promise.resolve([]) : queryVendorThreatSeries(db, cte, bindings),
    coreOnly ? Promise.resolve({ threat: 0, assessment: 0, advisory: 0, remediation: 0 }) : queryChangeCategoryCounts(db, cte, bindings),
    coreOnly ? Promise.resolve({ knownCoverage: 0, total: 0, series: [] }) : queryCweAnalytics(db, cte, bindings),
  ]);
  const allRows = rowsResult.results ?? [];
  const hasMore = allRows.length > limit;
  const rows = allRows.slice(0, limit).map(toDashboardRow);
  const total = Number(summary?.total ?? 0);
  const p1 = Number(summary?.p1 ?? 0); const p2 = Number(summary?.p2 ?? 0);

  const response: DashboardResponse = {
    generatedAt: new Date().toISOString(),
    metrics: { total, critical: Number(summary?.critical ?? 0), high: Number(summary?.high ?? 0), knownExploited: Number(summary?.known_exploited ?? 0), kev: Number(summary?.kev ?? 0), zeroDay: Number(summary?.zero_day ?? 0), patchAvailable: Number(summary?.patch_available ?? 0) },
    changes,
    priorityDistribution: { P1: p1, P2: p2, P3: Math.max(0, total - p1 - p2) },
    severitySeries: (severityRows.results ?? []).map((row) => ({ label: severityFromRank(row.severity_rank), value: Number(row.value) })),
    vendorSeries: (vendorRows.results ?? []).map((row) => ({ label: row.vendor, value: Number(row.value) })),
    productSeries,
    vulnerabilityActivity: activity.vulnerabilityActivity,
    threatSignalActivity: activity.threatSignalActivity,
    epssMovers,
    emergingVulnerabilities,
    vendorThreatSeries,
    changeCategoryCounts,
    cweAnalytics,
    rows,
    recentChanges,
    nextCursor: hasMore ? encodeCursor(offset + limit) : null,
    sourceHealth,
    latestReleaseEvent,
  };
  console.log(JSON.stringify({ event: "dashboard_query", mode: projection ? "projection" : "canonical_fallback", include: coreOnly ? "core" : "full", durationMs: Number((performance.now() - startedAt).toFixed(2)) }));
  return response;
}

export const DASHBOARD_ANALYTICS_PANELS = new Set<DashboardAnalyticsPanel>(["activity", "emerging", "epss-movers", "vendor-threats", "cwe", "products", "patch-tuesday"]);

export async function queryDashboardAnalytics(db: D1Database, url: URL, panel: DashboardAnalyticsPanel): Promise<DashboardAnalyticsResponse> {
  const startedAt = performance.now();
  if (panel === "patch-tuesday") {
    const releaseEvents = await queryPatchTuesdayEvents(db, 13);
    console.log(JSON.stringify({ event: "dashboard_analytics_query", panel, mode: "release_events", durationMs: Number((performance.now() - startedAt).toFixed(2)) }));
    return { generatedAt: new Date().toISOString(), panel, latestReleaseEvent: releaseEvents[0] ?? null, releaseEvents: releaseEvents.slice(0, 12) };
  }
  const projection = await hasPublishedProjection(db);
  const { cte, bindings } = projection ? buildProjectedFilteredCte(url.searchParams) : buildCanonicalFilteredCte(url.searchParams);
  let data: Omit<DashboardAnalyticsResponse, "generatedAt" | "panel">;
  switch (panel) {
    case "activity": data = await queryActivity(db, cte, bindings); break;
    case "emerging": {
      const [emergingVulnerabilities, changeCategoryCounts] = await Promise.all([queryEmergingVulnerabilities(db, cte, bindings), queryChangeCategoryCounts(db, cte, bindings)]);
      data = { emergingVulnerabilities, changeCategoryCounts };
      break;
    }
    case "epss-movers": data = { epssMovers: await queryEpssMovers(db, cte, bindings) }; break;
    case "vendor-threats": data = { vendorThreatSeries: await queryVendorThreatSeries(db, cte, bindings) }; break;
    case "cwe": data = { cweAnalytics: await queryCweAnalytics(db, cte, bindings) }; break;
    case "products": data = { productSeries: await queryProductSeries(db, cte, bindings, url.searchParams.get("vendor")) }; break;
  }
  console.log(JSON.stringify({ event: "dashboard_analytics_query", panel, mode: projection ? "projection" : "canonical_fallback", durationMs: Number((performance.now() - startedAt).toFixed(2)) }));
  return { generatedAt: new Date().toISOString(), panel, ...data };
}

export async function queryDashboardExport(db: D1Database, url: URL): Promise<{ generatedAt: string; rows: DashboardVulnerabilityRow[]; nextCursor: string | null }> {
  const projection = await hasPublishedProjection(db);
  const { cte, bindings } = projection ? buildProjectedFilteredCte(url.searchParams) : buildCanonicalFilteredCte(url.searchParams);
  const limit = clamp(Number(url.searchParams.get("limit") ?? 1_000), 1, 1_000);
  const offset = decodeCursor(url.searchParams.get("cursor"));
  const result = await db.prepare(`${cte} SELECT * FROM filtered ORDER BY ${sortSql(url.searchParams.get("sort"))} LIMIT ? OFFSET ?`).bind(...bindings, limit + 1, offset).all<BaseRow>();
  const rows = result.results ?? [];
  return { generatedAt: new Date().toISOString(), rows: rows.slice(0, limit).map(toDashboardRow), nextCursor: rows.length > limit ? encodeCursor(offset + limit) : null };
}

export interface ProjectionParityMetrics {
  total: number;
  critical: number;
  high: number;
  knownExploited: number;
  kev: number;
  zeroDay: number;
  patchAvailable: number;
  p1: number;
  p2: number;
  p3: number;
  microsoft: number;
  cisco: number;
}

async function queryRecentChanges(db: D1Database, cte: string, bindings: unknown[]): Promise<DashboardResponse["recentChanges"]> {
  const result = await db.prepare(`${cte} SELECT ic.cve_id, ic.advisory_id, ic.change_type, ic.summary, ic.observed_at FROM intelligence_changes ic JOIN filtered f ON f.cve_id=ic.cve_id ORDER BY ic.observed_at DESC LIMIT 8`).bind(...bindings).all<Record<string, unknown>>();
  return (result.results ?? []).map((row) => ({ cveId: nullableString(row.cve_id), advisoryId: nullableString(row.advisory_id), changeType: String(row.change_type), summary: String(row.summary), observedAt: String(row.observed_at) }));
}

async function queryActivity(db: D1Database, cte: string, bindings: unknown[]): Promise<Pick<DashboardResponse, "vulnerabilityActivity" | "threatSignalActivity">> {
  const result = await db.prepare(`${cte} SELECT substr(published_at,1,7) bucket,
    COALESCE(SUM(severity_rank=4),0) critical, COALESCE(SUM(severity_rank=3),0) high, COALESCE(SUM(severity_rank=2),0) medium, COALESCE(SUM(severity_rank=1),0) low,
    COALESCE(SUM(known_exploited),0) known_exploited, COALESCE(SUM(kev),0) kev, COALESCE(SUM(zero_day),0) zero_day, COALESCE(SUM(epss_percentile>=?),0) high_epss
    FROM filtered WHERE published_at IS NOT NULL GROUP BY substr(published_at,1,7) ORDER BY bucket`).bind(...bindings, HIGH_EPSS_PERCENTILE).all<Record<string, unknown>>();
  const observed = new Map((result.results ?? []).map((row) => [String(row.bucket), row]));
  const buckets = rollingMonthBuckets(new Date());
  return {
    vulnerabilityActivity: buckets.map(({ bucket, label }) => { const row = observed.get(bucket); return { bucket, label, critical: Number(row?.critical ?? 0), high: Number(row?.high ?? 0), medium: Number(row?.medium ?? 0), low: Number(row?.low ?? 0) }; }),
    threatSignalActivity: buckets.map(({ bucket, label }) => { const row = observed.get(bucket); return { bucket, label, knownExploited: Number(row?.known_exploited ?? 0), kev: Number(row?.kev ?? 0), zeroDay: Number(row?.zero_day ?? 0), highEpss: Number(row?.high_epss ?? 0) }; }),
  };
}

async function hasPublishedProjection(db: D1Database): Promise<boolean> {
  try {
    const state = await db.prepare("SELECT cve_count FROM dashboard_projection_state WHERE id='current' AND status='published'").first<{ cve_count: number }>();
    return Number(state?.cve_count ?? 0) > 0;
  } catch {
    return false;
  }
}

export async function queryCanonicalProjectionParity(db: D1Database): Promise<ProjectionParityMetrics> {
  const { cte, bindings } = buildCanonicalFilteredCte(new URLSearchParams());
  const row = await db.prepare(`${cte} SELECT COUNT(*) total,
    COALESCE(SUM(severity_rank=4),0) critical,COALESCE(SUM(severity_rank=3),0) high,
    COALESCE(SUM(known_exploited),0) known_exploited,COALESCE(SUM(kev),0) kev,
    COALESCE(SUM(zero_day),0) zero_day,COALESCE(SUM(patch_available=1),0) patch_available,
    COALESCE(SUM(kev=1 OR known_exploited=1),0) p1,
    COALESCE(SUM(kev=0 AND known_exploited=0 AND ((severity_rank=4 AND epss_percentile>=?) OR (severity_rank=3 AND epss_percentile>=?))),0) p2,
    COALESCE(SUM(instr(lower(vendor),'microsoft')>0),0) microsoft,
    COALESCE(SUM(instr(lower(vendor),'cisco')>0),0) cisco
    FROM filtered`).bind(...bindings, PRIORITY_THRESHOLDS.criticalHighEpssPercentile, PRIORITY_THRESHOLDS.highVeryHighEpssPercentile).first<Record<string, number>>();
  return parityMetrics(row);
}

function parityMetrics(row: Record<string, number> | null): ProjectionParityMetrics {
  const total = Number(row?.total ?? 0); const p1 = Number(row?.p1 ?? 0); const p2 = Number(row?.p2 ?? 0);
  return { total, critical: Number(row?.critical ?? 0), high: Number(row?.high ?? 0), knownExploited: Number(row?.known_exploited ?? 0), kev: Number(row?.kev ?? 0), zeroDay: Number(row?.zero_day ?? 0), patchAvailable: Number(row?.patch_available ?? 0), p1, p2, p3: Math.max(0, total - p1 - p2), microsoft: Number(row?.microsoft ?? 0), cisco: Number(row?.cisco ?? 0) };
}

async function queryEpssMovers(db: D1Database, cte: string, bindings: unknown[]): Promise<DashboardResponse["epssMovers"]> {
  const result = await db.prepare(`${cte}, current_points AS (
      SELECT eo.cve_id, eo.score_date, eo.score, eo.percentile, eo.model_version FROM epss_observations eo JOIN epss_datasets ed ON ed.score_date=eo.score_date AND ed.is_current=1 AND ed.status='published'
    ), prior_dates AS (
      SELECT cp.cve_id, (SELECT po.score_date FROM epss_observations po JOIN epss_datasets pd ON pd.score_date=po.score_date AND pd.status='published' WHERE po.cve_id=cp.cve_id AND po.score_date BETWEEN date(cp.score_date,?) AND date(cp.score_date,?) AND COALESCE(po.model_version,'')=COALESCE(cp.model_version,'') ORDER BY po.score_date DESC LIMIT 1) previous_score_date FROM current_points cp
    )
    SELECT f.cve_id, f.vendor, f.product, cp.score_date, cp.score, cp.percentile, cp.model_version, pd.previous_score_date, po.score previous_score, po.percentile previous_percentile
    FROM filtered f JOIN current_points cp ON cp.cve_id=f.cve_id JOIN prior_dates pd ON pd.cve_id=cp.cve_id JOIN epss_observations po ON po.cve_id=cp.cve_id AND po.score_date=pd.previous_score_date
    WHERE pd.previous_score_date IS NOT NULL AND cp.percentile-po.percentile>=?
    ORDER BY cp.percentile-po.percentile DESC, cp.score-po.score DESC LIMIT 10`).bind(
      ...bindings,
      `-${EPSS_MOVER_LOOKBACK_DAYS + EPSS_MOVER_DATE_TOLERANCE_DAYS} days`,
      `-${EPSS_MOVER_LOOKBACK_DAYS - EPSS_MOVER_DATE_TOLERANCE_DAYS} days`,
      MIN_EPSS_PERCENTILE_DELTA,
    ).all<Record<string, unknown>>();
  return (result.results ?? []).map((row) => ({
    cveId: String(row.cve_id), vendor: String(row.vendor), product: nullableString(row.product), previousScoreDate: String(row.previous_score_date), scoreDate: String(row.score_date),
    previousScore: Number(row.previous_score), score: Number(row.score), previousPercentile: Number(row.previous_percentile), percentile: Number(row.percentile),
    scoreDelta: Number(row.score) - Number(row.previous_score), percentileDelta: Number(row.percentile) - Number(row.previous_percentile), modelVersion: nullableString(row.model_version),
  }));
}

async function queryEmergingVulnerabilities(db: D1Database, cte: string, bindings: unknown[]): Promise<DashboardResponse["emergingVulnerabilities"]> {
  const recentSince = `-${EMERGING_CHANGE_WINDOW_DAYS} days`;
  const result = await db.prepare(`${cte} SELECT f.*, GROUP_CONCAT(DISTINCT ic.change_type) recent_change_types, MAX(ic.observed_at) latest_change_at
    FROM filtered f LEFT JOIN intelligence_changes ic ON ic.cve_id=f.cve_id AND ic.observed_at>=datetime('now',?)
    WHERE EXISTS(SELECT 1 FROM intelligence_changes ec WHERE ec.cve_id=f.cve_id AND ec.observed_at>=datetime('now',?) AND ec.change_type IN ('EXPLOITATION_STATUS_CHANGED','ZERO_DAY_STATUS_CHANGED','KEV_ADDED','SEVERITY_CHANGED','CVSS_CHANGED'))
      OR (f.severity_rank=4 AND f.epss_percentile>=?) OR (f.severity_rank=3 AND f.epss_percentile>=?)
    GROUP BY f.cve_id ORDER BY f.known_exploited DESC, f.kev DESC, f.zero_day DESC, latest_change_at DESC, f.epss_percentile DESC LIMIT 12`).bind(...bindings, recentSince, recentSince, HIGH_EPSS_PERCENTILE, PRIORITY_THRESHOLDS.highVeryHighEpssPercentile).all<BaseRow & { recent_change_types: string | null; latest_change_at: string | null }>();
  return (result.results ?? []).map((row) => {
    const vulnerability = toDashboardRow(row);
    const reasons = emergingReasons({ knownExploited: vulnerability.knownExploited, kev: vulnerability.kev, zeroDay: vulnerability.zeroDay, severity: vulnerability.severity, epssPercentile: vulnerability.epssPercentile, recentChangeTypes: row.recent_change_types?.split(",").filter(Boolean) ?? [] });
    return { vulnerability, reasons, latestChangeAt: row.latest_change_at };
  }).filter((item) => item.reasons.length > 0);
}

async function queryVendorThreatSeries(db: D1Database, cte: string, bindings: unknown[]): Promise<DashboardResponse["vendorThreatSeries"]> {
  const result = await db.prepare(`${cte} SELECT f.vendor label, COUNT(*) total,
    COALESCE(SUM(f.known_exploited),0) known_exploited,
    COALESCE(SUM(f.kev),0) kev,
    COALESCE(SUM(f.zero_day),0) zero_day,
    COALESCE(SUM(f.epss_percentile>=?),0) high_epss
    FROM filtered f GROUP BY f.vendor ORDER BY known_exploited DESC, kev DESC, high_epss DESC, total DESC LIMIT 12`).bind(...bindings, HIGH_EPSS_PERCENTILE).all<Record<string, unknown>>();
  return (result.results ?? []).map((row) => ({ label: String(row.label), total: Number(row.total), knownExploited: Number(row.known_exploited), kev: Number(row.kev), zeroDay: Number(row.zero_day), highEpss: Number(row.high_epss) }));
}

async function queryProductSeries(db: D1Database, cte: string, bindings: unknown[], vendorId: string | null): Promise<DashboardResponse["productSeries"]> {
  const result = await db.prepare(`${cte} SELECT COALESCE(p.family,p.name) label, COUNT(DISTINCT f.cve_id) value
    FROM filtered f JOIN advisory_cves pac ON pac.cve_id=f.cve_id JOIN advisories pa ON pa.id=pac.advisory_id
    JOIN advisory_revisions par ON par.id=(SELECT par2.id FROM advisory_revisions par2 WHERE par2.advisory_id=pa.id ORDER BY par2.observed_at DESC LIMIT 1)
    JOIN affected_products pap ON pap.advisory_id=pa.id AND pap.advisory_revision_id=par.id AND (pap.cve_id=f.cve_id OR pap.cve_id IS NULL)
    JOIN products p ON p.id=pap.product_id WHERE (?='' OR pa.vendor_id=?)
    GROUP BY COALESCE(p.family,p.name) ORDER BY value DESC, label LIMIT 12`).bind(...bindings, vendorId ?? "", vendorId ?? "").all<{ label: string; value: number }>();
  return (result.results ?? []).map((row) => ({ label: row.label, value: Number(row.value) }));
}

async function queryChangeCategoryCounts(db: D1Database, cte: string, bindings: unknown[]): Promise<DashboardResponse["changeCategoryCounts"]> {
  const result = await db.prepare(`${cte} SELECT ic.change_type, COUNT(DISTINCT ic.id) value FROM intelligence_changes ic JOIN filtered f ON f.cve_id=ic.cve_id WHERE ic.observed_at>=datetime('now','-30 days') GROUP BY ic.change_type`).bind(...bindings).all<{ change_type: string; value: number }>();
  const counts: DashboardResponse["changeCategoryCounts"] = { threat: 0, assessment: 0, advisory: 0, remediation: 0 };
  for (const row of result.results ?? []) counts[intelligenceChangeCategory(row.change_type)] += Number(row.value);
  return counts;
}

async function queryCweAnalytics(db: D1Database, cte: string, bindings: unknown[]): Promise<DashboardResponse["cweAnalytics"]> {
  const [coverage, series] = await Promise.all([
    db.prepare(`${cte} SELECT COUNT(*) total, COALESCE(SUM(cwe IS NOT NULL AND trim(cwe)<>''),0) known FROM filtered`).bind(...bindings).first<Record<string, number>>(),
    db.prepare(`${cte} SELECT cwe label, COUNT(*) value, COALESCE(SUM(severity_rank=4),0) critical, COALESCE(SUM(known_exploited),0) exploited FROM filtered WHERE cwe IS NOT NULL AND trim(cwe)<>'' GROUP BY cwe ORDER BY value DESC LIMIT 10`).bind(...bindings).all<Record<string, unknown>>(),
  ]);
  return { knownCoverage: Number(coverage?.known ?? 0), total: Number(coverage?.total ?? 0), series: (series.results ?? []).map((row) => ({ label: String(row.label), value: Number(row.value), critical: Number(row.critical), exploited: Number(row.exploited) })) };
}

function rollingMonthBuckets(now: Date): Array<{ bucket: string; label: string }> {
  const values: Array<{ bucket: string; label: string }> = [];
  for (let offset = 5; offset >= 0; offset -= 1) {
    const date = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - offset, 1));
    values.push({ bucket: date.toISOString().slice(0, 7), label: new Intl.DateTimeFormat("en", { month: "short", timeZone: "UTC" }).format(date) });
  }
  return values;
}

function buildProjectedFilteredCte(params: URLSearchParams): { cte: string; bindings: unknown[] } {
  const where = ["1=1"];
  const bindings: unknown[] = [];
  const add = (condition: string, ...values: unknown[]) => { where.push(condition); bindings.push(...values); };
  if (params.get("vendor")) add("instr(vendor_ids, '|' || ? || '|') > 0", params.get("vendor"));
  if (params.get("product")) add("product LIKE ? ESCAPE '\\'", `%${escapeLike(params.get("product")!)}%`);
  const severity = params.get("severity")?.toLowerCase();
  if (severity) add("severity_rank = ?", severity === "critical" ? 4 : severity === "high" ? 3 : severity === "medium" ? 2 : severity === "low" ? 1 : 0);
  if (params.get("q")) {
    const term = `%${escapeLike(params.get("q")!.slice(0, 100))}%`;
    add("(cve_id LIKE ? ESCAPE '\\' OR title LIKE ? ESCAPE '\\' OR vendor LIKE ? ESCAPE '\\' OR product LIKE ? ESCAPE '\\')", term, term, term, term);
  }
  if (params.get("publishedFrom")) add("published_at >= ?", params.get("publishedFrom"));
  if (params.get("publishedTo")) add("published_at < datetime(?, '+1 day')", params.get("publishedTo"));
  if (params.get("modifiedFrom")) add("modified_at >= ?", params.get("modifiedFrom"));
  if (params.get("modifiedTo")) add("modified_at < datetime(?, '+1 day')", params.get("modifiedTo"));
  if (finiteParam(params, "cvssMin") != null) add("cvss >= ?", finiteParam(params, "cvssMin"));
  if (finiteParam(params, "cvssMax") != null) add("cvss <= ?", finiteParam(params, "cvssMax"));
  if (finiteParam(params, "epssPercentileMin") != null) add("epss_percentile >= ?", finiteParam(params, "epssPercentileMin"));
  if (finiteParam(params, "epssMin") != null) add("epss >= ?", finiteParam(params, "epssMin"));
  booleanFilterOuter(params, add, "kev", "kev");
  booleanFilterOuter(params, add, "exploited", "known_exploited");
  booleanFilterOuter(params, add, "zeroDay", "zero_day");
  booleanFilterOuter(params, add, "patchAvailable", "patch_available");
  booleanFilterOuter(params, add, "mitigationAvailable", "mitigation_available");
  booleanFilterOuter(params, add, "workaroundAvailable", "workaround_available");
  const priority = params.get("priority")?.toUpperCase();
  if (priority === "P1" || priority === "P2" || priority === "P3") add("priority = ?", priority);
  const view = params.get("view");
  if (view === "needs-action") add("priority='P1'");
  if (view === "changed") add("EXISTS(SELECT 1 FROM intelligence_changes view_changes WHERE view_changes.cve_id=cve_dashboard_facts.cve_id AND view_changes.observed_at>=datetime('now','-1 day'))");
  if (view === "patch-new") add("patch_available=1 AND EXISTS(SELECT 1 FROM intelligence_changes view_changes WHERE view_changes.cve_id=cve_dashboard_facts.cve_id AND view_changes.observed_at>=datetime('now','-1 day') AND view_changes.change_type IN ('REMEDIATION_CHANGED','FIXED_VERSION_CHANGED','MITIGATION_ADDED','WORKAROUND_ADDED'))");
  return { cte: `WITH filtered AS (SELECT cve_id,title,vendor,product,severity_rank,cvss,epss,epss_percentile,kev,known_exploited,zero_day,patch_available,mitigation_available,workaround_available,published_at,modified_at,cwe,priority FROM cve_dashboard_facts WHERE ${where.join(" AND ")})`, bindings };
}

function buildCanonicalFilteredCte(params: URLSearchParams): { cte: string; bindings: unknown[] } {
  const where = ["1=1"]; const bindings: unknown[] = [];
  const add = (condition: string, ...values: unknown[]) => { where.push(condition); bindings.push(...values); };
  if (params.get("vendor")) add("a.vendor_id = ?", params.get("vendor"));
  if (params.get("product")) add("EXISTS(SELECT 1 FROM affected_products apf JOIN products pf ON pf.id=apf.product_id WHERE apf.advisory_id=a.id AND apf.advisory_revision_id=ar.id AND (apf.cve_id=c.id OR apf.cve_id IS NULL) AND pf.name LIKE ?)", `%${escapeLike(params.get("product")!)}%`);
  if (params.get("severity")) add("a.id IS NOT NULL AND ac.normalized_severity = ?", params.get("severity")!.toLowerCase());
  if (params.get("q")) { const term = `%${escapeLike(params.get("q")!.slice(0, 100))}%`; add("(c.id LIKE ? OR a.title LIKE ? OR (a.id IS NOT NULL AND ac.vendor_description LIKE ?) OR v.name LIKE ? OR EXISTS(SELECT 1 FROM affected_products aps JOIN products ps ON ps.id=aps.product_id WHERE aps.advisory_id=a.id AND aps.advisory_revision_id=ar.id AND (aps.cve_id=c.id OR aps.cve_id IS NULL) AND ps.name LIKE ?))", term, term, term, term, term); }
  if (params.get("publishedFrom")) add("date(a.published_at) >= date(?)", params.get("publishedFrom"));
  if (params.get("publishedTo")) add("date(a.published_at) <= date(?)", params.get("publishedTo"));
  if (params.get("modifiedFrom")) add("date(a.source_updated_at) >= date(?)", params.get("modifiedFrom"));
  if (params.get("modifiedTo")) add("date(a.source_updated_at) <= date(?)", params.get("modifiedTo"));
  const booleanFilter = (key: string, expression: string) => { const value = params.get(key); if (value === "true" || value === "false") add(`${expression} = ?`, value === "true" ? 1 : 0); };
  booleanFilter("kev", "EXISTS(SELECT 1 FROM kev_entries kf WHERE kf.cve_id=c.id AND kf.active=1)");
  booleanFilter("exploited", "EXISTS(SELECT 1 FROM exploit_evidence ef WHERE ef.cve_id=c.id AND ef.evidence_type='known_exploitation' AND ef.status='confirmed')");
  booleanFilter("zeroDay", "EXISTS(SELECT 1 FROM exploit_evidence zf WHERE zf.cve_id=c.id AND zf.evidence_type='zero_day' AND zf.status='confirmed')");

  const outer = ["1=1"];
  const addOuter = (condition: string, ...values: unknown[]) => { outer.push(condition); bindings.push(...values); };
  if (finiteParam(params, "cvssMin") != null) addOuter("cvss >= ?", finiteParam(params, "cvssMin"));
  if (finiteParam(params, "cvssMax") != null) addOuter("cvss <= ?", finiteParam(params, "cvssMax"));
  if (finiteParam(params, "epssPercentileMin") != null) addOuter("epss_percentile >= ?", finiteParam(params, "epssPercentileMin"));
  if (finiteParam(params, "epssMin") != null) addOuter("epss >= ?", finiteParam(params, "epssMin"));
  booleanFilterOuter(params, addOuter, "patchAvailable", "patch_available");
  booleanFilterOuter(params, addOuter, "mitigationAvailable", "mitigation_available");
  booleanFilterOuter(params, addOuter, "workaroundAvailable", "workaround_available");
  const priority = params.get("priority")?.toUpperCase();
  if (priority === "P1") outer.push("(kev=1 OR known_exploited=1)");
  if (priority === "P2") { outer.push("kev=0 AND known_exploited=0 AND ((severity_rank=4 AND epss_percentile>=?) OR (severity_rank=3 AND epss_percentile>=?))"); bindings.push(PRIORITY_THRESHOLDS.criticalHighEpssPercentile, PRIORITY_THRESHOLDS.highVeryHighEpssPercentile); }
  if (priority === "P3") { outer.push("kev=0 AND known_exploited=0 AND NOT ((severity_rank=4 AND COALESCE(epss_percentile,0)>=?) OR (severity_rank=3 AND COALESCE(epss_percentile,0)>=?))"); bindings.push(PRIORITY_THRESHOLDS.criticalHighEpssPercentile, PRIORITY_THRESHOLDS.highVeryHighEpssPercentile); }
  const view = params.get("view");
  if (view === "needs-action") outer.push("(kev=1 OR known_exploited=1)");
  if (view === "changed") outer.push("EXISTS(SELECT 1 FROM intelligence_changes view_changes WHERE view_changes.cve_id=base.cve_id AND view_changes.observed_at>=datetime('now','-1 day'))");
  if (view === "patch-new") outer.push("patch_available=1 AND EXISTS(SELECT 1 FROM intelligence_changes view_changes WHERE view_changes.cve_id=base.cve_id AND view_changes.observed_at>=datetime('now','-1 day') AND view_changes.change_type IN ('REMEDIATION_CHANGED','FIXED_VERSION_CHANGED','MITIGATION_ADDED','WORKAROUND_ADDED'))");

  const cte = `WITH current_epss AS (
    SELECT eo.cve_id, eo.score, eo.percentile FROM epss_observations eo JOIN epss_datasets ed ON ed.score_date=eo.score_date AND ed.is_current=1
  ), latest_revisions AS (
    SELECT ar.id, ar.advisory_id FROM advisory_revisions ar
    WHERE ar.id=(SELECT ar2.id FROM advisory_revisions ar2 WHERE ar2.advisory_id=ar.advisory_id ORDER BY ar2.observed_at DESC LIMIT 1)
  ), current_remediation_rows AS (
    SELECT r.cve_id, r.advisory_id, r.patch_available, r.kind
    FROM remediations r JOIN latest_revisions lr ON lr.id=r.advisory_revision_id
  ), remediation_assertions AS (
    SELECT cve_id, patch_available, kind FROM current_remediation_rows WHERE cve_id IS NOT NULL
    UNION ALL
    SELECT ac.cve_id, r.patch_available, r.kind
    FROM current_remediation_rows r JOIN advisory_cves ac ON ac.advisory_id=r.advisory_id
    WHERE r.cve_id IS NULL
  ), remediation_flags AS (
    SELECT cve_id,
      MAX(CASE WHEN patch_available=1 THEN 1 WHEN patch_available=0 THEN 0 ELSE NULL END) patch_available,
      MAX(CASE WHEN kind='mitigation' THEN 1 ELSE 0 END) mitigation_available,
      MAX(CASE WHEN kind='workaround' THEN 1 ELSE 0 END) workaround_available
    FROM remediation_assertions GROUP BY cve_id
  ), base AS (
    SELECT c.id cve_id, COALESCE(c.description, MAX(CASE WHEN a.id IS NOT NULL THEN ac.vendor_description END), MAX(a.title), c.id) title,
      COALESCE(GROUP_CONCAT(DISTINCT v.name),'CISA KEV') vendor,
      (SELECT GROUP_CONCAT(DISTINCT pp.name) FROM advisory_cves pac JOIN advisories pa ON pa.id=pac.advisory_id JOIN latest_revisions par ON par.advisory_id=pa.id JOIN affected_products pap ON pap.advisory_id=pa.id AND (pap.cve_id=c.id OR pap.cve_id IS NULL) AND pap.advisory_revision_id=par.id JOIN products pp ON pp.id=pap.product_id WHERE pac.cve_id=c.id AND COALESCE(pa.published_at,pa.source_updated_at)>=date('now','-${INTELLIGENCE_WINDOW_MONTHS} months')) product,
      MAX(CASE WHEN a.id IS NULL THEN 0 ELSE CASE ac.normalized_severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END END) severity_rank,
      MAX(CASE WHEN a.id IS NOT NULL THEN ac.vendor_cvss_score END) cvss, ce.score epss, ce.percentile epss_percentile,
      CASE WHEN EXISTS(SELECT 1 FROM kev_entries k WHERE k.cve_id=c.id AND k.active=1) THEN 1 ELSE 0 END kev,
      CASE WHEN EXISTS(SELECT 1 FROM exploit_evidence ee WHERE ee.cve_id=c.id AND ee.evidence_type='known_exploitation' AND ee.status='confirmed') THEN 1 ELSE 0 END known_exploited,
      CASE WHEN EXISTS(SELECT 1 FROM exploit_evidence ee WHERE ee.cve_id=c.id AND ee.evidence_type='zero_day' AND ee.status='confirmed') THEN 1 ELSE 0 END zero_day,
      MAX(rf.patch_available) patch_available,
      COALESCE(MAX(rf.mitigation_available),0) mitigation_available,
      COALESCE(MAX(rf.workaround_available),0) workaround_available,
      MIN(a.published_at) published_at, MAX(a.source_updated_at) modified_at, c.cwe
    FROM cves c
      LEFT JOIN advisory_cves ac ON ac.cve_id=c.id
      LEFT JOIN advisories a ON a.id=ac.advisory_id AND COALESCE(a.published_at,a.source_updated_at)>=date('now','-${INTELLIGENCE_WINDOW_MONTHS} months')
      LEFT JOIN vendors v ON v.id=a.vendor_id
      LEFT JOIN latest_revisions ar ON ar.advisory_id=a.id
      LEFT JOIN current_epss ce ON ce.cve_id=c.id
      LEFT JOIN remediation_flags rf ON rf.cve_id=c.id
    WHERE (a.id IS NOT NULL OR EXISTS(SELECT 1 FROM kev_entries scope_kev WHERE scope_kev.cve_id=c.id AND scope_kev.active=1 AND date(scope_kev.date_added)>=date('now','-${INTELLIGENCE_WINDOW_MONTHS} months'))) AND ${where.join(" AND ")}
    GROUP BY c.id, ce.score, ce.percentile
  ), filtered AS (SELECT * FROM base WHERE ${outer.join(" AND ")})`;
  return { cte, bindings };
}

function booleanFilterOuter(params: URLSearchParams, add: (condition: string, ...values: unknown[]) => void, key: string, expression: string): void {
  const value = params.get(key);
  if (value === "true" || value === "false") add(`${expression} = ?`, value === "true" ? 1 : 0);
}

async function queryChanges(db: D1Database, cte: string, bindings: unknown[]): Promise<DashboardResponse["changes"]> {
  const prior = await db.prepare("SELECT MAX((SELECT r.started_at FROM source_runs r WHERE r.source_id=s.id AND r.completed_at IS NOT NULL ORDER BY r.completed_at DESC LIMIT 1 OFFSET 1)) started_at FROM sources s WHERE s.enabled=1").first<{ started_at: string | null }>();
  const since = prior?.started_at ?? null;
  if (!since) return { since: null, newCves: 0, newCritical: 0, newlyKnownExploited: 0, newKev: 0, revisedAdvisories: 0, newRemediation: 0 };
  const row = await db.prepare(`${cte} SELECT COUNT(DISTINCT CASE WHEN ic.change_type='NEW_CVE' THEN ic.cve_id END) new_cves, COUNT(DISTINCT CASE WHEN ic.change_type='NEW_CVE' AND f.severity_rank=4 THEN ic.cve_id END) new_critical, COUNT(DISTINCT CASE WHEN ic.change_type='EXPLOITATION_STATUS_CHANGED' AND f.known_exploited=1 THEN ic.cve_id END) newly_exploited, COUNT(DISTINCT CASE WHEN ic.change_type='KEV_ADDED' THEN ic.cve_id END) new_kev, COUNT(DISTINCT CASE WHEN ic.change_type='ADVISORY_REVISED' THEN ic.advisory_id END) revised, COUNT(DISTINCT CASE WHEN ic.change_type IN ('REMEDIATION_CHANGED','FIXED_VERSION_CHANGED','MITIGATION_ADDED','WORKAROUND_ADDED') THEN ic.advisory_id END) new_remediation FROM intelligence_changes ic JOIN filtered f ON f.cve_id=ic.cve_id WHERE ic.observed_at>=?`).bind(...bindings, since).first<Record<string, number>>();
  return { since, newCves: Number(row?.new_cves ?? 0), newCritical: Number(row?.new_critical ?? 0), newlyKnownExploited: Number(row?.newly_exploited ?? 0), newKev: Number(row?.new_kev ?? 0), revisedAdvisories: Number(row?.revised ?? 0), newRemediation: Number(row?.new_remediation ?? 0) };
}

async function querySourceHealth(db: D1Database): Promise<SourceHealth[]> {
  const result = await db.prepare(`SELECT s.id source_id, s.name, r.started_at last_attempt,
    (SELECT completed_at FROM source_runs ok WHERE ok.source_id=s.id AND (ok.status IN ('success','unchanged') OR (ok.status='partial' AND ok.records_failed=0)) ORDER BY ok.completed_at DESC LIMIT 1) last_success,
    (SELECT completed_at FROM source_runs bad WHERE bad.source_id=s.id AND (bad.status='failed' OR bad.records_failed>0) ORDER BY bad.completed_at DESC LIMIT 1) last_failure,
    CAST((julianday(r.completed_at)-julianday(r.started_at))*86400000 AS INTEGER) duration_ms, r.status result, r.ingestion_mode,
    COALESCE(r.records_discovered,0) discovered, COALESCE(r.records_inserted,0) inserted, COALESCE(r.records_changed,0) changed, COALESCE(r.records_unchanged,0) unchanged, COALESCE(r.records_failed,0) failed, COALESCE(r.bound_hit,0) bound_hit, r.error_summary,
    l.expires_at lease_expires_at,
    cp.id checkpoint_id, cp.status checkpoint_status, cp.window_start checkpoint_window_start, cp.window_end checkpoint_window_end
    FROM sources s
    LEFT JOIN source_runs r ON r.id=(SELECT r2.id FROM source_runs r2 WHERE r2.source_id=s.id ORDER BY r2.started_at DESC LIMIT 1)
    LEFT JOIN ingestion_leases l ON l.source_id=s.id
    LEFT JOIN ingestion_checkpoints cp ON cp.id=(SELECT cp2.id FROM ingestion_checkpoints cp2 WHERE cp2.source_id=s.id AND cp2.status<>'complete' ORDER BY cp2.updated_at DESC LIMIT 1)
    WHERE s.enabled=1 ORDER BY s.name`).all<Record<string, unknown>>();
  return (result.results ?? []).map((row) => {
    const lastSuccess = nullableString(row.last_success);
    const leaseExpiresAt = nullableString(row.lease_expires_at);
    return {
      sourceId: String(row.source_id), name: String(row.name), lastAttempt: nullableString(row.last_attempt), lastSuccess, lastFailure: nullableString(row.last_failure),
      durationMs: row.duration_ms == null ? null : Number(row.duration_ms), result: nullableString(row.result), mode: nullableString(row.ingestion_mode),
      freshness: !lastSuccess ? "never" : Date.now() - new Date(lastSuccess).getTime() > 36 * 60 * 60 * 1000 ? "stale" : "fresh",
      discovered: Number(row.discovered ?? 0), inserted: Number(row.inserted ?? 0), changed: Number(row.changed ?? 0), unchanged: Number(row.unchanged ?? 0), failed: Number(row.failed ?? 0), boundHit: Boolean(row.bound_hit), errorSummary: nullableString(row.error_summary),
      lease: { active: Boolean(leaseExpiresAt && new Date(leaseExpiresAt) > new Date()), expiresAt: leaseExpiresAt },
      checkpoint: row.checkpoint_id ? { id: String(row.checkpoint_id), status: String(row.checkpoint_status), windowStart: String(row.checkpoint_window_start), windowEnd: String(row.checkpoint_window_end) } : null,
    } satisfies SourceHealth;
  });
}

async function queryLatestReleaseEvent(db: D1Database): Promise<DashboardResponse["latestReleaseEvent"]> {
  return (await queryPatchTuesdayEvents(db, 2))[0] ?? null;
}

export async function queryPatchTuesdayEvents(db: D1Database, limit = 12): Promise<PatchTuesdayReleaseEvent[]> {
  const boundedLimit = clamp(limit, 1, 24);
  const events = await db.prepare("SELECT id,label,event_date,source_url,reported_cve_count,reported_at,reported_product_families_json FROM release_events WHERE vendor_id='microsoft' AND event_type='patch_tuesday' ORDER BY event_date DESC LIMIT ?").bind(boundedLimit).all<Record<string, unknown>>();
  const eventRows = events.results ?? [];
  if (!eventRows.length) return [];
  const ids = eventRows.map((row) => String(row.id));
  const placeholders = ids.map(() => "?").join(",");
  const [statsResult, productsResult] = await Promise.all([
    db.prepare(`SELECT rea.release_event_id,
      COUNT(DISTINCT ac.cve_id) linked_total,
      COUNT(DISTINCT CASE WHEN ac.normalized_severity='critical' THEN ac.cve_id END) critical,
      COUNT(DISTINCT CASE WHEN ac.normalized_severity='high' THEN ac.cve_id END) high,
      COUNT(DISTINCT CASE WHEN EXISTS(SELECT 1 FROM exploit_evidence ee WHERE ee.cve_id=ac.cve_id AND ee.evidence_type='known_exploitation' AND ee.status='confirmed') THEN ac.cve_id END) exploited,
      COUNT(DISTINCT CASE WHEN EXISTS(SELECT 1 FROM exploit_evidence ee WHERE ee.cve_id=ac.cve_id AND ee.evidence_type='zero_day' AND ee.status='confirmed') THEN ac.cve_id END) zero_day,
      COUNT(DISTINCT CASE WHEN EXISTS(SELECT 1 FROM kev_entries k WHERE k.cve_id=ac.cve_id AND k.active=1) THEN ac.cve_id END) kev
      FROM release_event_advisories rea JOIN advisories a ON a.id=rea.advisory_id
      JOIN advisory_cves ac ON ac.advisory_id=rea.advisory_id
      WHERE rea.release_event_id IN (${placeholders}) AND a.vendor_advisory_id LIKE 'advisory:%'
      GROUP BY rea.release_event_id`).bind(...ids).all<Record<string, unknown>>(),
    db.prepare(`SELECT rea.release_event_id,COALESCE(p.family,p.name) label,COUNT(DISTINCT ac.cve_id) value
      FROM release_event_advisories rea JOIN advisories a ON a.id=rea.advisory_id
      JOIN advisory_revisions ar ON ar.id=(SELECT ar2.id FROM advisory_revisions ar2 WHERE ar2.advisory_id=a.id ORDER BY ar2.observed_at DESC LIMIT 1)
      JOIN affected_products ap ON ap.advisory_revision_id=ar.id JOIN products p ON p.id=ap.product_id
      JOIN advisory_cves ac ON ac.advisory_id=a.id AND (ap.cve_id IS NULL OR ac.cve_id=ap.cve_id)
      WHERE rea.release_event_id IN (${placeholders}) AND a.vendor_advisory_id LIKE 'advisory:%'
      GROUP BY rea.release_event_id,COALESCE(p.family,p.name)
      ORDER BY rea.release_event_id,value DESC`).bind(...ids).all<Record<string, unknown>>(),
  ]);
  const stats = new Map((statsResult.results ?? []).map((row) => [String(row.release_event_id), row]));
  const products = new Map<string, Array<{ label: string; value: number }>>();
  for (const row of productsResult.results ?? []) {
    const id = String(row.release_event_id); const list = products.get(id) ?? [];
    if (list.length < 8) list.push({ label: String(row.label), value: Number(row.value) });
    products.set(id, list);
  }
  const base = eventRows.map((event) => patchTuesdayEvent(event, stats.get(String(event.id)), products.get(String(event.id)) ?? []));
  return base.map((event, index) => {
    const previous = base[index + 1];
    return { ...event, comparison: previous ? { label: previous.label, eventDate: previous.eventDate, totalDelta: event.total - previous.total, linkedTotal: previous.linkedTotal, linkedTotalDelta: event.linkedTotal - previous.linkedTotal, criticalDelta: event.critical - previous.critical, highDelta: event.high - previous.high, knownExploitedDelta: event.knownExploited - previous.knownExploited, zeroDayDelta: event.zeroDay - previous.zeroDay, kevDelta: event.kev - previous.kev } : null };
  });
}

function patchTuesdayEvent(event: Record<string, unknown>, stats: Record<string, unknown> | undefined, linkedProductFamilies: Array<{ label: string; value: number }>): PatchTuesdayReleaseEvent {
  const linkedTotal = Number(stats?.linked_total ?? 0);
  const reported = event.reported_cve_count == null ? null : Number(event.reported_cve_count);
  const total = reported ?? linkedTotal;
  const linkDelta = reported == null ? 0 : linkedTotal - reported;
  const reconciliationStatus = reported == null ? "unreported" : linkDelta === 0 ? "matched" : linkDelta < 0 ? "partial" : "overlinked";
  const reportedProductFamilies = parseProductFamilies(event.reported_product_families_json);
  return {
    id: String(event.id), label: String(event.label), eventDate: String(event.event_date), total, linkedTotal,
    totalBasis: reported == null ? "linked_advisories" : "vendor_reported", totalSourceUrl: nullableString(event.source_url), reportedAt: nullableString(event.reported_at),
    reconciliationStatus, linkDelta, linkCoveragePercent: reported && reported > 0 ? Number((linkedTotal / reported * 100).toFixed(1)) : null,
    critical: Number(stats?.critical ?? 0), high: Number(stats?.high ?? 0), knownExploited: Number(stats?.exploited ?? 0), zeroDay: Number(stats?.zero_day ?? 0), kev: Number(stats?.kev ?? 0),
    productFamilyBasis: reportedProductFamilies.length ? "vendor_reported" : "linked_advisories",
    productFamilies: reportedProductFamilies.length ? reportedProductFamilies : linkedProductFamilies,
    linkedProductFamilies, comparison: null,
  };
}

function parseProductFamilies(value: unknown): Array<{ label: string; value: number }> {
  if (typeof value !== "string") return [];
  try {
    const parsed = JSON.parse(value) as unknown;
    if (!Array.isArray(parsed)) return [];
    return parsed.flatMap((item) => {
      if (!item || typeof item !== "object") return [];
      const label = (item as { label?: unknown }).label; const rawValue = (item as { value?: unknown }).value;
      return typeof label === "string" && Number.isFinite(Number(rawValue)) ? [{ label, value: Number(rawValue) }] : [];
    });
  } catch { return []; }
}

function toDashboardRow(row: BaseRow): DashboardVulnerabilityRow {
  const severity = severityFromRank(row.severity_rank).toLowerCase() as NormalizedSeverity;
  const knownExploited = Boolean(row.known_exploited); const kev = Boolean(row.kev);
  return { cveId: row.cve_id, title: row.title, vendor: row.vendor, product: row.product, severity, cvss: nullableNumber(row.cvss), epss: nullableNumber(row.epss), epssPercentile: nullableNumber(row.epss_percentile), kev, knownExploited, zeroDay: Boolean(row.zero_day), patchAvailable: row.patch_available == null ? null : Boolean(row.patch_available), mitigationAvailable: Boolean(row.mitigation_available), workaroundAvailable: Boolean(row.workaround_available), publishedAt: row.published_at, modifiedAt: row.modified_at, priority: calculatePriority({ kev, exploitationStatus: knownExploited ? "known_exploited" : "unknown", severity, cvss: nullableNumber(row.cvss), epssPercentile: nullableNumber(row.epss_percentile) }) };
}

function severityFromRank(rank: number): string { return rank === 4 ? "Critical" : rank === 3 ? "High" : rank === 2 ? "Medium" : rank === 1 ? "Low" : "Unknown"; }
function sortSql(value: string | null): string { return value === "epss" ? "epss_percentile DESC, cve_id DESC" : value === "cvss" ? "cvss DESC, cve_id DESC" : value === "modified" ? "modified_at DESC, cve_id DESC" : value === "published" ? "published_at DESC, cve_id DESC" : "kev DESC, known_exploited DESC, severity_rank DESC, epss_percentile DESC, published_at DESC"; }
function finiteParam(params: URLSearchParams, key: string): number | null { const raw = params.get(key); if (raw == null || raw === "") return null; const value = Number(raw); return Number.isFinite(value) ? value : null; }
function nullableNumber(value: unknown): number | null { return value == null ? null : Number(value); }
function nullableString(value: unknown): string | null { return value == null ? null : String(value); }
function clamp(value: number, min: number, max: number): number { return Number.isFinite(value) ? Math.max(min, Math.min(max, Math.trunc(value))) : min; }
function escapeLike(value: string): string { return value.replace(/[\\%_]/g, (match) => `\\${match}`); }
function encodeCursor(offset: number): string { return btoa(JSON.stringify({ offset })); }
function decodeCursor(cursor: string | null): number { if (!cursor) return 0; try { const parsed = JSON.parse(atob(cursor)) as { offset?: number }; return clamp(Number(parsed.offset ?? 0), 0, 10_000_000); } catch { return 0; } }
