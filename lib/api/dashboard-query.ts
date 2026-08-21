import type { DashboardResponse, SourceHealth } from "./contracts";
import type { DashboardVulnerabilityRow, NormalizedSeverity } from "../domain/types";
import { calculatePriority, PRIORITY_THRESHOLDS } from "../domain/priority";

interface BaseRow {
  cve_id: string; title: string; vendor: string; product: string | null; severity_rank: number; cvss: number | null; epss: number | null; epss_percentile: number | null; kev: number; known_exploited: number; zero_day: number; patch_available: number | null; mitigation_available: number; workaround_available: number; published_at: string | null; modified_at: string | null;
}

export async function queryDashboard(db: D1Database, url: URL): Promise<DashboardResponse> {
  const params = url.searchParams;
  const { cte, bindings } = buildFilteredCte(params);
  const limit = clamp(Number(params.get("limit") ?? 50), 1, 100);
  const offset = decodeCursor(params.get("cursor"));
  const sort = sortSql(params.get("sort"));
  const rowsResult = await db.prepare(`${cte} SELECT * FROM filtered ORDER BY ${sort} LIMIT ? OFFSET ?`).bind(...bindings, limit + 1, offset).all<BaseRow>();
  const allRows = rowsResult.results ?? [];
  const hasMore = allRows.length > limit;
  const rows = allRows.slice(0, limit).map(toDashboardRow);

  const summary = await db.prepare(`${cte} SELECT COUNT(*) total, COALESCE(SUM(severity_rank=4),0) critical, COALESCE(SUM(severity_rank=3),0) high, COALESCE(SUM(known_exploited),0) known_exploited, COALESCE(SUM(kev),0) kev, COALESCE(SUM(zero_day),0) zero_day, COALESCE(SUM(patch_available=1),0) patch_available, COALESCE(SUM(kev=1 OR known_exploited=1),0) p1, COALESCE(SUM(kev=0 AND known_exploited=0 AND ((severity_rank=4 AND epss_percentile>=?) OR (severity_rank=3 AND epss_percentile>=?))),0) p2 FROM filtered`).bind(...bindings, PRIORITY_THRESHOLDS.criticalHighEpssPercentile, PRIORITY_THRESHOLDS.highVeryHighEpssPercentile).first<Record<string, number>>();
  const total = Number(summary?.total ?? 0);
  const p1 = Number(summary?.p1 ?? 0); const p2 = Number(summary?.p2 ?? 0);

  const severityRows = await db.prepare(`${cte} SELECT severity_rank, COUNT(*) value FROM filtered GROUP BY severity_rank ORDER BY severity_rank DESC`).bind(...bindings).all<{ severity_rank: number; value: number }>();
  const vendorRows = await db.prepare(`${cte} SELECT vendor, COUNT(*) value FROM filtered GROUP BY vendor ORDER BY value DESC LIMIT 12`).bind(...bindings).all<{ vendor: string; value: number }>();
  const changes = await queryChanges(db, cte, bindings);
  const recentChanges = await queryRecentChanges(db, cte, bindings);
  const sourceHealth = await querySourceHealth(db);
  const latestReleaseEvent = await queryLatestReleaseEvent(db);

  return {
    generatedAt: new Date().toISOString(),
    metrics: { total, critical: Number(summary?.critical ?? 0), high: Number(summary?.high ?? 0), knownExploited: Number(summary?.known_exploited ?? 0), kev: Number(summary?.kev ?? 0), zeroDay: Number(summary?.zero_day ?? 0), patchAvailable: Number(summary?.patch_available ?? 0) },
    changes,
    priorityDistribution: { P1: p1, P2: p2, P3: Math.max(0, total - p1 - p2) },
    severitySeries: (severityRows.results ?? []).map((row) => ({ label: severityFromRank(row.severity_rank), value: Number(row.value) })),
    vendorSeries: (vendorRows.results ?? []).map((row) => ({ label: row.vendor, value: Number(row.value) })),
    rows,
    recentChanges,
    nextCursor: hasMore ? encodeCursor(offset + limit) : null,
    sourceHealth,
    latestReleaseEvent,
  };
}

async function queryRecentChanges(db: D1Database, cte: string, bindings: unknown[]): Promise<DashboardResponse["recentChanges"]> {
  const result = await db.prepare(`${cte} SELECT ic.cve_id, ic.advisory_id, ic.change_type, ic.summary, ic.observed_at FROM intelligence_changes ic JOIN filtered f ON f.cve_id=ic.cve_id ORDER BY ic.observed_at DESC LIMIT 8`).bind(...bindings).all<Record<string, unknown>>();
  return (result.results ?? []).map((row) => ({ cveId: nullableString(row.cve_id), advisoryId: nullableString(row.advisory_id), changeType: String(row.change_type), summary: String(row.summary), observedAt: String(row.observed_at) }));
}

function buildFilteredCte(params: URLSearchParams): { cte: string; bindings: unknown[] } {
  const where = ["1=1"]; const bindings: unknown[] = [];
  const add = (condition: string, ...values: unknown[]) => { where.push(condition); bindings.push(...values); };
  if (params.get("vendor")) add("a.vendor_id = ?", params.get("vendor"));
  if (params.get("product")) add("p.name LIKE ?", `%${escapeLike(params.get("product")!)}%`);
  if (params.get("severity")) add("ac.normalized_severity = ?", params.get("severity")!.toLowerCase());
  if (params.get("q")) { const term = `%${escapeLike(params.get("q")!.slice(0, 100))}%`; add("(c.id LIKE ? OR a.title LIKE ? OR ac.vendor_description LIKE ? OR v.name LIKE ? OR p.name LIKE ?)", term, term, term, term, term); }
  if (params.get("publishedFrom")) add("date(a.published_at) >= date(?)", params.get("publishedFrom"));
  if (params.get("publishedTo")) add("date(a.published_at) <= date(?)", params.get("publishedTo"));
  if (params.get("modifiedFrom")) add("date(a.source_updated_at) >= date(?)", params.get("modifiedFrom"));
  if (params.get("modifiedTo")) add("date(a.source_updated_at) <= date(?)", params.get("modifiedTo"));
  const booleanFilter = (key: string, expression: string) => { const value = params.get(key); if (value === "true" || value === "false") add(`${expression} = ?`, value === "true" ? 1 : 0); };
  booleanFilter("kev", "EXISTS(SELECT 1 FROM kev_entries kf WHERE kf.cve_id=c.id AND kf.active=1)");
  booleanFilter("exploited", "EXISTS(SELECT 1 FROM exploit_evidence ef WHERE ef.cve_id=c.id AND ef.evidence_type='known_exploitation' AND ef.status='confirmed')");
  booleanFilter("zeroDay", "EXISTS(SELECT 1 FROM exploit_evidence zf WHERE zf.cve_id=c.id AND zf.evidence_type='zero_day' AND zf.status='confirmed')");
  booleanFilter("patchAvailable", "EXISTS(SELECT 1 FROM remediations rf WHERE (rf.cve_id=c.id OR (rf.cve_id IS NULL AND EXISTS(SELECT 1 FROM advisory_cves rac WHERE rac.advisory_id=rf.advisory_id AND rac.cve_id=c.id))) AND rf.patch_available=1 AND rf.advisory_revision_id=(SELECT rr.id FROM advisory_revisions rr WHERE rr.advisory_id=rf.advisory_id ORDER BY rr.observed_at DESC LIMIT 1))");
  booleanFilter("mitigationAvailable", "EXISTS(SELECT 1 FROM remediations mf WHERE (mf.cve_id=c.id OR (mf.cve_id IS NULL AND EXISTS(SELECT 1 FROM advisory_cves mac WHERE mac.advisory_id=mf.advisory_id AND mac.cve_id=c.id))) AND mf.kind='mitigation' AND mf.advisory_revision_id=(SELECT mr.id FROM advisory_revisions mr WHERE mr.advisory_id=mf.advisory_id ORDER BY mr.observed_at DESC LIMIT 1))");
  booleanFilter("workaroundAvailable", "EXISTS(SELECT 1 FROM remediations wf WHERE (wf.cve_id=c.id OR (wf.cve_id IS NULL AND EXISTS(SELECT 1 FROM advisory_cves wac WHERE wac.advisory_id=wf.advisory_id AND wac.cve_id=c.id))) AND wf.kind='workaround' AND wf.advisory_revision_id=(SELECT wr.id FROM advisory_revisions wr WHERE wr.advisory_id=wf.advisory_id ORDER BY wr.observed_at DESC LIMIT 1))");

  const outer = ["1=1"];
  const addOuter = (condition: string, ...values: unknown[]) => { outer.push(condition); bindings.push(...values); };
  if (finiteParam(params, "cvssMin") != null) addOuter("cvss >= ?", finiteParam(params, "cvssMin"));
  if (finiteParam(params, "cvssMax") != null) addOuter("cvss <= ?", finiteParam(params, "cvssMax"));
  if (finiteParam(params, "epssPercentileMin") != null) addOuter("epss_percentile >= ?", finiteParam(params, "epssPercentileMin"));
  if (finiteParam(params, "epssMin") != null) addOuter("epss >= ?", finiteParam(params, "epssMin"));
  const priority = params.get("priority")?.toUpperCase();
  if (priority === "P1") outer.push("(kev=1 OR known_exploited=1)");
  if (priority === "P2") { outer.push("kev=0 AND known_exploited=0 AND ((severity_rank=4 AND epss_percentile>=?) OR (severity_rank=3 AND epss_percentile>=?))"); bindings.push(PRIORITY_THRESHOLDS.criticalHighEpssPercentile, PRIORITY_THRESHOLDS.highVeryHighEpssPercentile); }
  if (priority === "P3") { outer.push("kev=0 AND known_exploited=0 AND NOT ((severity_rank=4 AND COALESCE(epss_percentile,0)>=?) OR (severity_rank=3 AND COALESCE(epss_percentile,0)>=?))"); bindings.push(PRIORITY_THRESHOLDS.criticalHighEpssPercentile, PRIORITY_THRESHOLDS.highVeryHighEpssPercentile); }

  const cte = `WITH current_epss AS (
    SELECT eo.cve_id, eo.score, eo.percentile FROM epss_observations eo JOIN epss_datasets ed ON ed.score_date=eo.score_date AND ed.is_current=1
  ), base AS (
    SELECT c.id cve_id, COALESCE(c.description, MAX(ac.vendor_description), MAX(a.title), c.id) title, GROUP_CONCAT(DISTINCT v.name) vendor, GROUP_CONCAT(DISTINCT p.name) product,
      MAX(CASE ac.normalized_severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END) severity_rank,
      MAX(ac.vendor_cvss_score) cvss, ce.score epss, ce.percentile epss_percentile,
      MAX(CASE WHEN k.active=1 THEN 1 ELSE 0 END) kev,
      MAX(CASE WHEN ee.evidence_type='known_exploitation' AND ee.status='confirmed' THEN 1 ELSE 0 END) known_exploited,
      MAX(CASE WHEN ee.evidence_type='zero_day' AND ee.status='confirmed' THEN 1 ELSE 0 END) zero_day,
      MAX(CASE WHEN r.patch_available=1 THEN 1 WHEN r.patch_available=0 THEN 0 ELSE NULL END) patch_available,
      MAX(CASE WHEN r.kind='mitigation' THEN 1 ELSE 0 END) mitigation_available,
      MAX(CASE WHEN r.kind='workaround' THEN 1 ELSE 0 END) workaround_available,
      MIN(a.published_at) published_at, MAX(a.source_updated_at) modified_at
    FROM cves c JOIN advisory_cves ac ON ac.cve_id=c.id JOIN advisories a ON a.id=ac.advisory_id JOIN vendors v ON v.id=a.vendor_id
      JOIN advisory_revisions ar ON ar.id=(SELECT ar2.id FROM advisory_revisions ar2 WHERE ar2.advisory_id=a.id ORDER BY ar2.observed_at DESC LIMIT 1)
      LEFT JOIN affected_products ap ON ap.advisory_revision_id=ar.id AND (ap.cve_id=c.id OR ap.cve_id IS NULL) LEFT JOIN products p ON p.id=ap.product_id
      LEFT JOIN remediations r ON r.advisory_revision_id=ar.id AND (r.cve_id=c.id OR r.cve_id IS NULL)
      LEFT JOIN kev_entries k ON k.cve_id=c.id LEFT JOIN exploit_evidence ee ON ee.cve_id=c.id LEFT JOIN current_epss ce ON ce.cve_id=c.id
    WHERE COALESCE(a.published_at,a.source_updated_at) >= date('now','-24 months') AND ${where.join(" AND ")}
    GROUP BY c.id, ce.score, ce.percentile
  ), filtered AS (SELECT * FROM base WHERE ${outer.join(" AND ")})`;
  return { cte, bindings };
}

async function queryChanges(db: D1Database, cte: string, bindings: unknown[]): Promise<DashboardResponse["changes"]> {
  const prior = await db.prepare("SELECT MAX((SELECT r.started_at FROM source_runs r WHERE r.source_id=s.id AND r.completed_at IS NOT NULL ORDER BY r.completed_at DESC LIMIT 1 OFFSET 1)) started_at FROM sources s WHERE s.enabled=1").first<{ started_at: string | null }>();
  const since = prior?.started_at ?? null;
  if (!since) return { since: null, newCves: 0, newCritical: 0, newlyKnownExploited: 0, newKev: 0, revisedAdvisories: 0, newRemediation: 0 };
  const row = await db.prepare(`${cte} SELECT COUNT(DISTINCT CASE WHEN ic.change_type='NEW_CVE' THEN ic.cve_id END) new_cves, COUNT(DISTINCT CASE WHEN ic.change_type='NEW_CVE' AND f.severity_rank=4 THEN ic.cve_id END) new_critical, COUNT(DISTINCT CASE WHEN ic.change_type='EXPLOITATION_STATUS_CHANGED' AND f.known_exploited=1 THEN ic.cve_id END) newly_exploited, COUNT(DISTINCT CASE WHEN ic.change_type='KEV_ADDED' THEN ic.cve_id END) new_kev, COUNT(DISTINCT CASE WHEN ic.change_type='ADVISORY_REVISED' THEN ic.advisory_id END) revised, COUNT(DISTINCT CASE WHEN ic.change_type IN ('REMEDIATION_CHANGED','FIXED_VERSION_CHANGED','MITIGATION_ADDED','WORKAROUND_ADDED') THEN ic.advisory_id END) new_remediation FROM intelligence_changes ic JOIN filtered f ON f.cve_id=ic.cve_id WHERE ic.observed_at>=?`).bind(...bindings, since).first<Record<string, number>>();
  return { since, newCves: Number(row?.new_cves ?? 0), newCritical: Number(row?.new_critical ?? 0), newlyKnownExploited: Number(row?.newly_exploited ?? 0), newKev: Number(row?.new_kev ?? 0), revisedAdvisories: Number(row?.revised ?? 0), newRemediation: Number(row?.new_remediation ?? 0) };
}

async function querySourceHealth(db: D1Database): Promise<SourceHealth[]> {
  const result = await db.prepare(`SELECT s.id source_id, s.name, r.started_at last_attempt, CASE WHEN r.status IN ('success','partial','unchanged') THEN r.completed_at ELSE (SELECT completed_at FROM source_runs ok WHERE ok.source_id=s.id AND ok.status IN ('success','partial','unchanged') ORDER BY ok.completed_at DESC LIMIT 1) END last_success, CAST((julianday(r.completed_at)-julianday(r.started_at))*86400000 AS INTEGER) duration_ms, r.status result, COALESCE(r.records_discovered,0) discovered, COALESCE(r.records_inserted,0) inserted, COALESCE(r.records_changed,0) changed, COALESCE(r.records_unchanged,0) unchanged, COALESCE(r.records_failed,0) failed, r.error_summary FROM sources s LEFT JOIN source_runs r ON r.id=(SELECT r2.id FROM source_runs r2 WHERE r2.source_id=s.id ORDER BY r2.started_at DESC LIMIT 1) WHERE s.enabled=1 ORDER BY s.name`).all<Record<string, unknown>>();
  return (result.results ?? []).map((row) => ({ sourceId: String(row.source_id), name: String(row.name), lastAttempt: nullableString(row.last_attempt), lastSuccess: nullableString(row.last_success), durationMs: row.duration_ms == null ? null : Number(row.duration_ms), result: nullableString(row.result), discovered: Number(row.discovered ?? 0), inserted: Number(row.inserted ?? 0), changed: Number(row.changed ?? 0), unchanged: Number(row.unchanged ?? 0), failed: Number(row.failed ?? 0), errorSummary: nullableString(row.error_summary) }));
}

async function queryLatestReleaseEvent(db: D1Database): Promise<DashboardResponse["latestReleaseEvent"]> {
  const events = await db.prepare("SELECT id, label, event_date FROM release_events WHERE event_type='patch_tuesday' ORDER BY event_date DESC LIMIT 2").all<{ id: string; label: string; event_date: string }>();
  const [event, previousEvent] = events.results ?? [];
  if (!event) return null;
  const stats = await queryReleaseEventStats(db, event.id);
  const previous = previousEvent ? await queryReleaseEventStats(db, previousEvent.id) : null;
  const products = await db.prepare(`SELECT COALESCE(p.family,p.name) label, COUNT(DISTINCT ap.cve_id) value FROM release_event_advisories rea JOIN advisories a ON a.id=rea.advisory_id JOIN advisory_revisions ar ON ar.id=(SELECT ar2.id FROM advisory_revisions ar2 WHERE ar2.advisory_id=a.id ORDER BY ar2.observed_at DESC LIMIT 1) JOIN affected_products ap ON ap.advisory_revision_id=ar.id JOIN products p ON p.id=ap.product_id WHERE rea.release_event_id=? GROUP BY COALESCE(p.family,p.name) ORDER BY value DESC LIMIT 8`).bind(event.id).all<{ label: string; value: number }>();
  const total = Number(stats.total ?? 0); const critical = Number(stats.critical ?? 0); const high = Number(stats.high ?? 0); const knownExploited = Number(stats.exploited ?? 0); const zeroDay = Number(stats.zero_day ?? 0); const kev = Number(stats.kev ?? 0);
  return { id: event.id, label: event.label, eventDate: event.event_date, total, critical, high, knownExploited, zeroDay, kev, productFamilies: (products.results ?? []).map((row) => ({ label: row.label, value: Number(row.value) })), comparison: previousEvent && previous ? { label: previousEvent.label, eventDate: previousEvent.event_date, totalDelta: total - Number(previous.total ?? 0), criticalDelta: critical - Number(previous.critical ?? 0), highDelta: high - Number(previous.high ?? 0), knownExploitedDelta: knownExploited - Number(previous.exploited ?? 0), zeroDayDelta: zeroDay - Number(previous.zero_day ?? 0), kevDelta: kev - Number(previous.kev ?? 0) } : null };
}

async function queryReleaseEventStats(db: D1Database, eventId: string): Promise<Record<string, number>> {
  return await db.prepare(`SELECT COUNT(DISTINCT ac.cve_id) total, COUNT(DISTINCT CASE WHEN ac.normalized_severity='critical' THEN ac.cve_id END) critical, COUNT(DISTINCT CASE WHEN ac.normalized_severity='high' THEN ac.cve_id END) high, COUNT(DISTINCT CASE WHEN EXISTS(SELECT 1 FROM exploit_evidence ee WHERE ee.cve_id=ac.cve_id AND ee.evidence_type='known_exploitation' AND ee.status='confirmed') THEN ac.cve_id END) exploited, COUNT(DISTINCT CASE WHEN EXISTS(SELECT 1 FROM exploit_evidence ee WHERE ee.cve_id=ac.cve_id AND ee.evidence_type='zero_day' AND ee.status='confirmed') THEN ac.cve_id END) zero_day, COUNT(DISTINCT CASE WHEN EXISTS(SELECT 1 FROM kev_entries k WHERE k.cve_id=ac.cve_id AND k.active=1) THEN ac.cve_id END) kev FROM release_event_advisories rea JOIN advisory_cves ac ON ac.advisory_id=rea.advisory_id WHERE rea.release_event_id=?`).bind(eventId).first<Record<string, number>>() ?? {};
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
