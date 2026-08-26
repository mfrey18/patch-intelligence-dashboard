import { INTELLIGENCE_WINDOW_MONTHS, rollingWindowStart } from "../ingestion/operational-policy";
import { queryDashboard } from "../api/dashboard-query";

const MAJOR_TABLES = [
  "advisories", "advisory_revisions", "cves", "advisory_cves", "affected_products", "remediations", "exploit_evidence", "kev_entries", "epss_datasets", "epss_observations", "intelligence_changes", "source_runs", "source_run_results", "ingestion_checkpoints", "ingestion_leases", "cve_dashboard_facts", "dashboard_projection_state",
] as const;
const STARTUP_AUDIT_ROWS_PER_DAY_ESTIMATE = 60;

export interface D1ProductionBaseline {
  capturedAt: string;
  intelligenceWindowMonths: number;
  databaseBytes: null;
  databaseSizeSource: "wrangler_d1_info_required";
  rowCounts: Record<string, number>;
  largestTables: Array<{ table: string; rows: number }>;
  indexes: Array<{ name: string; table: string; sql: string | null }>;
  epssHistory: { rows: number; datasetDays: number; rowsPerDatasetDay: number; oldestDate: string | null; newestDate: string | null };
  queryLatencyMs: Record<string, number>;
  slowestImportantQuery: { name: string; durationMs: number };
  projections: Array<{ horizon: "current" | "plus_6_months" | "plus_12_months"; estimatedRows: number; estimatedBytes: null }>;
  projectionAssumptions: string[];
  baselineMaturity: "startup" | "representative";
}

export async function captureD1ProductionBaseline(db: D1Database): Promise<D1ProductionBaseline> {
  const rowCounts: Record<string, number> = {};
  for (const table of MAJOR_TABLES) {
    const row = await db.prepare(`SELECT COUNT(*) row_count FROM ${table}`).first<{ row_count: number }>();
    rowCounts[table] = Number(row?.row_count ?? 0);
  }
  const indexes = await db.prepare("SELECT name, tbl_name table_name, sql FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_autoindex_%' ORDER BY tbl_name,name").all<{ name: string; table_name: string; sql: string | null }>();
  const epss = await db.prepare("SELECT COUNT(*) rows, COUNT(DISTINCT score_date) dataset_days, MIN(score_date) oldest_date, MAX(score_date) newest_date FROM epss_observations").first<Record<string, unknown>>();

  const queryLatencyMs: Record<string, number> = {};
  await timed(queryLatencyMs, "dashboard_api_default", () => queryDashboard(db, new URL("https://baseline.invalid/api/dashboard?limit=1")));
  await timed(queryLatencyMs, "dashboard_api_core", () => queryDashboard(db, new URL("https://baseline.invalid/api/dashboard?limit=1&include=core")));
  await timed(queryLatencyMs, "dashboard_six_month_summary", () => db.prepare("SELECT COUNT(DISTINCT ac.cve_id) total FROM advisories a JOIN advisory_cves ac ON ac.advisory_id=a.id WHERE COALESCE(a.published_at,a.source_updated_at)>=date('now','-6 months')").first());
  await timed(queryLatencyMs, "dashboard_priority_signals", () => db.prepare("SELECT COUNT(DISTINCT ac.cve_id) total FROM advisory_cves ac WHERE EXISTS(SELECT 1 FROM kev_entries k WHERE k.cve_id=ac.cve_id AND k.active=1) OR EXISTS(SELECT 1 FROM exploit_evidence ee WHERE ee.cve_id=ac.cve_id AND ee.evidence_type='known_exploitation' AND ee.status='confirmed')").first());
  await timed(queryLatencyMs, "epss_current_join", () => db.prepare("SELECT COUNT(*) total FROM epss_observations eo JOIN epss_datasets ed ON ed.score_date=eo.score_date AND ed.is_current=1 JOIN cves c ON c.id=eo.cve_id").first());
  await timed(queryLatencyMs, "source_health_latest_runs", () => db.prepare("SELECT COUNT(*) total FROM sources s LEFT JOIN source_runs r ON r.id=(SELECT r2.id FROM source_runs r2 WHERE r2.source_id=s.id ORDER BY r2.started_at DESC LIMIT 1)").first());
  await timed(queryLatencyMs, "ingestion_latest_revision", () => db.prepare("SELECT COUNT(*) total FROM advisories a JOIN advisory_revisions ar ON ar.id=(SELECT ar2.id FROM advisory_revisions ar2 WHERE ar2.advisory_id=a.id ORDER BY ar2.observed_at DESC LIMIT 1)").first());
  await timed(queryLatencyMs, "ingestion_kev_snapshot", () => db.prepare("SELECT COUNT(*) total FROM kev_entries WHERE active=1").first());
  await timed(queryLatencyMs, "checkpoint_resume", () => db.prepare("SELECT id FROM ingestion_checkpoints WHERE status IN ('pending','failed') ORDER BY updated_at DESC LIMIT 1").first());

  const sortedLatency = Object.entries(queryLatencyMs).sort((left, right) => right[1] - left[1]);
  const totalRows = Object.values(rowCounts).reduce((sum, value) => sum + value, 0);
  const epssRows = Number(epss?.rows ?? 0);
  const datasetDays = Number(epss?.dataset_days ?? 0);
  const epssPerDay = datasetDays > 0 ? epssRows / datasetDays : 0;
  const observationSpan = await db.prepare("SELECT MIN(started_at) oldest, MAX(started_at) newest FROM source_runs").first<Record<string, unknown>>();
  const observedDays = dateSpanDays(nullableString(observationSpan?.oldest), nullableString(observationSpan?.newest));
  const auditRows = (rowCounts.advisory_revisions ?? 0) + (rowCounts.intelligence_changes ?? 0) + (rowCounts.source_run_results ?? 0) + (rowCounts.source_runs ?? 0);
  const baselineMaturity = observedDays >= 7 ? "representative" : "startup";
  const auditRowsPerDay = baselineMaturity === "representative" ? auditRows / observedDays : STARTUP_AUDIT_ROWS_PER_DAY_ESTIMATE;
  const sixMonthDays = 183;
  const fullWindowEpssRows = Math.round(epssPerDay * sixMonthDays);
  const stableRows = Math.max(0, totalRows - epssRows) + fullWindowEpssRows;
  const project = (additionalDays: number) => Math.round(stableRows + auditRowsPerDay * additionalDays);
  const projectionRows = [project(0), project(sixMonthDays), project(sixMonthDays * 2)];

  return {
    capturedAt: new Date().toISOString(),
    intelligenceWindowMonths: INTELLIGENCE_WINDOW_MONTHS,
    databaseBytes: null,
    databaseSizeSource: "wrangler_d1_info_required",
    rowCounts,
    largestTables: Object.entries(rowCounts).map(([table, rows]) => ({ table, rows })).sort((left, right) => right.rows - left.rows).slice(0, 8),
    indexes: (indexes.results ?? []).map((row) => ({ name: row.name, table: row.table_name, sql: row.sql })),
    epssHistory: { rows: epssRows, datasetDays, rowsPerDatasetDay: datasetDays > 0 ? Math.round(epssPerDay) : 0, oldestDate: nullableString(epss?.oldest_date), newestDate: nullableString(epss?.newest_date) },
    queryLatencyMs,
    slowestImportantQuery: { name: sortedLatency[0]?.[0] ?? "none", durationMs: sortedLatency[0]?.[1] ?? 0 },
    projections: (["current", "plus_6_months", "plus_12_months"] as const).map((horizon, index) => ({ horizon, estimatedRows: projectionRows[index], estimatedBytes: null })),
    projectionAssumptions: ["EPSS observations are retained for the rolling six-month window.", baselineMaturity === "representative" ? "Advisory and audit history is not destructively pruned; observed audit-row growth is projected linearly." : `Fewer than seven days of production runs are available; the startup projection assumes ${STARTUP_AUDIT_ROWS_PER_DAY_ESTIMATE} audit/run rows per day and must be refreshed after a representative week.`, "Cloudflare D1 does not authorize page-size PRAGMAs through a Worker binding; deployment enriches this health snapshot with the authoritative database_size from wrangler d1 info."],
    baselineMaturity,
  };
}

export async function pruneRollingRetention(db: D1Database, now = new Date()): Promise<{ cutoff: string; epssObservations: number; epssDatasets: number; completedCheckpoints: number; abandonedRuns: number; expiredLeases: number; preservedAuditHistory: true }> {
  const cutoff = rollingWindowStart(now).toISOString().slice(0, 10);
  const checkpointCutoff = new Date(now.getTime() - 30 * 86_400_000).toISOString();
  const observations = await db.prepare("DELETE FROM epss_observations WHERE score_date < ?").bind(cutoff).run();
  const datasets = await db.prepare("DELETE FROM epss_datasets WHERE score_date < ? AND is_current=0 AND NOT EXISTS(SELECT 1 FROM epss_observations eo WHERE eo.score_date=epss_datasets.score_date)").bind(cutoff).run();
  const checkpoints = await db.prepare("DELETE FROM ingestion_checkpoints WHERE status='complete' AND completed_at < ?").bind(checkpointCutoff).run();
  const abandonedRuns = await db.prepare("UPDATE source_runs SET status='failed', completed_at=?, records_failed=MAX(records_failed,1), error_summary=COALESCE(error_summary,'Ingestion lease expired before the run completed') WHERE status='running' AND started_at < ?").bind(now.toISOString(), new Date(now.getTime() - 15 * 60_000).toISOString()).run();
  const leases = await db.prepare("DELETE FROM ingestion_leases WHERE expires_at < ?").bind(now.toISOString()).run();
  return { cutoff, epssObservations: changes(observations), epssDatasets: changes(datasets), completedCheckpoints: changes(checkpoints), abandonedRuns: changes(abandonedRuns), expiredLeases: changes(leases), preservedAuditHistory: true };
}

async function timed(target: Record<string, number>, name: string, operation: () => Promise<unknown>): Promise<void> {
  const started = performance.now();
  await operation();
  target[name] = Number((performance.now() - started).toFixed(2));
}

function changes(result: D1Result): number { return Number((result.meta as { changes?: number } | undefined)?.changes ?? 0); }
function nullableString(value: unknown): string | null { return value == null ? null : String(value); }
function dateSpanDays(oldest: string | null, newest: string | null): number { if (!oldest || !newest) return 1; return Math.max(1, (new Date(newest).getTime() - new Date(oldest).getTime()) / 86_400_000); }
