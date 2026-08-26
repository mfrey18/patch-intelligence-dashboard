import { queryDashboard } from "../api/dashboard-query";
import { PRODUCTION_SOURCE_IDS } from "../ingestion/source-catalog";

export const OPERATIONAL_THRESHOLDS = Object.freeze({
  projectionStaleHours: 36,
  sourceStaleHours: 36,
  coreLatencyMs: 1_000,
  repeatedBoundHits24h: 3,
});

export interface OperationalAlert {
  code: string;
  severity: "warning" | "critical";
  message: string;
  sourceId?: string;
}

export interface OperationalMonitorResult {
  capturedAt: string;
  status: "healthy" | "degraded" | "unhealthy";
  projection: { generatedAt: string | null; ageHours: number | null; stateCount: number; actualCount: number; parityStatus: string | null; parityCheckedAt: string | null; lastAttemptStatus: string | null; lastAttemptAt: string | null; lastAttemptError: string | null; latestIngestionSuccess: string | null };
  sources: Array<{ sourceId: string; lastAttempt: string | null; lastSuccess: string | null; lastFailure: string | null; result: string | null; failed: number; boundHits24h: number }>;
  leases: { ingestion: Array<{ sourceId: string; expiresAt: string }>; projection: { expiresAt: string } | null };
  dashboardCoreLatencyMs: number;
  alerts: OperationalAlert[];
}

export async function captureOperationalMonitor(db: D1Database, now = new Date(), measureCoreLatency: (db: D1Database) => Promise<number> = measureDashboardCoreLatency): Promise<OperationalMonitorResult> {
  const placeholders = PRODUCTION_SOURCE_IDS.map(() => "?").join(",");
  const [projection, actualCount, sources, ingestionLeases, projectionLease, latestSuccess] = await Promise.all([
    db.prepare("SELECT generated_at,cve_count,parity_status,parity_checked_at,last_attempt_status,last_attempt_at,last_attempt_error FROM dashboard_projection_state WHERE id='current'").first<Record<string, unknown>>(),
    db.prepare("SELECT COUNT(*) count FROM cve_dashboard_facts").first<{ count: number }>(),
    db.prepare(`SELECT s.id source_id,r.started_at last_attempt,r.completed_at,r.status result,COALESCE(r.records_failed,0) failed,
      (SELECT completed_at FROM source_runs ok WHERE ok.source_id=s.id AND (ok.status IN ('success','unchanged') OR (ok.status='partial' AND ok.records_failed=0)) ORDER BY ok.completed_at DESC LIMIT 1) last_success,
      (SELECT completed_at FROM source_runs bad WHERE bad.source_id=s.id AND (bad.status='failed' OR bad.records_failed>0) ORDER BY bad.completed_at DESC LIMIT 1) last_failure,
      (SELECT COUNT(*) FROM source_runs bh WHERE bh.source_id=s.id AND bh.bound_hit=1 AND bh.started_at>=datetime('now','-24 hours')) bound_hits_24h
      FROM sources s LEFT JOIN source_runs r ON r.id=(SELECT r2.id FROM source_runs r2 WHERE r2.source_id=s.id ORDER BY r2.started_at DESC LIMIT 1)
      WHERE s.id IN (${placeholders}) ORDER BY s.id`).bind(...PRODUCTION_SOURCE_IDS).all<Record<string, unknown>>(),
    db.prepare("SELECT source_id,expires_at FROM ingestion_leases WHERE expires_at>?").bind(now.toISOString()).all<{ source_id: string; expires_at: string }>(),
    db.prepare("SELECT expires_at FROM dashboard_projection_leases WHERE id='current' AND expires_at>?").bind(now.toISOString()).first<{ expires_at: string }>(),
    db.prepare("SELECT MAX(completed_at) completed_at FROM source_runs WHERE status IN ('success','unchanged','partial') AND records_failed=0").first<{ completed_at: string | null }>(),
  ]);
  const dashboardCoreLatencyMs = await measureCoreLatency(db);
  const generatedAt = nullableString(projection?.generated_at); const latestIngestionSuccess = nullableString(latestSuccess?.completed_at);
  const stateCount = Number(projection?.cve_count ?? 0); const factCount = Number(actualCount?.count ?? 0);
  const ageHours = generatedAt ? Math.max(0, (now.getTime() - new Date(generatedAt).getTime()) / 3_600_000) : null;
  const sourceRows = (sources.results ?? []).map((row) => ({ sourceId: String(row.source_id), lastAttempt: nullableString(row.last_attempt), lastSuccess: nullableString(row.last_success), lastFailure: nullableString(row.last_failure), result: nullableString(row.result), failed: Number(row.failed ?? 0), boundHits24h: Number(row.bound_hits_24h ?? 0) }));
  const alerts: OperationalAlert[] = [];
  if (!generatedAt || factCount === 0) alerts.push({ code: "projection_missing", severity: "critical", message: "No published dashboard projection is available." });
  if (ageHours != null && ageHours > OPERATIONAL_THRESHOLDS.projectionStaleHours) alerts.push({ code: "projection_stale", severity: "critical", message: `Dashboard projection is ${ageHours.toFixed(1)} hours old.` });
  if (stateCount !== factCount) alerts.push({ code: "projection_count_mismatch", severity: "critical", message: `Projection state count ${stateCount} does not match stored facts ${factCount}.` });
  if (projection?.parity_status !== "passed") alerts.push({ code: "projection_parity_unverified", severity: "critical", message: "The current projection does not have a passing canonical parity result." });
  if (projection?.last_attempt_status === "failed") alerts.push({ code: "projection_refresh_failed", severity: "critical", message: nullableString(projection.last_attempt_error) ?? "The latest projection refresh failed." });
  if (generatedAt && latestIngestionSuccess && new Date(latestIngestionSuccess) > new Date(generatedAt)) alerts.push({ code: "projection_behind_ingestion", severity: "critical", message: "A source committed data after the current projection was generated." });
  for (const source of sourceRows) {
    if (!source.lastSuccess || now.getTime() - new Date(source.lastSuccess).getTime() > OPERATIONAL_THRESHOLDS.sourceStaleHours * 3_600_000) alerts.push({ code: "source_stale", severity: "critical", sourceId: source.sourceId, message: `${source.sourceId} has no successful ingestion within ${OPERATIONAL_THRESHOLDS.sourceStaleHours} hours.` });
    if (source.lastFailure && (!source.lastSuccess || new Date(source.lastFailure) > new Date(source.lastSuccess))) alerts.push({ code: "source_latest_attempt_failed", severity: "critical", sourceId: source.sourceId, message: `${source.sourceId} has a failure newer than its last success.` });
    if (source.boundHits24h >= OPERATIONAL_THRESHOLDS.repeatedBoundHits24h) alerts.push({ code: "source_repeated_bound_hits", severity: "warning", sourceId: source.sourceId, message: `${source.sourceId} reached its configured batch bound ${source.boundHits24h} times in 24 hours.` });
  }
  const activeIngestionLeases = (ingestionLeases.results ?? []).map((row) => ({ sourceId: row.source_id, expiresAt: row.expires_at }));
  for (const lease of activeIngestionLeases) alerts.push({ code: "ingestion_lease_active", severity: "warning", sourceId: lease.sourceId, message: `${lease.sourceId} still has an active ingestion lease.` });
  if (projectionLease) alerts.push({ code: "projection_lease_active", severity: "warning", message: "The dashboard projection lease is still active." });
  if (dashboardCoreLatencyMs > OPERATIONAL_THRESHOLDS.coreLatencyMs) alerts.push({ code: "dashboard_core_slow", severity: "warning", message: `Dashboard core query took ${dashboardCoreLatencyMs} ms.` });
  const status = alerts.some((alert) => alert.severity === "critical") ? "unhealthy" : alerts.length ? "degraded" : "healthy";
  return { capturedAt: now.toISOString(), status, projection: { generatedAt, ageHours: ageHours == null ? null : Number(ageHours.toFixed(2)), stateCount, actualCount: factCount, parityStatus: nullableString(projection?.parity_status), parityCheckedAt: nullableString(projection?.parity_checked_at), lastAttemptStatus: nullableString(projection?.last_attempt_status), lastAttemptAt: nullableString(projection?.last_attempt_at), lastAttemptError: nullableString(projection?.last_attempt_error), latestIngestionSuccess }, sources: sourceRows, leases: { ingestion: activeIngestionLeases, projection: projectionLease ? { expiresAt: projectionLease.expires_at } : null }, dashboardCoreLatencyMs, alerts };
}

function nullableString(value: unknown): string | null { return value == null ? null : String(value); }

async function measureDashboardCoreLatency(db: D1Database): Promise<number> {
  const started = performance.now();
  await queryDashboard(db, new URL("https://monitor.invalid/api/dashboard?limit=1&include=core"));
  return Number((performance.now() - started).toFixed(2));
}
