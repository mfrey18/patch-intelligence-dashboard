import type { Database } from "../../db/database";
import { queryDashboard } from "../api/dashboard-query";

export const OPERATIONAL_THRESHOLDS = Object.freeze({
  projectionStaleHours: 36,
  sourceStaleHours: 36,
  coreLatencyMs: 1_000,
  repeatedBoundHits24h: 3,
  repeatedFailures24h: 3,
  leaseStuckMinutes: 8,
});

// A scheduled Cisco checkpoint is expected to make progress over several
// invocations. These thresholds distinguish that normal pending state from a
// worker that is repeatedly retrying the same continuation or a backlog that
// has crossed a daily freshness boundary.
export const CISCO_PENDING_STALL_HOURS = 36;
export const INCOMPLETE_BACKLOG_STALE_HOURS = 36;

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
  sources: Array<{ sourceId: string; lastAttempt: string | null; lastSuccess: string | null; lastSuccessCoverageThrough: string | null; lastFailure: string | null; result: string | null; failed: number; failures24h: number; boundHits24h: number; pending: boolean; incomplete: boolean; checkpointStatus: string | null; pendingProgressAt: string | null; pendingUpdatedAt: string | null; pendingCreatedAt: string | null; pendingBacklogAgeHours: number | null; pendingStalledAttempts: number }>;
  leases: { ingestion: Array<{ sourceId: string; acquiredAt: string; expiresAt: string; state: "active" | "expired" }>; projection: { acquiredAt: string; expiresAt: string; state: "active" | "expired" } | null };
  dashboardCoreLatencyMs: number;
  alerts: OperationalAlert[];
}

export async function captureOperationalMonitor(db: Database, now = new Date(), measureCoreLatency: (db: Database) => Promise<number> = measureDashboardCoreLatency): Promise<OperationalMonitorResult> {
  const [projection, actualCount, sources, ingestionLeases, projectionLease, latestSuccess] = await Promise.all([
    db.prepare("SELECT generated_at,cve_count,parity_status,parity_checked_at,last_attempt_status,last_attempt_at,last_attempt_error FROM dashboard_projection_state WHERE id='current'").first<Record<string, unknown>>(),
    db.prepare("SELECT COUNT(*) count FROM cve_dashboard_facts").first<{ count: number }>(),
    db.prepare(`SELECT s.id source_id,r.started_at last_attempt,r.completed_at,r.status result,COALESCE(r.records_failed,0) failed,
      CASE WHEN s.id NOT IN ('microsoft-msrc-csaf','cisco-psirt-csaf','palo-alto-psirt-csaf','mozilla-mfsa-yaml','cisa-kev','first-epss') THEN
        (SELECT MAX(e.completed_at) FROM source_completion_evidence e WHERE e.source_id=s.id AND e.kind IN ('delta','initial_enrichment'))
      WHEN s.kind='vendor_advisory' THEN
        (SELECT MAX(cp_done.completed_at) FROM ingestion_checkpoints cp_done WHERE cp_done.source_id=s.id AND cp_done.mode='delta' AND (cp_done.scheduled OR cp_done.id LIKE 'daily:' || s.id || ':%' OR (s.id='cisco-psirt-csaf' AND cp_done.id LIKE 'daily:cisco:%')) AND cp_done.status='complete')
        ELSE (SELECT completed_at FROM source_runs ok WHERE ok.source_id=s.id AND (ok.status IN ('success','unchanged') OR (ok.status='partial' AND ok.records_failed=0)) ORDER BY ok.completed_at DESC LIMIT 1)
      END last_success,
      CASE WHEN s.id NOT IN ('microsoft-msrc-csaf','cisco-psirt-csaf','palo-alto-psirt-csaf','mozilla-mfsa-yaml','cisa-kev','first-epss') THEN
        (SELECT MAX(e.coverage_end) FROM source_completion_evidence e WHERE e.source_id=s.id AND e.kind IN ('delta','initial_enrichment'))
      WHEN s.kind='vendor_advisory' THEN
        (SELECT MAX(cp_done.coverage_end) FROM ingestion_checkpoints cp_done WHERE cp_done.source_id=s.id AND cp_done.mode='delta' AND (cp_done.scheduled OR cp_done.id LIKE 'daily:' || s.id || ':%' OR (s.id='cisco-psirt-csaf' AND cp_done.id LIKE 'daily:cisco:%')) AND cp_done.status='complete')
        ELSE NULL
      END last_success_coverage_through,
      (SELECT started_at FROM source_runs bad WHERE bad.source_id=s.id AND (bad.status='failed' OR bad.records_failed>0) ORDER BY bad.started_at DESC LIMIT 1) last_failure,
      (SELECT COUNT(*) FROM source_runs failures WHERE failures.source_id=s.id AND (failures.status='failed' OR failures.records_failed>0) AND failures.started_at>=(CURRENT_TIMESTAMP + INTERVAL '-24 hours')) failures_24h,
      (SELECT COUNT(*) FROM source_runs bh JOIN ingestion_checkpoints cp ON cp.id=bh.checkpoint_id WHERE bh.source_id=s.id AND bh.bound_hit=TRUE AND bh.ingestion_mode IN ('delta','patch_tuesday') AND cp.status IN ('pending','running','failed') AND bh.started_at>=(CURRENT_TIMESTAMP + INTERVAL '-24 hours')) bound_hits_24h,
      (COALESCE(active_cp.status IN ('pending','running'), FALSE) OR ec.id IS NOT NULL) pending,
      (active_cp.id IS NOT NULL OR ec.id IS NOT NULL) incomplete, active_cp.status checkpoint_status,
      COALESCE(active_cp.updated_at,ep.progress_at,ec.started_at) pending_updated_at, COALESCE(active_cp.created_at,ec.started_at) pending_created_at,
      GREATEST(ep.progress_at,(SELECT MAX(progress.completed_at) FROM source_runs progress
        WHERE (progress.checkpoint_id=active_cp.id OR progress.checkpoint_id=ec.id) AND progress.records_failed=0
          AND progress.status IN ('partial','success','unchanged')
          AND (progress.continuation_out IS DISTINCT FROM progress.continuation_in OR progress.bound_hit=FALSE))) pending_progress_at,
      (SELECT COUNT(*) FROM (
        SELECT stalled.status,stalled.records_failed,stalled.bound_hit,stalled.continuation_out,stalled.continuation_in
        FROM source_runs stalled WHERE (stalled.checkpoint_id=active_cp.id OR stalled.checkpoint_id=ec.id) AND stalled.completed_at IS NOT NULL
        ORDER BY stalled.completed_at DESC, stalled.started_at DESC, stalled.id DESC LIMIT 2
      ) stalled WHERE stalled.status='partial' AND stalled.records_failed=0 AND stalled.bound_hit=TRUE
        AND stalled.continuation_out IS NOT DISTINCT FROM stalled.continuation_in) pending_stalled_attempts
      FROM sources s LEFT JOIN source_runs r ON r.id=(SELECT r2.id FROM source_runs r2 WHERE r2.source_id=s.id ORDER BY r2.started_at DESC LIMIT 1)
      LEFT JOIN LATERAL (
        SELECT cp.id,cp.status,cp.created_at,cp.updated_at FROM ingestion_checkpoints cp
        WHERE cp.source_id=s.id AND cp.status IN ('pending','running','failed') AND cp.retired_at IS NULL
          AND (s.id<>'cisco-psirt-csaf' OR (cp.mode='delta' AND (cp.id LIKE 'daily:cisco-psirt-csaf:%' OR cp.id LIKE 'daily:cisco:%')))
        ORDER BY cp.created_at ASC, cp.updated_at ASC, cp.id ASC LIMIT 1
      ) active_cp ON TRUE
      LEFT JOIN enrichment_cycles ec ON ec.source_id=s.id AND ec.completed_at IS NULL
      LEFT JOIN LATERAL (SELECT MAX(checked_at) progress_at FROM enrichment_cycle_members WHERE cycle_id=ec.id) ep ON TRUE
      WHERE s.enabled=TRUE AND s.readiness='production' ORDER BY s.id`).all<Record<string, unknown>>(),
    db.prepare("SELECT source_id,acquired_at,expires_at FROM ingestion_leases").all<{ source_id: string; acquired_at: string; expires_at: string }>(),
    db.prepare("SELECT acquired_at,expires_at FROM dashboard_projection_leases WHERE id='current'").first<{ acquired_at: string; expires_at: string }>(),
    db.prepare("SELECT MAX(completed_at) completed_at FROM source_runs WHERE status IN ('success','unchanged','partial') AND (records_inserted>0 OR records_changed>0)").first<{ completed_at: string | null }>(),
  ]);
  const dashboardCoreLatencyMs = await measureCoreLatency(db);
  const generatedAt = nullableString(projection?.generated_at); const latestIngestionSuccess = nullableString(latestSuccess?.completed_at);
  const stateCount = Number(projection?.cve_count ?? 0); const factCount = Number(actualCount?.count ?? 0);
  const ageHours = generatedAt ? Math.max(0, (now.getTime() - new Date(generatedAt).getTime()) / 3_600_000) : null;
  const sourceRows = (sources.results ?? []).map((row) => {
    const pending = Boolean(row.pending);
    const incomplete = Boolean(row.incomplete ?? row.pending);
    const pendingProgressAt = nullableString(row.pending_progress_at);
    const pendingUpdatedAt = nullableString(row.pending_updated_at);
    const pendingCreatedAt = nullableString(row.pending_created_at);
    const pendingBacklogAgeHours = pendingCreatedAt ? Math.max(0, (now.getTime() - new Date(pendingCreatedAt).getTime()) / 3_600_000) : null;
    const failed = Number(row.failed ?? 0);
    const result = pending && failed === 0 && row.result !== "failed" ? "pending" : nullableString(row.result);
    return { sourceId: String(row.source_id), lastAttempt: nullableString(row.last_attempt), lastSuccess: nullableString(row.last_success), lastSuccessCoverageThrough: nullableString(row.last_success_coverage_through), lastFailure: nullableString(row.last_failure), result, failed, failures24h: Number(row.failures_24h ?? 0), boundHits24h: Number(row.bound_hits_24h ?? 0), pending, incomplete, checkpointStatus: nullableString(row.checkpoint_status), pendingProgressAt, pendingUpdatedAt, pendingCreatedAt, pendingBacklogAgeHours, pendingStalledAttempts: Number(row.pending_stalled_attempts ?? 0) };
  });
  const alerts: OperationalAlert[] = [];
  if (!generatedAt || factCount === 0) alerts.push({ code: "projection_missing", severity: "critical", message: "No published dashboard projection is available." });
  if (ageHours != null && ageHours > OPERATIONAL_THRESHOLDS.projectionStaleHours) alerts.push({ code: "projection_stale", severity: "critical", message: `Dashboard projection is ${ageHours.toFixed(1)} hours old.` });
  if (stateCount !== factCount) alerts.push({ code: "projection_count_mismatch", severity: "critical", message: `Projection state count ${stateCount} does not match stored facts ${factCount}.` });
  if (projection?.parity_status !== "passed") alerts.push({ code: "projection_parity_unverified", severity: "critical", message: "The current projection does not have a passing canonical parity result." });
  if (projection?.last_attempt_status === "failed") alerts.push({ code: "projection_refresh_failed", severity: "critical", message: nullableString(projection.last_attempt_error) ?? "The latest projection refresh failed." });
  if (generatedAt && latestIngestionSuccess && new Date(latestIngestionSuccess) > new Date(generatedAt)) alerts.push({ code: "projection_behind_ingestion", severity: "critical", message: "A source committed data after the current projection was generated." });
  for (const source of sourceRows) {
    const lastProgress = source.pendingProgressAt ?? source.pendingCreatedAt;
    const pendingProgressAgeHours = lastProgress ? Math.max(0, (now.getTime() - new Date(lastProgress).getTime()) / 3_600_000) : null;
    const pendingStalled = source.pending && ((source.pendingStalledAttempts >= 2) || (pendingProgressAgeHours != null && pendingProgressAgeHours > CISCO_PENDING_STALL_HOURS));
    const pendingBacklogStale = source.incomplete && source.pendingBacklogAgeHours != null && source.pendingBacklogAgeHours > INCOMPLETE_BACKLOG_STALE_HOURS;
    // A Cisco partial batch is expected while its scheduled checkpoint is
    // pending. Its freshness is represented by the last COMPLETE checkpoint;
    // pending work gets its own stall/backlog alerts below.
    const lastSuccessAgeHours = source.lastSuccess ? Math.max(0, (now.getTime() - new Date(source.lastSuccess).getTime()) / 3_600_000) : null;
    const lastSuccessCoverageAgeHours = source.lastSuccessCoverageThrough ? Math.max(0, (now.getTime() - new Date(source.lastSuccessCoverageThrough).getTime()) / 3_600_000) : null;
    if (!source.lastSuccess || (lastSuccessAgeHours != null && lastSuccessAgeHours > OPERATIONAL_THRESHOLDS.sourceStaleHours) || (lastSuccessCoverageAgeHours != null && lastSuccessCoverageAgeHours > OPERATIONAL_THRESHOLDS.sourceStaleHours)) alerts.push({ code: "source_stale", severity: "critical", sourceId: source.sourceId, message: `${source.sourceId} has no successful ingestion with current coverage within ${OPERATIONAL_THRESHOLDS.sourceStaleHours} hours.` });
    if (source.result === "failed" || source.failed > 0) alerts.push({ code: "source_latest_attempt_failed", severity: "critical", sourceId: source.sourceId, message: `${source.sourceId}'s latest ingestion attempt failed.` });
    if (source.checkpointStatus === "failed" && source.result !== "failed" && source.failed === 0) alerts.push({ code: "source_scheduled_checkpoint_failed", severity: "critical", sourceId: source.sourceId, message: `${source.sourceId} has an unresolved failed scheduled checkpoint.` });
    if (source.failures24h >= OPERATIONAL_THRESHOLDS.repeatedFailures24h) alerts.push({ code: "source_repeated_failures", severity: "critical", sourceId: source.sourceId, message: `${source.sourceId} failed ${source.failures24h} times in 24 hours.` });
    if (pendingStalled) {
      const stallMessage = pendingProgressAgeHours == null ? `${source.sourceId} repeated the same checkpoint continuation in ${source.pendingStalledAttempts} recent attempts.` : `${source.sourceId} has made no checkpoint progress for ${pendingProgressAgeHours.toFixed(1)} hours.`;
      alerts.push({ code: "source_pending_stalled", severity: "warning", sourceId: source.sourceId, message: stallMessage });
    }
    if (pendingBacklogStale) alerts.push({ code: "source_pending_backlog_stale", severity: "critical", sourceId: source.sourceId, message: `${source.sourceId} has a scheduled checkpoint that has remained incomplete for ${source.pendingBacklogAgeHours!.toFixed(1)} hours.` });
    // Active Cisco progress can legitimately hit the one-advisory bound many
    // times. Surface bound pressure for other sources and only for Cisco when
    // the checkpoint has actually stalled.
    if (source.boundHits24h >= OPERATIONAL_THRESHOLDS.repeatedBoundHits24h && !(source.pending && !pendingStalled)) alerts.push({ code: "source_repeated_bound_hits", severity: "warning", sourceId: source.sourceId, message: `${source.sourceId} reached its configured batch bound ${source.boundHits24h} times in 24 hours.` });
  }
  const observedIngestionLeases = (ingestionLeases.results ?? []).map((row) => ({ sourceId: row.source_id, acquiredAt: row.acquired_at, expiresAt: row.expires_at, state: new Date(row.expires_at) > now ? "active" as const : "expired" as const }));
  for (const lease of observedIngestionLeases) {
    const ageMinutes = (now.getTime() - new Date(lease.acquiredAt).getTime()) / 60_000;
    if (lease.state === "expired") alerts.push({ code: "ingestion_lease_expired", severity: "critical", sourceId: lease.sourceId, message: `${lease.sourceId} has an expired ingestion lease that was not cleaned up.` });
    else if (ageMinutes >= OPERATIONAL_THRESHOLDS.leaseStuckMinutes) alerts.push({ code: "ingestion_lease_stuck", severity: "warning", sourceId: lease.sourceId, message: `${lease.sourceId} ingestion lease has remained active for ${ageMinutes.toFixed(1)} minutes.` });
  }
  const observedProjectionLease = projectionLease ? { acquiredAt: projectionLease.acquired_at, expiresAt: projectionLease.expires_at, state: new Date(projectionLease.expires_at) > now ? "active" as const : "expired" as const } : null;
  if (observedProjectionLease) {
    const ageMinutes = (now.getTime() - new Date(observedProjectionLease.acquiredAt).getTime()) / 60_000;
    if (observedProjectionLease.state === "expired") alerts.push({ code: "projection_lease_expired", severity: "critical", message: "The dashboard projection lease expired without cleanup." });
    else if (ageMinutes >= OPERATIONAL_THRESHOLDS.leaseStuckMinutes) alerts.push({ code: "projection_lease_stuck", severity: "warning", message: `The dashboard projection lease has remained active for ${ageMinutes.toFixed(1)} minutes.` });
  }
  if (dashboardCoreLatencyMs > OPERATIONAL_THRESHOLDS.coreLatencyMs) alerts.push({ code: "dashboard_core_slow", severity: "warning", message: `Dashboard core query took ${dashboardCoreLatencyMs} ms.` });
  const status = alerts.some((alert) => alert.severity === "critical") ? "unhealthy" : alerts.length ? "degraded" : "healthy";
  return { capturedAt: now.toISOString(), status, projection: { generatedAt, ageHours: ageHours == null ? null : Number(ageHours.toFixed(2)), stateCount, actualCount: factCount, parityStatus: nullableString(projection?.parity_status), parityCheckedAt: nullableString(projection?.parity_checked_at), lastAttemptStatus: nullableString(projection?.last_attempt_status), lastAttemptAt: nullableString(projection?.last_attempt_at), lastAttemptError: nullableString(projection?.last_attempt_error), latestIngestionSuccess }, sources: sourceRows, leases: { ingestion: observedIngestionLeases, projection: observedProjectionLease }, dashboardCoreLatencyMs, alerts };
}

function nullableString(value: unknown): string | null { return value == null ? null : String(value); }

async function measureDashboardCoreLatency(db: Database): Promise<number> {
  const started = performance.now();
  await queryDashboard(db, new URL("https://monitor.invalid/api/dashboard?limit=1&include=core"));
  return Number((performance.now() - started).toFixed(2));
}
