import type { Database } from "../../db/database";
import type { IngestionMode, IngestResult } from "./contracts";
import { defaultDeltaStart, DELTA_LOOKBACK_DAYS, INGESTION_MODES, rollingWindowStart, windowDaysForSource } from "./operational-policy";

import { recordSourceCompletion } from "./source-completion";
import { PRODUCTION_SOURCE_IDS, SOURCE_CATALOG } from "./source-catalog";

const CISCO_SOURCE_ID = "cisco-psirt-csaf";
const CISCO_SCHEDULED_ID = /^(?:daily:cisco:|daily:cisco-psirt-csaf:)/;

export interface IngestionRequest {
  mode?: IngestionMode;
  since?: string;
  until?: string;
  checkpointId?: string;
  scheduled?: boolean;
  deadline?: string;
}

export interface IngestionCheckpoint {
  id: string;
  sourceId: string;
  mode: IngestionMode;
  coverageStart: string;
  coverageEnd: string;
  windowStart: string;
  windowEnd: string;
  continuation: string | null;
  scheduled?: boolean;
  historicalCoverageVerified?: boolean;
  status: "pending" | "running" | "failed" | "complete";
}

export function normalizeIngestionRequest(sourceId: string, request: IngestionRequest, now = new Date()): Omit<IngestionCheckpoint, "status" | "continuation"> {
  const mode = request.mode ?? "delta";
  validateScheduledScope(sourceId, request, mode);
  if (!INGESTION_MODES.includes(mode)) throw new Error("Unsupported ingestion mode");
  if (mode === "replay" && (!request.since || !request.until)) throw new Error("Replay mode requires explicit since and until timestamps");

  const reconcile = ["oracle-cpu-csaf", "atlassian-vulnerability-api"].includes(sourceId);
  const defaultStart = mode === "backfill" || (mode === "delta" && reconcile) ? rollingWindowStart(now) : mode === "patch_tuesday" ? new Date(now.getTime() - 7 * 86_400_000) : defaultDeltaStart(now);
  const coverageStart = parseTimestamp(request.since, defaultStart, "since");
  const coverageEnd = parseTimestamp(request.until, now, "until");
  if (coverageStart > coverageEnd) throw new Error("since must not be later than until");
  const sixMonthStart = rollingWindowStart(now);
  if (coverageStart < sixMonthStart) throw new Error("Requested coverage begins outside the rolling six-month intelligence window");

  const checkpointId = request.checkpointId ?? checkpointIdentity(sourceId, mode, coverageStart, coverageEnd);
  if (!/^[A-Za-z0-9:._-]{1,220}$/.test(checkpointId)) throw new Error("Invalid checkpoint identifier");
  // The implicit delta range is already exactly one bounded lookback. Treat it
  // as a single inclusive window so a successful source does not leave a
  // one-millisecond trailing checkpoint that scheduled ingestion must replay.
  const windowEnd = mode === "delta" && !request.since && !request.until
    ? coverageEnd
    : boundedWindowEnd(coverageStart, coverageEnd, windowDaysForSource(sourceId, mode));
  return { id: checkpointId, sourceId, mode, coverageStart: coverageStart.toISOString(), coverageEnd: coverageEnd.toISOString(), windowStart: coverageStart.toISOString(), windowEnd: windowEnd.toISOString() };
}

export async function loadOrCreateCheckpoint(db: Database, sourceId: string, request: IngestionRequest, now = new Date(), evidence: {historicalCoverage?: boolean} = {}): Promise<IngestionCheckpoint> {
  validateScheduledScope(sourceId, request, request.mode ?? "delta");
  const scheduledSource = isScheduledSourceRequest(sourceId, request);
  if (scheduledSource) {
    const oldest = await findOldestIncompleteScheduledCheckpoint(db, sourceId);
    if (oldest && Date.parse(String(oldest.coverage_end)) >= rollingWindowStart(now).getTime()) return checkpointFromRow(oldest);
    if (oldest) {
      await db.prepare("UPDATE ingestion_checkpoints SET retired_at=?,retired_reason='Coverage expired outside six-month window',updated_at=? WHERE source_id=? AND (scheduled=TRUE OR id LIKE 'daily:' || source_id || ':%' OR id LIKE 'expansion:' || source_id || ':delta:%' OR (source_id='cisco-psirt-csaf' AND id LIKE 'daily:cisco:%')) AND status<>'complete' AND coverage_end<? AND retired_at IS NULL").bind(now.toISOString(),now.toISOString(),sourceId,rollingWindowStart(now).toISOString()).run();
      const remaining = await findOldestIncompleteScheduledCheckpoint(db, sourceId);
      if (remaining) return checkpointFromRow(remaining);
    }
  }
  if (request.checkpointId) {
    const existing = await db.prepare("SELECT id, source_id, mode, coverage_start, coverage_end, window_start, window_end, continuation_token, status, historical_coverage_verified, scheduled, retired_at FROM ingestion_checkpoints WHERE id=?").bind(request.checkpointId).first<Record<string, unknown>>();
    if (existing) {
      if (String(existing.source_id) !== sourceId || (request.mode && String(existing.mode) !== request.mode)) throw new Error("Checkpoint identity conflicts with the requested source or mode");
      if (!scheduledSource && ((request.since && new Date(request.since).toISOString() !== String(existing.coverage_start)) || (request.until && new Date(request.until).toISOString() !== String(existing.coverage_end)))) throw new Error("Checkpoint identity conflicts with the requested coverage range");
      if (!(scheduledSource && (String(existing.status) === "complete" || existing.retired_at))) return checkpointFromRow(existing);
    }
  }
  let planned = normalizeIngestionRequest(sourceId, request, now);
  if (scheduledSource) {
    const boundary = await findLastCompletedScheduledCoverageEnd(db, sourceId);
    const reconcile = ["oracle-cpu-csaf", "atlassian-vulnerability-api"].includes(sourceId);
    const expansion = !(PRODUCTION_SOURCE_IDS as readonly string[]).includes(sourceId);
    const lastReconcile = expansion ? await db.prepare("SELECT completed_at FROM ingestion_checkpoints WHERE source_id=? AND scheduled=TRUE AND status='complete' AND coverage_start<=coverage_end-INTERVAL '5 months' ORDER BY completed_at DESC LIMIT 1").bind(sourceId).first<{completed_at:string}>() : null;
    const reconcileDue = reconcile || (expansion && (!lastReconcile || Date.parse(lastReconcile.completed_at) < now.getTime()-7*86_400_000));
    const start = reconcileDue ? rollingWindowStart(now) : boundary
      ? new Date(Math.max(rollingWindowStart(now).getTime(), new Date(boundary).getTime() - DELTA_LOOKBACK_DAYS * 86_400_000))
      : new Date(planned.coverageStart);
    const end = new Date(now);
    if (start <= end) {
      const baseId = request.checkpointId ?? `daily:${sourceId}:${now.toISOString().slice(0,10)}`;
      const generatedId = `${baseId}:${compactTimestamp(start)}-${compactTimestamp(end)}`;
      planned = normalizeIngestionRequest(sourceId, { ...request, since: start.toISOString(), until: end.toISOString(), checkpointId: generatedId }, now);
      if (reconcileDue || end.getTime() - start.getTime() <= DELTA_LOOKBACK_DAYS * 86_400_000) planned = { ...planned, windowEnd: end.toISOString() };
    }
  }
  const timestamp = now.toISOString();
  await db.prepare("INSERT INTO ingestion_checkpoints (id, source_id, mode, coverage_start, coverage_end, window_start, window_end, continuation_token, status, created_at, updated_at, scheduled, historical_coverage_verified) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, 'pending', ?, ?, ?, ?) ON CONFLICT DO NOTHING").bind(planned.id, sourceId, planned.mode, planned.coverageStart, planned.coverageEnd, planned.windowStart, planned.windowEnd, timestamp, timestamp, scheduledSource, evidence.historicalCoverage===true).run();
  let row = await db.prepare("SELECT id, source_id, mode, coverage_start, coverage_end, window_start, window_end, continuation_token, status, historical_coverage_verified, scheduled, retired_at FROM ingestion_checkpoints WHERE id=?").bind(planned.id).first<Record<string, unknown>>();
  let matchedCanonicalRange = false;
  if (!row) {
    row = await db.prepare("SELECT id, source_id, mode, coverage_start, coverage_end, window_start, window_end, continuation_token, status, historical_coverage_verified, scheduled FROM ingestion_checkpoints WHERE source_id=? AND mode=? AND coverage_start=? AND coverage_end=? LIMIT 1").bind(sourceId, planned.mode, planned.coverageStart, planned.coverageEnd).first<Record<string, unknown>>();
    matchedCanonicalRange = Boolean(row);
  }
  if (!row) throw new Error("Ingestion checkpoint could not be created");
  if (String(row.source_id) !== sourceId || String(row.mode) !== planned.mode || String(row.coverage_start) !== planned.coverageStart || String(row.coverage_end) !== planned.coverageEnd) throw new Error("Checkpoint identity conflicts with a different ingestion range");
  // A newly named replay of the same canonical range is an intentional
  // consistency check, not a duplicate checkpoint. Reopen only completed
  // replays; active or failed ranges remain resumable as-is.
  if (matchedCanonicalRange && planned.mode === "replay" && String(row.status) === "complete") {
    const checkpointId = String(row.id);
    await db.prepare("UPDATE ingestion_checkpoints SET window_start=?, window_end=?, continuation_token=NULL, status='pending', last_error=NULL, completed_at=NULL, updated_at=? WHERE id=?").bind(planned.windowStart, planned.windowEnd, timestamp, checkpointId).run();
    row = { ...row, window_start: planned.windowStart, window_end: planned.windowEnd, continuation_token: null, status: "pending" };
  }
  return checkpointFromRow(row);
}

export async function markCheckpointRunning(db: Database, checkpointId: string): Promise<void> {
  await db.prepare("UPDATE ingestion_checkpoints SET status='running', last_error=NULL, updated_at=? WHERE id=? AND status<>'complete'").bind(new Date().toISOString(), checkpointId).run();
}

export async function markCheckpointFailed(db: Database, checkpointId: string, error: string): Promise<void> {
  await db.prepare("UPDATE ingestion_checkpoints SET status='failed', last_error=?, updated_at=? WHERE id=? AND status<>'complete'").bind(error.slice(0, 2000), new Date().toISOString(), checkpointId).run();
}

export async function advanceCheckpoint(db: Database, checkpoint: IngestionCheckpoint, result: IngestResult, evidence: {historicalCoverage?: boolean} = {}): Promise<IngestionCheckpoint> {
  const now = new Date().toISOString();
  const historicalCoverageVerified=checkpoint.historicalCoverageVerified===true && evidence.historicalCoverage===true;
  if(checkpoint.mode==='backfill' && checkpoint.historicalCoverageVerified!==undefined) await db.prepare('UPDATE ingestion_checkpoints SET historical_coverage_verified=historical_coverage_verified AND ? WHERE id=?').bind(evidence.historicalCoverage===true,checkpoint.id).run();
  if (result.counts.failed > 0 || result.status === "failed") {
    await db.prepare("UPDATE ingestion_checkpoints SET status='failed', last_run_id=?, last_error=?, updated_at=? WHERE id=?").bind(result.runId, result.errors.join(" | ").slice(0, 2000) || "Source batch failed", now, checkpoint.id).run();
    return { ...checkpoint, status: "failed" };
  }
  if (result.continuation) {
    await db.prepare("UPDATE ingestion_checkpoints SET continuation_token=?, status='pending', last_run_id=?, last_error=NULL, updated_at=? WHERE id=?").bind(result.continuation, result.runId, now, checkpoint.id).run();
    return { ...checkpoint, continuation: result.continuation, status: "pending" };
  }

  const nextStart = new Date(new Date(checkpoint.windowEnd).getTime() + 1);
  const coverageEnd = new Date(checkpoint.coverageEnd);
  if (nextStart > coverageEnd) {
    const complete = async (tx: Database) => {
      await tx.prepare("UPDATE ingestion_checkpoints SET continuation_token=NULL, status='complete', last_run_id=?, last_error=NULL, completed_at=?, updated_at=? WHERE id=?").bind(result.runId, now, now, checkpoint.id).run();
      if (checkpoint.scheduled || (checkpoint.mode==='backfill' && historicalCoverageVerified)) {
        const members = await tx.prepare("SELECT COUNT(DISTINCT rr.source_ref) count FROM source_run_results rr JOIN source_runs r ON r.id=rr.source_run_id WHERE r.checkpoint_id=? AND rr.status IN ('inserted','changed','unchanged')").bind(checkpoint.id).first<{count:number}>();
        await recordSourceCompletion(tx,{sourceId:checkpoint.sourceId,ownerKind:'checkpoint',ownerId:checkpoint.id,kind:checkpoint.mode==='backfill'?'backfill':'delta',coverageStart:checkpoint.coverageStart,coverageEnd:checkpoint.coverageEnd,completedAt:now,memberCount:Number(members?.count??0),sourceRunId:result.runId});
      }
    };
    if (checkpoint.scheduled || checkpoint.mode==='backfill') await db.transaction(complete); else await complete(db);
    return { ...checkpoint, continuation: null, status: "complete" };
  }
  const nextEnd = boundedWindowEnd(nextStart, coverageEnd, windowDaysForSource(checkpoint.sourceId, checkpoint.mode));
  await db.prepare("UPDATE ingestion_checkpoints SET window_start=?, window_end=?, continuation_token=NULL, status='pending', last_run_id=?, last_error=NULL, updated_at=? WHERE id=?").bind(nextStart.toISOString(), nextEnd.toISOString(), result.runId, now, checkpoint.id).run();
  return { ...checkpoint, windowStart: nextStart.toISOString(), windowEnd: nextEnd.toISOString(), continuation: null, status: "pending" };
}

export function checkpointBatchKey(checkpoint: IngestionCheckpoint, requestedCheckpointId?: string): string {
  // PostgreSQL keeps one canonical checkpoint for a source/mode/range. A newly named
  // deterministic replay can therefore reopen that canonical row, but it must
  // not reuse the prior replay's successful source_runs. Scope only that case
  // to the caller's validated checkpoint identifier; normal resumptions retain
  // their existing idempotency keys.
  const replayGeneration = requestedCheckpointId && requestedCheckpointId !== checkpoint.id
    ? `:generation:${requestedCheckpointId}`
    : "";
  return `${checkpoint.id}${replayGeneration}:${checkpoint.windowStart}:${checkpoint.continuation ?? "start"}`;
}

function checkpointIdentity(sourceId: string, mode: IngestionMode, start: Date, end: Date): string {
  const compact = (value: Date) => value.toISOString().replace(/[^0-9]/g, "");
  return `${sourceId}:${mode}:${compact(start)}:${compact(end)}`;
}

function boundedWindowEnd(start: Date, coverageEnd: Date, days: number): Date {
  return new Date(Math.min(coverageEnd.getTime(), start.getTime() + days * 86_400_000 - 1));
}

function parseTimestamp(value: string | undefined, fallback: Date, label: string): Date {
  const parsed = value ? new Date(value) : new Date(fallback);
  if (Number.isNaN(parsed.getTime()) || (value && (!/^\d{4}-\d{2}-\d{2}T/.test(value) || value.length > 40))) throw new Error(`${label} must be a valid ISO-8601 timestamp`);
  return parsed;
}

function checkpointFromRow(row: Record<string, unknown>): IngestionCheckpoint {
  return { id: String(row.id), sourceId: String(row.source_id), mode: String(row.mode) as IngestionMode, coverageStart: String(row.coverage_start), coverageEnd: String(row.coverage_end), windowStart: String(row.window_start), windowEnd: String(row.window_end), continuation: row.continuation_token == null ? null : String(row.continuation_token), historicalCoverageVerified: Boolean(row.historical_coverage_verified), scheduled: Boolean(row.scheduled) || isScheduledCheckpointId(String(row.source_id), String(row.id)), status: String(row.status) as IngestionCheckpoint["status"] };
}

export function isCiscoScheduledCheckpointId(value: string | undefined): boolean {
  return Boolean(value && CISCO_SCHEDULED_ID.test(value));
}

export function isScheduledCheckpointId(sourceId: string, value: string | undefined): boolean {
  return Boolean(value && (value.startsWith(`daily:${sourceId}:`) || value.startsWith(`expansion:${sourceId}:delta:`) || (sourceId===CISCO_SOURCE_ID && isCiscoScheduledCheckpointId(value))));
}

export function isScheduledSourceRequest(sourceId: string, request: IngestionRequest): boolean {
  return (request.mode ?? "delta") === "delta" && (request.scheduled===true || (request.scheduled==null && isScheduledCheckpointId(sourceId,request.checkpointId)));
}
/** Compatibility export for existing Cisco callers. */
export function isScheduledCiscoRequest(sourceId: string, request: IngestionRequest): boolean {
  return sourceId===CISCO_SOURCE_ID && isScheduledSourceRequest(sourceId,request);
}
export function validateScheduledScope(sourceId: string, request: IngestionRequest, mode = request.mode ?? "delta"): void {
  if (request.scheduled != null && typeof request.scheduled !== "boolean") throw new Error("scheduled must be a boolean");
  if (request.scheduled===true && mode!=="delta") throw new Error("scheduled ingestion is only supported for delta checkpoints");
  if (request.scheduled===true && !SOURCE_CATALOG.some(source=>source.id===sourceId)) throw new Error("Unknown scheduled source");
  if (request.scheduled===true && request.checkpointId && !isScheduledCheckpointId(sourceId,request.checkpointId)) throw new Error("scheduled checkpoints must use the source daily checkpoint namespace");
  if (request.scheduled===false && isScheduledCheckpointId(sourceId,request.checkpointId)) throw new Error("daily checkpoints require scheduled=true");
}
const scheduledPredicate = "(scheduled=TRUE OR id LIKE 'daily:' || source_id || ':%' OR id LIKE 'expansion:' || source_id || ':delta:%' OR (source_id='cisco-psirt-csaf' AND id LIKE 'daily:cisco:%'))";
async function findOldestIncompleteScheduledCheckpoint(db: Database, sourceId: string): Promise<Record<string, unknown> | null> {
  const result = await db.prepare(`SELECT id, source_id, mode, coverage_start, coverage_end, window_start, window_end, continuation_token, status, historical_coverage_verified, scheduled FROM ingestion_checkpoints WHERE source_id=? AND mode='delta' AND status<>'complete' AND retired_at IS NULL AND ${scheduledPredicate} ORDER BY created_at ASC, updated_at ASC, id ASC LIMIT 1`).bind(sourceId).all<Record<string, unknown>>();
  return result.results?.[0] ?? null;
}
async function findLastCompletedScheduledCoverageEnd(db: Database, sourceId: string): Promise<string | null> {
  const result = await db.prepare(`SELECT id, coverage_end FROM ingestion_checkpoints WHERE source_id=? AND mode='delta' AND status='complete' AND ${scheduledPredicate} ORDER BY coverage_end DESC, completed_at DESC, id DESC LIMIT 1`).bind(sourceId).all<Record<string, unknown>>();
  return result.results?.[0]?.coverage_end == null ? null : String(result.results[0].coverage_end);
}
function compactTimestamp(value: Date): string { return value.toISOString().replace(/[^0-9]/g, ""); }
