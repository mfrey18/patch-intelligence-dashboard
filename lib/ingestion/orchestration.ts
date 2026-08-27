import type { IngestionMode, IngestResult } from "./contracts";
import { defaultDeltaStart, INGESTION_MODES, rollingWindowStart, windowDaysForSource } from "./operational-policy";

export interface IngestionRequest {
  mode?: IngestionMode;
  since?: string;
  until?: string;
  checkpointId?: string;
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
  status: "pending" | "running" | "failed" | "complete";
}

export function normalizeIngestionRequest(sourceId: string, request: IngestionRequest, now = new Date()): Omit<IngestionCheckpoint, "status" | "continuation"> {
  const mode = request.mode ?? "delta";
  if (!INGESTION_MODES.includes(mode)) throw new Error("Unsupported ingestion mode");
  if (mode === "replay" && (!request.since || !request.until)) throw new Error("Replay mode requires explicit since and until timestamps");

  const defaultStart = mode === "backfill" ? rollingWindowStart(now) : mode === "patch_tuesday" ? new Date(now.getTime() - 7 * 86_400_000) : defaultDeltaStart(now);
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

export async function loadOrCreateCheckpoint(db: D1Database, sourceId: string, request: IngestionRequest, now = new Date()): Promise<IngestionCheckpoint> {
  if (request.checkpointId) {
    const existing = await db.prepare("SELECT id, source_id, mode, coverage_start, coverage_end, window_start, window_end, continuation_token, status FROM ingestion_checkpoints WHERE id=?").bind(request.checkpointId).first<Record<string, unknown>>();
    if (existing) {
      if (String(existing.source_id) !== sourceId || (request.mode && String(existing.mode) !== request.mode)) throw new Error("Checkpoint identity conflicts with the requested source or mode");
      if ((request.since && new Date(request.since).toISOString() !== String(existing.coverage_start)) || (request.until && new Date(request.until).toISOString() !== String(existing.coverage_end))) throw new Error("Checkpoint identity conflicts with the requested coverage range");
      return checkpointFromRow(existing);
    }
  }
  const planned = normalizeIngestionRequest(sourceId, request, now);
  const timestamp = now.toISOString();
  await db.prepare("INSERT INTO ingestion_checkpoints (id, source_id, mode, coverage_start, coverage_end, window_start, window_end, continuation_token, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, 'pending', ?, ?) ON CONFLICT DO NOTHING").bind(planned.id, sourceId, planned.mode, planned.coverageStart, planned.coverageEnd, planned.windowStart, planned.windowEnd, timestamp, timestamp).run();
  let row = await db.prepare("SELECT id, source_id, mode, coverage_start, coverage_end, window_start, window_end, continuation_token, status FROM ingestion_checkpoints WHERE id=?").bind(planned.id).first<Record<string, unknown>>();
  let matchedCanonicalRange = false;
  if (!row) {
    row = await db.prepare("SELECT id, source_id, mode, coverage_start, coverage_end, window_start, window_end, continuation_token, status FROM ingestion_checkpoints WHERE source_id=? AND mode=? AND coverage_start=? AND coverage_end=? LIMIT 1").bind(sourceId, planned.mode, planned.coverageStart, planned.coverageEnd).first<Record<string, unknown>>();
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

export async function markCheckpointRunning(db: D1Database, checkpointId: string): Promise<void> {
  await db.prepare("UPDATE ingestion_checkpoints SET status='running', last_error=NULL, updated_at=? WHERE id=? AND status<>'complete'").bind(new Date().toISOString(), checkpointId).run();
}

export async function markCheckpointFailed(db: D1Database, checkpointId: string, error: string): Promise<void> {
  await db.prepare("UPDATE ingestion_checkpoints SET status='failed', last_error=?, updated_at=? WHERE id=? AND status<>'complete'").bind(error.slice(0, 2000), new Date().toISOString(), checkpointId).run();
}

export async function advanceCheckpoint(db: D1Database, checkpoint: IngestionCheckpoint, result: IngestResult): Promise<IngestionCheckpoint> {
  const now = new Date().toISOString();
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
    await db.prepare("UPDATE ingestion_checkpoints SET continuation_token=NULL, status='complete', last_run_id=?, last_error=NULL, completed_at=?, updated_at=? WHERE id=?").bind(result.runId, now, now, checkpoint.id).run();
    return { ...checkpoint, continuation: null, status: "complete" };
  }
  const nextEnd = boundedWindowEnd(nextStart, coverageEnd, windowDaysForSource(checkpoint.sourceId, checkpoint.mode));
  await db.prepare("UPDATE ingestion_checkpoints SET window_start=?, window_end=?, continuation_token=NULL, status='pending', last_run_id=?, last_error=NULL, updated_at=? WHERE id=?").bind(nextStart.toISOString(), nextEnd.toISOString(), result.runId, now, checkpoint.id).run();
  return { ...checkpoint, windowStart: nextStart.toISOString(), windowEnd: nextEnd.toISOString(), continuation: null, status: "pending" };
}

export function checkpointBatchKey(checkpoint: IngestionCheckpoint, requestedCheckpointId?: string): string {
  // D1 keeps one canonical checkpoint for a source/mode/range. A newly named
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
  return { id: String(row.id), sourceId: String(row.source_id), mode: String(row.mode) as IngestionMode, coverageStart: String(row.coverage_start), coverageEnd: String(row.coverage_end), windowStart: String(row.window_start), windowEnd: String(row.window_end), continuation: row.continuation_token == null ? null : String(row.continuation_token), status: String(row.status) as IngestionCheckpoint["status"] };
}
