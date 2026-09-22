import type { Database } from "../../db/database";
import type { IngestionMode, IngestResult } from "./contracts";
import { defaultDeltaStart, DELTA_LOOKBACK_DAYS, INGESTION_MODES, rollingWindowStart, windowDaysForSource } from "./operational-policy";

const CISCO_SOURCE_ID = "cisco-psirt-csaf";
const CISCO_SCHEDULED_ID = /^(?:daily:cisco:|daily:cisco-psirt-csaf:)/;

export interface IngestionRequest {
  mode?: IngestionMode;
  since?: string;
  until?: string;
  checkpointId?: string;
  scheduled?: boolean;
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

export async function loadOrCreateCheckpoint(db: Database, sourceId: string, request: IngestionRequest, now = new Date()): Promise<IngestionCheckpoint> {
  validateScheduledScope(sourceId, request, request.mode ?? "delta");
  const scheduledCisco = isScheduledCiscoRequest(sourceId, request);
  if (scheduledCisco) {
    const oldest = await findOldestIncompleteCiscoCheckpoint(db);
    if (oldest) return checkpointFromRow(oldest);
  }
  if (request.checkpointId) {
    const existing = await db.prepare("SELECT id, source_id, mode, coverage_start, coverage_end, window_start, window_end, continuation_token, status FROM ingestion_checkpoints WHERE id=?").bind(request.checkpointId).first<Record<string, unknown>>();
    if (existing) {
      if (String(existing.source_id) !== sourceId || (request.mode && String(existing.mode) !== request.mode)) throw new Error("Checkpoint identity conflicts with the requested source or mode");
      if (!scheduledCisco && ((request.since && new Date(request.since).toISOString() !== String(existing.coverage_start)) || (request.until && new Date(request.until).toISOString() !== String(existing.coverage_end)))) throw new Error("Checkpoint identity conflicts with the requested coverage range");
      if (!(scheduledCisco && String(existing.status) === "complete")) return checkpointFromRow(existing);
    }
  }
  let planned = normalizeIngestionRequest(sourceId, request, now);
  if (scheduledCisco) {
    const boundary = await findLastCompletedCiscoCoverageEnd(db);
    const start = boundary
      ? new Date(Math.max(rollingWindowStart(now).getTime(), new Date(boundary).getTime() - DELTA_LOOKBACK_DAYS * 86_400_000))
      : new Date(planned.coverageStart);
    const end = new Date(now);
    if (start <= end) {
      const baseId = request.checkpointId ?? "daily:cisco:today";
      const generatedId = `${baseId}:${compactTimestamp(start)}-${compactTimestamp(end)}`;
      planned = normalizeIngestionRequest(sourceId, { ...request, since: start.toISOString(), until: end.toISOString(), checkpointId: generatedId }, now);
      if (end.getTime() - start.getTime() <= DELTA_LOOKBACK_DAYS * 86_400_000) planned = { ...planned, windowEnd: end.toISOString() };
    }
  }
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

export async function markCheckpointRunning(db: Database, checkpointId: string): Promise<void> {
  await db.prepare("UPDATE ingestion_checkpoints SET status='running', last_error=NULL, updated_at=? WHERE id=? AND status<>'complete'").bind(new Date().toISOString(), checkpointId).run();
}

export async function markCheckpointFailed(db: Database, checkpointId: string, error: string): Promise<void> {
  await db.prepare("UPDATE ingestion_checkpoints SET status='failed', last_error=?, updated_at=? WHERE id=? AND status<>'complete'").bind(error.slice(0, 2000), new Date().toISOString(), checkpointId).run();
}

export async function advanceCheckpoint(db: Database, checkpoint: IngestionCheckpoint, result: IngestResult): Promise<IngestionCheckpoint> {
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
  return { id: String(row.id), sourceId: String(row.source_id), mode: String(row.mode) as IngestionMode, coverageStart: String(row.coverage_start), coverageEnd: String(row.coverage_end), windowStart: String(row.window_start), windowEnd: String(row.window_end), continuation: row.continuation_token == null ? null : String(row.continuation_token), status: String(row.status) as IngestionCheckpoint["status"] };
}

export function isCiscoScheduledCheckpointId(value: string | undefined): boolean {
  return Boolean(value && CISCO_SCHEDULED_ID.test(value));
}

export function isScheduledCiscoRequest(sourceId: string, request: IngestionRequest): boolean {
  const mode = request.mode ?? "delta";
  return sourceId === CISCO_SOURCE_ID && mode === "delta" && (request.scheduled === true || (request.scheduled == null && isCiscoScheduledCheckpointId(request.checkpointId)));
}

export function validateScheduledScope(sourceId: string, request: IngestionRequest, mode = request.mode ?? "delta"): void {
  if (request.scheduled != null && typeof request.scheduled !== "boolean") throw new Error("scheduled must be a boolean");
  if (request.scheduled === true && (sourceId !== CISCO_SOURCE_ID || mode !== "delta")) throw new Error("scheduled ingestion is only supported for Cisco delta checkpoints");
  if (request.scheduled === true && request.checkpointId && !isCiscoScheduledCheckpointId(request.checkpointId)) throw new Error("scheduled Cisco checkpoints must use the daily checkpoint namespace");
  if (request.scheduled === false && sourceId === CISCO_SOURCE_ID && isCiscoScheduledCheckpointId(request.checkpointId)) throw new Error("daily Cisco checkpoints require scheduled=true");
}

async function findOldestIncompleteCiscoCheckpoint(db: Database): Promise<Record<string, unknown> | null> {
  const result = await db.prepare("SELECT id, source_id, mode, coverage_start, coverage_end, window_start, window_end, continuation_token, status FROM ingestion_checkpoints WHERE source_id=? AND mode='delta' AND status<>'complete' AND (id LIKE 'daily:cisco:%' OR id LIKE 'daily:cisco-psirt-csaf:%') ORDER BY created_at ASC, updated_at ASC, id ASC LIMIT 1").bind(CISCO_SOURCE_ID).all<Record<string, unknown>>();
  const rows = result.results ?? [];
  return rows[0] ?? null;
}

async function findLastCompletedCiscoCoverageEnd(db: Database): Promise<string | null> {
  const result = await db.prepare("SELECT id, coverage_end FROM ingestion_checkpoints WHERE source_id=? AND mode='delta' AND status='complete' AND (id LIKE 'daily:cisco:%' OR id LIKE 'daily:cisco-psirt-csaf:%') ORDER BY coverage_end DESC, completed_at DESC, id DESC LIMIT 1").bind(CISCO_SOURCE_ID).all<Record<string, unknown>>();
  const row = result.results?.[0];
  return row?.coverage_end == null ? null : String(row.coverage_end);
}

function compactTimestamp(value: Date): string {
  return value.toISOString().replace(/[^0-9]/g, "");
}
