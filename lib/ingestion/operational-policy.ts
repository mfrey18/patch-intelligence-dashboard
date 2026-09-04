import type { IngestionMode } from "./contracts";

export const INTELLIGENCE_WINDOW_MONTHS = 6;
// Keep dense EPSS history where daily movement is operationally useful, then
// retain one published point per week for the remainder of the six-month view.
export const EPSS_DAILY_RETENTION_DAYS = 42;
export const EPSS_WEEKLY_RETENTION_MONTHS = INTELLIGENCE_WINDOW_MONTHS;
export const DELTA_LOOKBACK_DAYS = 3;
export const BACKFILL_WINDOW_DAYS = 1;
export const REPLAY_WINDOW_DAYS = 1;
export const PATCH_TUESDAY_WINDOW_DAYS = 1;
export const SOURCE_WINDOW_DAYS: Readonly<Record<string, number>> = Object.freeze({
  "palo-alto-psirt-csaf": 7,
  "mozilla-mfsa-yaml": 7,
});

// Workers Free permits 50 external subrequests per invocation. Twelve advisory
// fetches leave room for discovery, redirects, OAuth, and configured retries.
export const WORKERS_FREE_EXTERNAL_SUBREQUEST_LIMIT = 50;
export const EXTERNAL_SUBREQUEST_RESERVE = 8;
export const MAX_ADVISORY_FETCHES_PER_INVOCATION = 12;

export const INGESTION_MODES = ["delta", "replay", "backfill", "patch_tuesday"] as const satisfies readonly IngestionMode[];

export function rollingWindowStart(now = new Date()): Date {
  const day = now.getUTCDate();
  const start = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - INTELLIGENCE_WINDOW_MONTHS, 1));
  const lastDay = new Date(Date.UTC(start.getUTCFullYear(), start.getUTCMonth() + 1, 0)).getUTCDate();
  start.setUTCDate(Math.min(day, lastDay));
  start.setUTCHours(0, 0, 0, 0);
  return start;
}

export function defaultDeltaStart(now = new Date()): Date {
  return new Date(now.getTime() - DELTA_LOOKBACK_DAYS * 86_400_000);
}

export function defaultDiscoveryStart(value?: string, now = new Date()): Date {
  return value ? new Date(value) : defaultDeltaStart(now);
}

export function windowDaysForMode(mode: IngestionMode): number {
  if (mode === "backfill") return BACKFILL_WINDOW_DAYS;
  if (mode === "replay") return REPLAY_WINDOW_DAYS;
  if (mode === "patch_tuesday") return PATCH_TUESDAY_WINDOW_DAYS;
  return DELTA_LOOKBACK_DAYS;
}

export function windowDaysForSource(sourceId: string, mode: IngestionMode): number {
  if (mode === "backfill" || mode === "replay") return SOURCE_WINDOW_DAYS[sourceId] ?? windowDaysForMode(mode);
  return windowDaysForMode(mode);
}

export function clampBatchSize(value?: number): number {
  if (value == null || !Number.isFinite(value)) return MAX_ADVISORY_FETCHES_PER_INVOCATION;
  return Math.max(1, Math.min(MAX_ADVISORY_FETCHES_PER_INVOCATION, Math.trunc(value)));
}

export function encodeContinuationOffset(offset: number): string {
  return `offset:${Math.max(0, Math.trunc(offset))}`;
}

export function decodeContinuationOffset(value?: string): number {
  if (!value) return 0;
  const match = /^offset:(\d{1,9})$/.exec(value);
  if (!match) throw new Error("Invalid ingestion continuation token");
  return Number(match[1]);
}
