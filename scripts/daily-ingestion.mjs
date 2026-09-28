// Run the scheduled Cisco delta until it reaches a fresh checkpoint or the
// workflow's bounded processing budget. The API owns checkpoint selection and
// Cisco's native adapter owns upstream pacing and Retry-After handling.
import { appendFile, writeFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

export const LEGACY_BATCH_SOURCES = new Set(['microsoft-msrc-csaf', 'palo-alto-psirt-csaf', 'mozilla-mfsa-yaml']);
export const CISCO_SOURCE = 'cisco-psirt-csaf';
export const DEFAULT_MAX_BATCHES = 50;
export const DEFAULT_MAX_DURATION_MS = 10 * 60 * 1000;
export const DEFAULT_MAX_BACKLOG_AGE_MS = 36 * 60 * 60 * 1000;

const sleepDefault = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

/**
 * Parse a Retry-After value as an absolute deadline. Cisco may return either
 * seconds or an HTTP date. Invalid values are deliberately ignored: the
 * service's own cooldown state remains authoritative in that case.
 */
export function retryAfterDeadline(value, now = Date.now()) {
  if (value == null || value === '') return null;
  if (/^\d+(?:\.\d+)?$/.test(String(value).trim())) return now + Number(value) * 1000;
  const timestamp = Date.parse(String(value));
  return Number.isFinite(timestamp) ? timestamp : null;
}

function firstResult(payload) {
  return payload?.results?.[0] ?? payload?.result ?? null;
}

function valueFrom(...values) {
  return values.find((value) => value != null && value !== '');
}

function toDateMs(value) {
  if (value == null) return null;
  const parsed = new Date(value).getTime();
  return Number.isFinite(parsed) ? parsed : null;
}

export function checkpointSignature(checkpoint) {
  if (!checkpoint) return null;
  return JSON.stringify([
    checkpoint.id ?? null,
    checkpoint.status ?? null,
    checkpoint.coverageStart ?? checkpoint.coverage_start ?? null,
    checkpoint.coverageEnd ?? checkpoint.coverage_end ?? null,
    checkpoint.windowStart ?? checkpoint.window_start ?? null,
    checkpoint.windowEnd ?? checkpoint.window_end ?? null,
    checkpoint.continuation ?? checkpoint.continuationToken ?? checkpoint.continuation_token ?? null,
  ]);
}

function normalizeCheckpoint(checkpoint) {
  if (!checkpoint || typeof checkpoint !== 'object') return null;
  return {
    ...checkpoint,
    coverageEnd: checkpoint.coverageEnd ?? checkpoint.coverage_end,
    coverageStart: checkpoint.coverageStart ?? checkpoint.coverage_start,
    windowStart: checkpoint.windowStart ?? checkpoint.window_start,
    windowEnd: checkpoint.windowEnd ?? checkpoint.window_end,
    continuation: checkpoint.continuation ?? checkpoint.continuationToken ?? checkpoint.continuation_token ?? null,
  };
}

function isConcurrentSkip(run) {
  const text = [run?.error, run?.reason, ...(run?.errors ?? [])].filter(Boolean).join(' ');
  return ['skipped', 'pending'].includes(run?.status) && /already\s+running|currently\s+running|lease/i.test(text);
}

function retryDeadline({ response, payload, run, now }) {
  const header = response?.headers?.get?.('retry-after');
  const headerDeadline = retryAfterDeadline(header, now);
  const field = valueFrom(run?.retryAfter, run?.retry_after, run?.cooldownUntil, run?.cooldown_until, run?.progress?.retryAt, payload?.retryAfter, payload?.retry_after);
  const fieldDeadline = typeof field === 'number'
    ? (field > now ? field : now + field * 1000)
    : retryAfterDeadline(field, now);
  return Math.max(headerDeadline ?? 0, fieldDeadline ?? 0) || null;
}

function responseFailure(response, payload, run) {
  const httpFailure = response && !response.ok;
  const resultFailure = run?.status === 'failed' || run?.counts?.failed > 0 || run?.checkpoint?.status === 'failed';
  return Boolean(httpFailure || resultFailure);
}

function responseError(response, payload, run) {
  return [payload?.error, run?.error, ...(run?.errors ?? [])].filter(Boolean).join(' | ') || `HTTP ${response?.status ?? 0}: Cisco ingestion failed`;
}

function writeOutputLine(name, value) {
  return `${name}=${String(value).replace(/[\r\n]/g, ' ')}\n`;
}

export function renderDailySummary(summary) {
  const lines = [
    `### ${summary.source ?? CISCO_SOURCE} ingestion: **${summary.status}**`,
    '',
    `- Date window: \`${summary.dailyDate}\``,
    `- Batches: ${summary.batches}/${summary.maxBatches}`,
    `- Elapsed: ${Math.round(summary.elapsedMs / 1000)}s/${Math.round(summary.maxDurationMs / 1000)}s`,
    `- Checkpoint: \`${summary.checkpointId}\``,
  ];
  if (summary.coverageEnd) lines.push(`- Coverage through: \`${summary.coverageEnd}\``);
  if (summary.reason) lines.push(`- ${summary.reason}`);
  if (summary.error) lines.push(`- Error: ${summary.error}`);
  if (summary.alert) lines.push('- Alert: required');
  else if (summary.status === 'pending') lines.push('- Pending work is resumable; this run did not complete a daily cycle.');
  return `${lines.join('\n')}\n`;
}

/**
 * Run one pinned UTC daily window. `now`, `fetchImpl`, and `sleep` are
 * injectable so interruption, midnight rollover, cooldown, and concurrency
 * behavior can be tested without network traffic or wall-clock waits.
 */
export async function runDailyIngestion({
  env = process.env,
  fetchImpl = fetch,
  sleep = sleepDefault,
  now = Date.now,
  log = () => {},
  maxBatches = Number(env.SOURCE_MAX_BATCHES ?? env.CISCO_MAX_BATCHES ?? DEFAULT_MAX_BATCHES),
  maxDurationMs = Number(env.SOURCE_MAX_DURATION_MS ?? env.CISCO_MAX_DURATION_MS ?? DEFAULT_MAX_DURATION_MS),
  maxBacklogAgeMs = Number(env.CISCO_MAX_BACKLOG_AGE_MS ?? DEFAULT_MAX_BACKLOG_AGE_MS),
  sourceId = env.SOURCE_ID ?? CISCO_SOURCE,
  mode = env.INGEST_MODE ?? 'delta',
  checkpointOverride = env.CHECKPOINT_ID || undefined,
  since = env.SINCE, until = env.UNTIL,
  scheduled = env.SCHEDULED !== 'false' && mode === 'delta' && !since && !until && (!checkpointOverride || checkpointOverride.startsWith(`daily:${sourceId}:`) || checkpointOverride.startsWith(`expansion:${sourceId}:delta:`) || (sourceId === CISCO_SOURCE && checkpointOverride.startsWith('daily:cisco:'))),
  maxItems = LEGACY_BATCH_SOURCES.has(sourceId) ? 12 : 1,
  origin = env.API_ORIGIN ?? env.PRIVATE_API_BASE_URL ?? env.PUBLIC_API_BASE_URL ?? 'http://127.0.0.1:3002',
  secret = env.INGEST_SECRET,
} = {}) {
  if (!secret) throw new Error('INGEST_SECRET is required');
  if (!Number.isSafeInteger(maxBatches) || maxBatches < 1 || maxBatches > 50) throw new Error('maxBatches must be an integer from 1 to 50');
  if (!Number.isFinite(maxDurationMs) || maxDurationMs <= 0 || maxDurationMs > DEFAULT_MAX_DURATION_MS) throw new Error('maxDurationMs must be positive and at most 600000');
  if (!Number.isFinite(maxBacklogAgeMs) || maxBacklogAgeMs < 0) throw new Error('maxBacklogAgeMs must be non-negative');

  const originUrl = new URL(origin);
  if (!['http:', 'https:'].includes(originUrl.protocol)) throw new Error('API origin must use HTTP or HTTPS');
  const startedAtMs = now();
  const startedAt = new Date(startedAtMs).toISOString();
  const dailyDate = startedAt.slice(0, 10); // Pin this before any request crosses UTC midnight.
  const checkpointId = checkpointOverride ?? (scheduled ? `daily:${sourceId}:${dailyDate}` : `${mode}:${sourceId}:${startedAt}`);
  const deadline = startedAtMs + maxDurationMs;
  let previousPosition;
  let batches = 0;
  let latestCheckpoint = null;
  let hadRequestFailure = false;
  let retries = 0;
  let backlogTooOld = false;

  const emit = (event) => log({ at: new Date(now()).toISOString(), source: sourceId, ...event });
  const baseSummary = () => ({
    status: 'pending', source: sourceId, dailyDate, startedAt,
    batches, invocations: batches, maxBatches, maxDurationMs, elapsedMs: Math.max(0, now() - startedAtMs),
    requestedCheckpointId: checkpointId,
    checkpointId: latestCheckpoint?.id ?? checkpointId,
    checkpoint: latestCheckpoint, coverageEnd: latestCheckpoint?.coverageEnd ?? null,
    retries, hadRequestFailure, backlogTooOld, alert: false,
  });
  const finish = (status, fields = {}) => {
    const summary = { ...baseSummary(), ...fields, status, elapsedMs: Math.max(0, now() - startedAtMs) };
    if(sourceId !== CISCO_SOURCE)for(const key of ['reason','error'])if(summary[key])summary[key]=summary[key].replaceAll('Cisco',sourceId);
    summary.alert = Boolean(summary.alert || summary.hadRequestFailure || status === 'failed' || summary.backlogTooOld);
    emit({ event: 'summary', ...summary });
    return summary;
  };

  emit({ event: 'start', dailyDate, checkpointId, maxBatches, maxDurationMs });

  for (;;) {
    const current = now();
    if (current >= deadline) return finish('pending', { reason: 'Processing time budget exhausted; checkpoint remains resumable.' });
    if (batches >= maxBatches) return finish('pending', { reason: 'Batch budget exhausted; checkpoint remains resumable.' });

    const body = { sources: [sourceId], mode, scheduled, checkpointId, invocationStartedAt: startedAt, budgetMs: Math.max(1, deadline-now()), maxItems, refreshProjection: false, ...(since ? {since} : {}), ...(until ? {until} : {}) };
    let response;
    let payload;
    try {
      batches++;
      const controller = new AbortController();
      let timedOut = false;
      const timer = setTimeout(() => { timedOut = true; controller.abort(); }, Math.max(1, deadline - now()));
      try {
        response = await fetchImpl(new URL('/api/internal/ingest', originUrl), {
          method: 'POST',
          headers: { Authorization: `Bearer ${secret}`, 'Content-Type': 'application/json' },
          body: JSON.stringify(body), signal: controller.signal,
        });
        const text = await response.text();
        try { payload = JSON.parse(text); } catch { payload = { error: text.slice(0, 1000) || `HTTP ${response.status}` }; }
      } catch (error) {
        if (timedOut || now() >= deadline) return finish('pending', { reason: 'Processing time budget exhausted while waiting for Cisco; checkpoint remains resumable.' });
        throw error;
      } finally {
        clearTimeout(timer);
      }
    } catch (error) {
      hadRequestFailure = true;
      return finish('failed', { error: error instanceof Error ? error.message : String(error) });
    }

    const run = firstResult(payload);
    const progress = run?.progress;
    const checkpoint = normalizeCheckpoint(run?.checkpoint ?? payload?.checkpoint ?? (progress?.ownerId ? {id:progress.ownerId,status:progress.state,continuation:progress.position,coverageEnd:progress.coverageEnd} : null));
    latestCheckpoint = checkpoint ?? latestCheckpoint;
    const retryAt = retryDeadline({ response, payload, run, now: now() });
    const failed = responseFailure(response, payload, run);
    const concurrent = isConcurrentSkip(run);
    const cooldown = Boolean(retryAt && retryAt > now()) || /cooldown|rate.?limit/i.test([run?.reason, run?.error, payload?.error].filter(Boolean).join(' '));

    emit({ event: 'batch', batch: batches, status: run?.status ?? payload?.status, httpStatus: response.status, checkpoint, retryAt: retryAt ? new Date(retryAt).toISOString() : null });

    if (/paused/i.test(run?.reason ?? '')) return finish('pending', { reason: 'Source is paused; no cycle was completed.' });
    if (concurrent) return finish('pending', { reason: 'Cisco ingestion is already running; this run will be resumed by the next window.', concurrent: true });

    if (failed) {
      hadRequestFailure = true;
      const message = responseError(response, payload, run);
      if (retryAt && retryAt > now()) {
        if (batches >= maxBatches) return finish('pending', { reason: `Cisco requested a cooldown until ${new Date(retryAt).toISOString()} after the final allowed batch; checkpoint remains resumable.`, retryAt: new Date(retryAt).toISOString() });
        retries++;
        const remaining = deadline - now();
        const waitMs = retryAt - now();
        if (waitMs >= remaining) return finish('pending', { reason: `Cisco requested a cooldown until ${new Date(retryAt).toISOString()}; checkpoint remains resumable.`, retryAt: new Date(retryAt).toISOString() });
        emit({ event: 'retry-wait', waitMs, retryAt: new Date(retryAt).toISOString(), error: message });
        await sleep(waitMs);
        continue;
      }
      return finish('failed', { error: message });
    }

    if (cooldown && retryAt && retryAt > now()) {
      if (batches >= maxBatches) return finish('pending', { reason: `Cisco cooldown arrived after the final allowed batch; checkpoint remains resumable until ${new Date(retryAt).toISOString()}.`, retryAt: new Date(retryAt).toISOString() });
      const remaining = deadline - now();
      const waitMs = retryAt - now();
      if (waitMs >= remaining) return finish('pending', { reason: `Cisco cooldown extends beyond this run at ${new Date(retryAt).toISOString()}; checkpoint remains resumable.`, retryAt: new Date(retryAt).toISOString() });
      retries++;
      emit({ event: 'cooldown-wait', waitMs, retryAt: new Date(retryAt).toISOString() });
      await sleep(waitMs);
      continue;
    }

    if (!run) return finish('failed', { error: 'Cisco response did not include a result.' });
    const status = run.status ?? payload.status;
    if (!['success', 'unchanged', 'partial', 'pending'].includes(status)) return finish('failed', { error: `Unexpected Cisco ingestion status: ${status ?? 'missing'}` });
    const checkpointStatus = checkpoint?.status ?? progress?.state ?? (['success', 'unchanged'].includes(status) && !run.boundHit && !run.continuation ? 'complete' : 'pending');
    const coverageEndMs = toDateMs(checkpoint?.coverageEnd);
    if (coverageEndMs != null && startedAtMs - coverageEndMs > maxBacklogAgeMs) backlogTooOld = true;

    const freshComplete = checkpointStatus === 'complete' && (!scheduled || (coverageEndMs != null && coverageEndMs >= startedAtMs));
    if (freshComplete) {
      if (now() > deadline) return finish('pending', { reason: 'The fresh checkpoint completed after the processing budget; verify it on the next run.' });
      return finish('complete', { reason: 'Cisco coverage reached the invocation start time.' });
    }

    const position = checkpointSignature(checkpoint);
    if (position && position === previousPosition) return finish('failed', { error: 'Cisco checkpoint did not advance; stopping repeated requests.', stalled: true });
    previousPosition = position;

    // A completed historical checkpoint is intentionally followed by another
    // request. The API must create/select the next overlapping window instead
    // of returning the same completed checkpoint forever.
    if (!checkpoint) return finish('pending', { reason: 'Cisco work is pending but no checkpoint was returned; retry the scheduled run.' });
  }
}

export async function writeGithubResult(summary, { outputPath = process.env.GITHUB_OUTPUT, summaryPath = process.env.GITHUB_STEP_SUMMARY, reportPath = process.env.SOURCE_REPORT_PATH, append = appendFile } = {}) {
  const output = [
    writeOutputLine('daily_status', summary.status),
    writeOutputLine('daily_complete', summary.status === 'complete' ? 'true' : 'false'),
    writeOutputLine('daily_pending', summary.status === 'pending' ? 'true' : 'false'),
    writeOutputLine('daily_alert', summary.alert ? 'true' : 'false'),
    writeOutputLine('daily_batches', summary.batches),
    writeOutputLine('daily_checkpoint', summary.checkpointId),
  ].join('');
  if (reportPath) await writeFile(reportPath, JSON.stringify(summary));
  if (outputPath) await append(outputPath, output);
  if (summaryPath) await append(summaryPath, renderDailySummary(summary));
  return summary;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const summary = await runDailyIngestion({ log: (event) => console.log(JSON.stringify(event)) });
    await writeGithubResult(summary);
    if (summary.alert && summary.status !== 'failed') {
      console.log(`::warning title=Cisco daily ingestion alert::${summary.hadRequestFailure ? 'An upstream request failed before recovery.' : summary.backlogTooOld ? 'Cisco backlog is older than the configured freshness threshold.' : 'Cisco scheduled work requires attention.'}`);
    }
    // Pending is a healthy, resumable outcome. The explicit output and summary
    // prevent it from being mistaken for a completed daily cycle while avoiding
    // a noisy failure alert for a normal bounded continuation.
    if (summary.status === 'failed') process.exitCode = 1;
  } catch (error) {
    const summary = { status: 'failed', alert: true, batches: 0, checkpointId: `daily:${CISCO_SOURCE}:${new Date().toISOString().slice(0, 10)}`, dailyDate: new Date().toISOString().slice(0, 10), elapsedMs: 0, maxBatches: DEFAULT_MAX_BATCHES, maxDurationMs: DEFAULT_MAX_DURATION_MS, error: error instanceof Error ? error.message : String(error) };
    await writeGithubResult(summary);
    console.error(summary.error);
    process.exitCode = 1;
  }
}
