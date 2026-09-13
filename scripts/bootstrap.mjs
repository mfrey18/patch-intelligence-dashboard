// Resume bounded vendor checkpoints, verify current deltas, then enrich the final CVE universe.
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';

const vendors = ['microsoft-msrc-csaf', 'cisco-psirt-csaf', 'palo-alto-psirt-csaf', 'mozilla-mfsa-yaml'];
const enrichments = ['cisa-kev', 'first-epss'];
const retryableStatuses = new Set([429, 500, 502, 503, 504]);

/** Injectable transport and clock let the operational flow be tested without vendor traffic. */
export async function runBootstrap({ env = process.env, fetchImpl = fetch, sleep = delay, now = Date.now, invocationId = randomUUID(), log = (event) => console.log(JSON.stringify(event)) } = {}) {
  assert.ok(env.INGEST_SECRET, 'INGEST_SECRET is required');
  const maxInvocations = Number(env.BOOTSTRAP_MAX_INVOCATIONS ?? 1000);
  assert.ok(Number.isSafeInteger(maxInvocations) && maxInvocations >= 1 && maxInvocations <= 2000, 'BOOTSTRAP_MAX_INVOCATIONS must be an integer from 1 to 2000');
  const origin = new URL(env.PRIVATE_API_BASE_URL ?? 'http://127.0.0.1:3002');
  assert.ok(['http:', 'https:'].includes(origin.protocol), 'Private API origin must use HTTP or HTTPS');
  const secretValues = [env.INGEST_SECRET, env.CISCO_CLIENT_ID, env.CISCO_CLIENT_SECRET].filter(Boolean);
  const safeError = (error) => secretValues.reduce((message, secret) => message.replaceAll(secret, '[redacted]'), String(error?.message ?? error)).slice(0, 1500);
  const emit = (event) => log({ at: new Date(now()).toISOString(), ...event });

  async function call(path, body, budget) {
    for (let retry = 0; ; retry++) {
      if (budget.used >= budget.limit) throw new Error(`Invocation limit reached (${budget.limit}); checkpoint is resumable`);
      budget.used++;
      const response = await fetchImpl(new URL(path, origin), {
        method: 'POST', headers: { Authorization: `Bearer ${env.INGEST_SECRET}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(body), signal: AbortSignal.timeout(150000),
      });
      // A non-JSON error response must not prevent other sources from running.
      const text = await response.text();
      let result;
      try { result = JSON.parse(text); } catch { result = { error: text.slice(0, 1000) || `HTTP ${response.status}` }; }
      const run = result.results?.[0];
      const failed = !response.ok || result.status === 'failed' || (body.sources && (!run || run.sourceId !== body.sources[0])) ||
        ['failed', 'skipped'].includes(run?.status) || run?.checkpoint?.status === 'failed' || run?.counts?.failed > 0;
      if (!failed) return result;
      const message = [result.error, run?.error, ...(run?.errors ?? [])].filter(Boolean).join(' | ') || `HTTP ${response.status}: ingestion did not succeed`;
      // Source fetch errors arrive inside a 207 response, while API rate limits use HTTP status.
      const sourceStatus = Number(message.match(/\bHTTP\s+(\d{3})\b/i)?.[1]);
      const transient = retryableStatuses.has(response.status) || retryableStatuses.has(sourceStatus);
      const retryAfter = response.headers.get('retry-after');
      const retryAfterMs = retryAfter == null ? 0 : /^\d+(?:\.\d+)?$/.test(retryAfter)
        ? Number(retryAfter) * 1000 : Math.max(0, Date.parse(retryAfter) - now());
      const waitMs = Math.max(2000 * 2 ** retry, Number.isFinite(retryAfterMs) ? retryAfterMs : 0);
      // Defer long rate-limit windows to the next invocation rather than retrying before Retry-After.
      if (!transient || retry >= 2 || budget.used >= budget.limit || waitMs > 60000) {
        throw new Error(`${message}${waitMs > 60000 && transient ? `; retry after ${new Date(now() + waitMs).toISOString()}` : ''}`);
      }
      emit({ event: 'retry', source: body.sources?.[0], retry: retry + 1, waitMs, error: safeError(message) });
      await sleep(waitMs);
    }
  }

  async function runVendorPhase(source, mode, budget) {
    const checkpointId = mode === 'backfill' ? `backfill:${source}:six-month` : `bootstrap:${invocationId}:${source}:delta`;
    let previousPosition;
    for (;;) {
      const result = await call('/api/internal/ingest', {
        sources: [source], mode, checkpointId, maxItems: source === 'cisco-psirt-csaf' ? 1 : 12, refreshProjection: false,
      }, budget);
      const run = result.results[0];
      emit({ event: 'batch', source, mode, invocation: budget.used, status: run.status, counts: run.counts, checkpoint: run.checkpoint });
      if (!['success', 'unchanged', 'partial'].includes(run.status)) throw new Error(`Unexpected source status: ${run.status}`);
      if (run.checkpoint?.status === 'complete') return;
      // Older API responses may have no checkpoint. Both success and unchanged can be terminal.
      if (!run.checkpoint && ['success', 'unchanged'].includes(run.status) && !run.boundHit && !run.continuation) return;
      if (!run.checkpoint) throw new Error('Incomplete response has no resumable checkpoint');
      const position = JSON.stringify([run.checkpoint.windowStart, run.checkpoint.windowEnd, run.checkpoint.continuation]);
      if (position === previousPosition) throw new Error('Checkpoint did not advance; stopping repeated requests');
      previousPosition = position;
    }
  }

  const summary = { invocationId, status: 'complete', sources: [], enrichments: [], projection: 'pending' };
  emit({ event: 'start', invocationId, maxInvocations });
  for (const source of vendors) {
    const budget = { used: 0, limit: maxInvocations };
    const outcome = { source, backfill: 'pending', delta: 'pending', invocations: 0 };
    try {
      await runVendorPhase(source, 'backfill', budget);
      outcome.backfill = 'complete';
      // A previously completed backfill is not evidence that today's source run works.
      await runVendorPhase(source, 'delta', budget);
      outcome.delta = 'complete';
    } catch (error) {
      outcome.error = safeError(error);
      summary.status = 'pending';
    }
    outcome.invocations = budget.used;
    summary.sources.push(outcome);
    emit({ event: 'source', ...outcome });
  }

  // A new snapshot key on every bootstrap includes CVEs added after an earlier same-day EPSS run.
  // Retries within this invocation retain that key so a lost/failed response cannot duplicate a run.
  for (const source of enrichments) {
    const outcome = { source, status: 'pending' };
    try {
      const result = await call('/api/internal/ingest', {
        sources: [source], mode: 'delta', idempotencyKey: `bootstrap:${invocationId}:${source}:snapshot`, refreshProjection: false,
      }, { used: 0, limit: 3 });
      if (!['success', 'unchanged'].includes(result.results?.[0]?.status) || result.results[0].boundHit) throw new Error('Enrichment snapshot is incomplete');
      outcome.status = 'complete';
      outcome.counts = result.results[0].counts;
    } catch (error) {
      outcome.error = safeError(error);
      summary.status = 'pending';
    }
    summary.enrichments.push(outcome);
    emit({ event: 'enrichment', ...outcome });
  }
  try {
    const projection = await call('/api/internal/projection', {}, { used: 0, limit: 3 });
    if (projection.status !== 'success' || projection.parity?.status !== 'passed') throw new Error(projection.error ?? 'Projection publication or parity verification is incomplete');
    summary.projection = 'complete';
    emit({ event: 'projection', result: projection });
  } catch (error) {
    summary.status = 'pending';
    summary.projection = 'failed';
    summary.projectionError = safeError(error);
  }
  emit({ event: 'summary', ...summary });
  return summary;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const summary = await runBootstrap();
    console.log(summary.status === 'complete'
      ? 'Backfills, current deltas, enrichments, and projection completed; verify actual coverage and cutover gates.'
      : 'Some sources require follow-up; checkpoints remain resumable and public cutover remains gated.');
    if (summary.status !== 'complete') process.exitCode = 2;
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
