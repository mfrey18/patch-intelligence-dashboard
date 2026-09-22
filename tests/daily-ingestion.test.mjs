import assert from 'node:assert/strict';
import test from 'node:test';
import { runDailyIngestion, writeGithubResult } from '../scripts/daily-ingestion.mjs';

const source = 'cisco-psirt-csaf';
const started = Date.parse('2026-09-22T23:59:50.000Z');
const checkpoint = (overrides = {}) => ({
  id: 'daily:cisco-psirt-csaf:2026-09-22',
  status: 'pending',
  coverageStart: '2026-09-21T00:00:00.000Z',
  coverageEnd: '2026-09-21T23:59:59.999Z',
  windowStart: '2026-09-21T00:00:00.000Z',
  windowEnd: '2026-09-21T23:59:59.999Z',
  continuation: 'offset:4',
  ...overrides,
});
const response = (run, status = 200, headers) => Response.json({ status: status === 207 ? 'partial' : 'success', results: [{ sourceId: source, ...run }] }, { status, headers });
const successful = (overrides = {}) => ({ status: 'partial', boundHit: true, counts: { failed: 0 }, checkpoint: checkpoint(), ...overrides });

function harness(handler, { initialTime = started, maxBatches, maxDurationMs } = {}) {
  let time = initialTime;
  const requests = [];
  const waits = [];
  const log = [];
  return {
    requests,
    waits,
    log,
    run: () => runDailyIngestion({
      secret: 'daily-secret', origin: 'http://api.example.test', now: () => time,
      sleep: async (milliseconds) => { waits.push(milliseconds); time += milliseconds; },
      log: (event) => log.push(event), maxBatches, maxDurationMs,
      fetchImpl: async (_url, init) => {
        const body = JSON.parse(init.body);
        requests.push(body);
        return handler({ body, index: requests.length, now: time, signal: init.signal, advance: (milliseconds) => { time += milliseconds; } });
      },
    }),
  };
}

test('pins the initial UTC daily date across midnight and resumes the saved offset', async () => {
  const h = harness(({ index, advance }) => {
    advance(index === 1 ? 20_000 : 0);
    return response(index === 1 ? successful() : successful({ checkpoint: checkpoint({ status: 'complete', coverageEnd: '2026-09-23T00:00:00.000Z', continuation: null }) }));
  });
  const result = await h.run();
  assert.equal(result.status, 'complete');
  assert.equal(result.dailyDate, '2026-09-22');
  assert.equal(h.requests.length, 2);
  assert.ok(h.requests.every((request) => request.scheduled === true && request.maxItems === 1));
  assert.ok(h.requests.every((request) => request.checkpointId === 'daily:cisco-psirt-csaf:2026-09-22'));
});

test('preserves a progressing checkpoint when the 50-batch budget is exhausted', async () => {
  const h = harness(({ index }) => response(successful({ checkpoint: checkpoint({ continuation: `offset:${index}` }) })), { maxBatches: 50, maxDurationMs: 600_000 });
  const result = await h.run();
  assert.equal(result.status, 'pending');
  assert.equal(result.batches, 50);
  assert.equal(result.alert, false);
  assert.match(result.reason, /Batch budget/);
});

test('stops on the ten-minute budget even while work is advancing', async () => {
  const h = harness(({ advance, index }) => {
    advance(61_000);
    return response(successful({ checkpoint: checkpoint({ continuation: `offset:${index}` }) }));
  }, { maxBatches: 50, maxDurationMs: 600_000 });
  const result = await h.run();
  assert.equal(result.status, 'pending');
  assert.equal(result.batches, 10);
  assert.equal(result.alert, false);
  assert.match(result.reason, /time budget/);
});

test('waits for a short Retry-After and defers a long cooldown beyond the budget', async () => {
  let attempts = 0;
  const h = harness(() => {
    attempts++;
    if (attempts === 1) return new Response('rate limited', { status: 429, headers: { 'retry-after': '30' } });
    return response({ status: 'success', checkpoint: checkpoint({ status: 'complete', coverageEnd: '2026-09-23T00:00:00.000Z', continuation: null }) });
  }, { maxDurationMs: 60_000 });
  const result = await h.run();
  assert.equal(result.status, 'complete');
  assert.deepEqual(h.waits, [30_000]);
  assert.equal(result.hadRequestFailure, true);
  assert.equal(result.alert, true);

  const deferred = harness(() => new Response('rate limited', { status: 429, headers: { 'retry-after': '600' } }), { maxDurationMs: 60_000 });
  const pending = await deferred.run();
  assert.equal(pending.status, 'pending');
  assert.equal(deferred.requests.length, 1);
  assert.deepEqual(deferred.waits, []);
});

test('honors an HTTP-date Retry-After without retrying early', async () => {
  let attempts = 0;
  const h = harness(() => {
    attempts++;
    if (attempts === 1) return new Response('rate limited', { status: 429, headers: { 'retry-after': new Date(started + 45_000).toUTCString() } });
    return response({ status: 'success', checkpoint: checkpoint({ status: 'complete', coverageEnd: '2026-09-23T00:00:00.000Z', continuation: null }) });
  }, { maxDurationMs: 60_000 });
  const result = await h.run();
  assert.equal(result.status, 'complete');
  assert.deepEqual(h.waits, [45_000]);
});

test('does not sleep after a cooldown returned by the final allowed batch', async () => {
  const h = harness(() => new Response('rate limited', { status: 429, headers: { 'retry-after': '30' } }), { maxBatches: 1, maxDurationMs: 60_000 });
  const result = await h.run();
  assert.equal(result.status, 'pending');
  assert.equal(result.batches, 1);
  assert.deepEqual(h.waits, []);
  assert.match(result.reason, /final allowed batch/);
});

test('reports API-style pending contention without treating it as an error', async () => {
  const h = harness(() => response({ status: 'pending', reason: 'Source ingestion is already running' }, 202));
  const result = await h.run();
  assert.equal(result.status, 'pending');
  assert.equal(result.concurrent, true);
  assert.equal(result.alert, false);
});

test('continues draining an old backlog while retaining an age alert', async () => {
  const h = harness(({ index }) => response({
    status: 'partial',
    checkpoint: index === 1
      ? checkpoint({ coverageEnd: '2026-09-20T23:59:59.999Z', continuation: 'offset:5' })
      : checkpoint({ status: 'complete', coverageStart: '2026-09-22T00:00:00.000Z', coverageEnd: '2026-09-22T23:59:59.999Z', windowStart: '2026-09-22T00:00:00.000Z', windowEnd: '2026-09-22T23:59:59.999Z', continuation: null }),
  }));
  const result = await h.run();
  assert.equal(result.status, 'complete');
  assert.equal(result.backlogTooOld, true);
  assert.equal(result.alert, true);
  assert.equal(h.requests.length, 2);
});

test('alerts on a repeated checkpoint position instead of looping', async () => {
  const h = harness(() => response(successful()));
  const result = await h.run();
  assert.equal(result.status, 'failed');
  assert.equal(result.stalled, true);
  assert.equal(result.alert, true);
  assert.equal(h.requests.length, 2);
});

test('alerts on an actual non-retryable request failure', async () => {
  const h = harness(() => response({ status: 'failed', error: 'Source returned HTTP 403', checkpoint: checkpoint({ status: 'failed' }) }, 207));
  const result = await h.run();
  assert.equal(result.status, 'failed');
  assert.equal(result.alert, true);
  assert.match(result.error, /403/);
});

test('continues after an old checkpoint completes and requires a fresh window', async () => {
  const h = harness(({ index }) => response({
    status: 'success',
    checkpoint: index === 1
      ? checkpoint({ status: 'complete', continuation: null })
      : checkpoint({ status: 'complete', coverageStart: '2026-09-22T00:00:00.000Z', coverageEnd: '2026-09-22T23:59:59.999Z', windowStart: '2026-09-22T00:00:00.000Z', windowEnd: '2026-09-22T23:59:59.999Z', continuation: null }),
  }));
  const result = await h.run();
  assert.equal(result.status, 'complete');
  assert.equal(h.requests.length, 2);
  assert.equal(result.coverageEnd, '2026-09-22T23:59:59.999Z');
});

test('writes an explicit non-complete GitHub output and summary for pending work', async () => {
  const writes = [];
  const summary = { status: 'pending', dailyDate: '2026-09-22', checkpointId: 'daily:cisco-psirt-csaf:2026-09-22', batches: 50, maxBatches: 50, elapsedMs: 600_000, maxDurationMs: 600_000, alert: false, reason: 'Batch budget exhausted.' };
  await writeGithubResult(summary, { outputPath: 'outputs', summaryPath: 'summary', append: async (path, value) => writes.push({ path, value }) });
  const output = writes.find(({ path }) => path === 'outputs').value;
  assert.match(output, /daily_status=pending/);
  assert.match(output, /daily_complete=false/);
  assert.match(output, /daily_pending=true/);
  assert.match(writes.find(({ path }) => path === 'summary').value, /did not complete a daily cycle/);
});

test('aborted upstream calls become pending at the client deadline and do not alert as request failures', async () => {
  const h = harness(({ signal }) => new Promise((_, reject) => {
    // The runner's AbortController is the only thing that can finish this request.
    signal.addEventListener('abort', () => reject(new DOMException('The operation was aborted', 'AbortError')), { once: true });
  }), { maxDurationMs: 20 });
  const result = await h.run();
  assert.equal(result.status, 'pending');
  assert.equal(result.hadRequestFailure, false);
  assert.equal(result.alert, false);
});
