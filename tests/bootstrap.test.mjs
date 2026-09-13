import assert from 'node:assert/strict';
import test from 'node:test';
import { runBootstrap } from '../scripts/bootstrap.mjs';

const microsoft = 'microsoft-msrc-csaf';
const cisco = 'cisco-psirt-csaf';
const mozilla = 'mozilla-mfsa-yaml';
const env = { INGEST_SECRET: 'bootstrap-test-secret', PRIVATE_API_BASE_URL: 'http://127.0.0.1:3002' };
const successfulRun = (source, overrides = {}) => ({ sourceId: source, status: 'success', boundHit: false, counts: { discovered: 1, inserted: 1, changed: 0, unchanged: 0, failed: 0 }, ...overrides });
const ingestionResponse = (run, status = 200, headers) => Response.json({ status: status === 207 ? 'partial' : 'success', results: [run] }, { status, headers });

function harness(handler = () => undefined, overrides = {}) {
  const requests = [], events = [], waits = [];
  const options = {
    env, invocationId: 'invocation-one', now: () => Date.parse('2026-09-11T12:00:00Z'),
    log: (event) => events.push(event), sleep: async (ms) => waits.push(ms),
    fetchImpl: async (url, init) => {
      const body = JSON.parse(init.body);
      const request = { path: url.pathname, body, headers: init.headers };
      requests.push(request);
      const response = await handler(request);
      if (response) return response;
      if (url.pathname.endsWith('/projection')) return Response.json({ status: 'success', cveCount: 10, parity: { status: 'passed' } });
      return ingestionResponse(successfulRun(body.sources[0], body.checkpointId ? { checkpoint: { status: 'complete' } } : {}));
    }, ...overrides,
  };
  return { run: () => runBootstrap(options), requests, events, waits };
}

const sourceRequests = (h, source) => h.requests.filter((request) => request.body.sources?.[0] === source);

test('bootstrap advances beyond fifty batches, preserves batch bounds, then verifies current deltas before enrichment', async () => {
  let batches = 0;
  const h = harness(({ body }) => {
    if (body.sources?.[0] === microsoft && body.mode === 'backfill') {
      batches++;
      return ingestionResponse(successfulRun(microsoft, {
        status: batches < 60 ? 'partial' : 'success', boundHit: batches < 60,
        checkpoint: { status: batches < 60 ? 'pending' : 'complete', windowStart: `window-${batches}`, continuation: `offset-${batches}` },
      }));
    }
  });
  const result = await h.run();
  assert.equal(result.status, 'complete');
  assert.equal(batches, 60);
  assert.equal(result.sources[0].invocations, 61);
  const vendorRequests = h.requests.filter(({ body }) => body.checkpointId);
  assert.ok(vendorRequests.every(({ body }) => body.maxItems === (body.sources[0] === cisco ? 1 : 12)));
  assert.ok(vendorRequests.every(({ body }) => body.refreshProjection === false && !body.idempotencyKey));
  const current = vendorRequests.filter(({ body }) => body.mode === 'delta');
  assert.equal(current.length, 4);
  assert.ok(current.every(({ body }) => body.checkpointId.startsWith('bootstrap:invocation-one:')));
  assert.ok(h.requests.indexOf(current.at(-1)) < h.requests.findIndex(({ body }) => body.sources?.[0] === 'first-epss'));
  assert.equal(h.requests.at(-1).path, '/api/internal/projection');
});

test('completed checkpoints and unchanged legacy responses stop immediately but still receive a fresh delta', async () => {
  const h = harness(({ body }) => body.sources && ingestionResponse(successfulRun(body.sources[0], {
    status: 'unchanged', counts: { inserted: 0, changed: 0, unchanged: 1, failed: 0 },
    ...(body.sources[0] === cisco ? { checkpoint: { status: 'complete' } } : {}),
  })));
  assert.equal((await h.run()).status, 'complete');
  for (const source of [microsoft, cisco, mozilla, 'palo-alto-psirt-csaf']) {
    assert.deepEqual(sourceRequests(h, source).map(({ body }) => body.mode), ['backfill', 'delta']);
  }
});

test('missing Cisco credentials and permanent HTTP failure leave follow-up status while other sources and projection continue', async () => {
  const h = harness(({ body }) => {
    if (body.sources?.[0] === cisco) return ingestionResponse({ sourceId: cisco, status: 'failed', error: 'Cisco ingestion requires CISCO_CLIENT_ID and CISCO_CLIENT_SECRET' }, 207);
    if (body.sources?.[0] === mozilla) return ingestionResponse(successfulRun(mozilla, {
      status: 'partial', counts: { failed: 1 }, errors: ['Source returned HTTP 403'], checkpoint: { status: 'failed' },
    }), 207);
  });
  const result = await h.run();
  assert.equal(result.status, 'pending');
  assert.equal(result.projection, 'complete');
  assert.ok(result.enrichments.every(({ status }) => status === 'complete'));
  assert.equal(sourceRequests(h, cisco).length, 1);
  assert.equal(sourceRequests(h, mozilla).length, 1);
  assert.deepEqual(h.waits, []);
  assert.match(result.sources.find(({ source }) => source === cisco).error, /CISCO_CLIENT_ID/);
});

test('transient HTTP failures back off, honor Retry-After, and retain the same enrichment idempotency key', async () => {
  let attempts = 0;
  const h = harness(({ body }) => {
    if (body.sources?.[0] !== 'first-epss') return;
    attempts++;
    if (attempts === 1) return new Response('Temporarily unavailable', { status: 503, headers: { 'retry-after': '7' } });
    if (attempts === 2) return ingestionResponse({ sourceId: 'first-epss', status: 'failed', error: 'Source returned HTTP 429' }, 207);
  });
  assert.equal((await h.run()).status, 'complete');
  assert.deepEqual(h.waits, [7000, 4000]);
  const requests = sourceRequests(h, 'first-epss');
  assert.equal(requests.length, 3);
  assert.equal(new Set(requests.map(({ body }) => body.idempotencyKey)).size, 1);
});

test('long Retry-After is deferred without early retries and newer bootstrap invocations refresh same-day snapshots', async () => {
  const h = harness(({ body }) => body.sources?.[0] === mozilla
    ? new Response('Rate limited', { status: 429, headers: { 'retry-after': '3600' } }) : undefined);
  const result = await h.run();
  assert.equal(result.status, 'pending');
  assert.equal(sourceRequests(h, mozilla).length, 1);
  assert.deepEqual(h.waits, []);
  assert.match(result.sources.find(({ source }) => source === mozilla).error, /2026-09-11T13:00:00.000Z/);
  const next = harness(undefined, { invocationId: 'invocation-two' });
  await next.run();
  for (const source of ['cisa-kev', 'first-epss']) {
    assert.notEqual(sourceRequests(h, source)[0].body.idempotencyKey, sourceRequests(next, source)[0].body.idempotencyKey);
  }
});

test('repeated checkpoint position stops a stuck source instead of consuming the full invocation budget', async () => {
  const h = harness(({ body }) => body.sources?.[0] === microsoft
    ? ingestionResponse(successfulRun(microsoft, { status: 'unchanged', checkpoint: { status: 'pending', windowStart: '2026-09-01', windowEnd: '2026-09-02', continuation: null } })) : undefined);
  const result = await h.run();
  assert.equal(result.status, 'pending');
  assert.equal(sourceRequests(h, microsoft).length, 2);
  assert.match(result.sources[0].error, /did not advance/);
  assert.equal(result.projection, 'complete');
});

test('per-source limit counts actual calls, stops a continuing source, and leaves other sources runnable', async () => {
  let position = 0;
  const h = harness(({ body }) => body.sources?.[0] === microsoft
    ? ingestionResponse(successfulRun(microsoft, { status: 'partial', boundHit: true, checkpoint: { status: 'pending', continuation: String(++position) } })) : undefined,
  { env: { ...env, BOOTSTRAP_MAX_INVOCATIONS: '3' } });
  const result = await h.run();
  assert.equal(result.status, 'pending');
  assert.equal(sourceRequests(h, microsoft).length, 3);
  assert.match(result.sources[0].error, /Invocation limit reached/);
  assert.equal(result.sources.find(({ source }) => source === cisco).delta, 'complete');
});

test('invalid invocation bounds fail before contacting the service', async () => {
  for (const limit of ['0', '2001', '1.5', 'not-a-number']) {
    const h = harness(undefined, { env: { ...env, BOOTSTRAP_MAX_INVOCATIONS: limit } });
    await assert.rejects(h.run(), /integer from 1 to 2000/);
    assert.equal(h.requests.length, 0);
  }
});

test('incomplete snapshot or invalid projection parity never reports bootstrap complete', async () => {
  const h = harness(({ path, body }) => {
    if (body.sources?.[0] === 'first-epss') return ingestionResponse(successfulRun('first-epss', { status: 'partial', boundHit: true }));
    if (path.endsWith('/projection')) return Response.json({ status: 'success', parity: { status: 'failed' } });
  });
  const result = await h.run();
  assert.equal(result.status, 'pending');
  assert.equal(result.projection, 'failed');
  assert.match(result.projectionError, /parity/);
  assert.equal(result.enrichments[1].status, 'pending');
});
