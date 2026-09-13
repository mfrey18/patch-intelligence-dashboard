import assert from 'node:assert/strict';
import test from 'node:test';
import { createCiscoAdapter } from '../lib/ingestion/adapters/cisco.ts';
import { createCiscoRequestPolicy } from '../lib/ingestion/cisco-rate-limit.ts';
import { fetchWithPolicy, SourceHttpError } from '../lib/ingestion/safety.ts';

const sourcePolicy = { timeoutMs: 20000, maxResponseBytes: 8_000_000, retries: 2, retryBaseMs: 350 };
const credentials = { clientId: 'test-client', clientSecret: 'test-secret' };
const context = { fetch, since: '2026-09-01T00:00:00Z', until: '2026-09-01T23:59:59Z', policy: sourcePolicy };

function fixture(handler = () => Response.json({ advisories: [] })) {
  let time = Date.parse('2026-09-11T12:00:00Z');
  const apiRequests = [], waits = [];
  const runtime = {
    now: () => time,
    sleep: async (milliseconds) => { waits.push(milliseconds); time += milliseconds; },
    fetch: async (url) => {
      if (url.startsWith('https://id.cisco.com/')) return Response.json({ access_token: 'fake-token', expires_in: 3600 });
      assert.ok(url.startsWith('https://apix.cisco.com/security/advisories/v2/'));
      apiRequests.push({ at: time, url });
      return handler(apiRequests.length, time);
    },
  };
  const shared = createCiscoRequestPolicy(runtime);
  return { runtime, shared, apiRequests, waits, now: () => time, setTime: (value) => { time = value; }, adapter: () => createCiscoAdapter(credentials, shared) };
}

test('Cisco shares request spacing across recreated adapters and every discovery page', async () => {
  const f = fixture((attempt) => Response.json({ advisories: attempt === 1 ? Array.from({ length: 100 }, () => ({})) : [] }));
  const first = f.adapter(), second = f.adapter();
  await Promise.all([first.discover(context), second.discover(context)]);
  assert.equal(f.apiRequests.length, 3);
  assert.deepEqual(f.apiRequests.slice(1).map((request, index) => request.at - f.apiRequests[index].at), [2200, 2200]);
  assert.deepEqual(f.apiRequests.map(({ url }) => new URL(url).searchParams.get('pageIndex')).sort(), ['1', '1', '2']);
});

test('Cisco actual retry requests obey pacing rather than only pacing each batch', async () => {
  const f = fixture((attempt) => attempt === 1 ? new Response(null, { status: 503 }) : Response.json({ advisories: [] }));
  await f.adapter().discover(context);
  await f.adapter().discover(context);
  const started = f.apiRequests[0].at;
  assert.deepEqual(f.apiRequests.map(({ at }) => at - started), [0, 2200, 4400]);
  assert.deepEqual(f.waits, [350, 1850, 2200]);
});

test('Cisco waits for numeric Retry-After before retrying and keeps the next request spaced', async () => {
  const f = fixture((attempt) => attempt === 1 ? new Response(null, { status: 429, headers: { 'retry-after': '12' } }) : Response.json({ advisories: [] }));
  const started = f.now();
  await f.adapter().discover(context);
  await f.adapter().discover(context);
  assert.deepEqual(f.apiRequests.map(({ at }) => at - started), [0, 12000, 14200]);
});

test('Cisco HTTP-date cooldown survives failed batches and newly created adapters without early requests', async () => {
  let deadline;
  const f = fixture((attempt, now) => {
    deadline ??= now + 45000;
    return attempt === 1 ? new Response(null, { status: 429, headers: { 'retry-after': new Date(deadline).toUTCString() } }) : Response.json({ advisories: [] });
  });
  await assert.rejects(f.adapter().discover(context), (error) => error instanceof SourceHttpError && error.retryAt === deadline);
  f.setTime(f.now() + 10000);
  await assert.rejects(f.adapter().discover(context), (error) => error instanceof SourceHttpError && error.retryAt === deadline);
  assert.equal(f.apiRequests.length, 1);
  assert.deepEqual(f.waits, []);
  f.setTime(deadline);
  await f.adapter().discover(context);
  assert.equal(f.apiRequests[1].at, deadline);
});

test('Cisco unknown 429 cooldown stops resumably rather than probing a potentially exhausted quota', async () => {
  const f = fixture(() => new Response(null, { status: 429 }));
  const started = f.now();
  await assert.rejects(f.adapter().discover(context), (error) => error.retryAt === started + 60000);
  await assert.rejects(f.adapter().discover(context), (error) => error.retryAt === started + 60000);
  assert.equal(f.apiRequests.length, 1);
  assert.deepEqual(f.waits, []);
});

test('Cisco native process refuses a 5001st call inside a rolling day', async () => {
  const f = fixture();
  const started = f.now();
  let calls = 0;
  const request = async () => { calls++; return new Response(null, { status: 204 }); };
  for (let index = 0; index < 5000; index++) await f.shared.schedule(request);
  await assert.rejects(f.shared.schedule(request), (error) => error instanceof SourceHttpError && error.retryAt === started + 86400000);
  assert.equal(calls, 5000);
  f.setTime(started + 86400000);
  await f.shared.schedule(request);
  assert.equal(calls, 5001);
});

test('general fetch policy honors Retry-After dates and refuses to clamp long numeric cooldowns', async () => {
  for (const delay of [10000, 3600000]) {
    let now = Date.parse('2026-09-11T12:00:00Z');
    const started = now, calls = [], waits = [];
    const runtime = {
      now: () => now, sleep: async (ms) => { waits.push(ms); now += ms; },
      fetch: async () => {
        calls.push(now);
        return calls.length === 1 ? new Response(null, { status: 429, headers: { 'retry-after': delay === 10000 ? new Date(now + delay).toUTCString() : String(delay / 1000) } }) : Response.json({ ok: true });
      },
    };
    const pending = fetchWithPolicy('https://example.test/source', sourcePolicy, undefined, [], runtime);
    if (delay <= 30000) {
      await pending;
      assert.deepEqual(calls, [started, started + delay]);
      assert.deepEqual(waits, [delay]);
    } else {
      await assert.rejects(pending, (error) => error.retryAt === started + delay && error.message.includes(new Date(started + delay).toISOString()));
      assert.equal(calls.length, 1);
      assert.deepEqual(waits, []);
    }
  }
});
