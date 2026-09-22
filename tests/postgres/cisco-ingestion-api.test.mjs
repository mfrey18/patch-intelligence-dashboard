import test from 'node:test';
import assert from 'node:assert/strict';
import { testDatabase } from './database.mjs';
import { handleApi, acquireLease, releaseLease } from '../../server/api.ts';
import { ResponseCache } from '../../server/cache.ts';
import { PostgresIngestionRepository, seedIngestionCatalog } from '../../lib/ingestion/postgres-repository.ts';
import { checkpointBatchKey } from '../../lib/ingestion/orchestration.ts';
import { pruneRollingRetention } from '../../lib/operations/postgres-health.ts';

const sourceId = 'cisco-psirt-csaf';
const secret = 'integration-test-secret';

async function setup(db, offset = 4) {
  await seedIngestionCatalog(db);
  const yesterday = new Date(Date.now() - 86_400_000);
  const end = yesterday.toISOString();
  const start = new Date(yesterday.getTime() - 3 * 86_400_000).toISOString();
  const id = `daily:${sourceId}:${end.slice(0, 10)}`;
  await db.prepare(`INSERT INTO ingestion_checkpoints
    (id,source_id,mode,coverage_start,coverage_end,window_start,window_end,continuation_token,status,created_at,updated_at)
    VALUES (?,?,'delta',?,?,?,?,?,'pending',?,?)`).bind(id, sourceId, start, end, start, end, `offset:${offset}`, end, end).run();
  const refs = Array.from({ length: 7 }, (_, index) => ({ id: `cisco-test-${index}`, url: `https://sec.cloudapps.cisco.com/test-${index}.json` }));
  const discoveryId = `${sourceId}:${id}:${start}:${end}:start`;
  await db.prepare('INSERT INTO discovery_pages(id,source_id,refs) VALUES (?,?,?::jsonb)').bind(discoveryId, sourceId, JSON.stringify(refs)).run();
  return { id, sourceId, mode: 'delta', coverageStart: start, coverageEnd: end, windowStart: start, windowEnd: end, continuation: `offset:${offset}`, status: 'pending', refs };
}

function env(db) {
  return { DB: db, cache: new ResponseCache(), INGEST_SECRET: secret, CISCO_CLIENT_ID: 'test', CISCO_CLIENT_SECRET: 'test' };
}

async function invoke(environment, overrides = {}) {
  const response = await handleApi(new Request('https://local/api/internal/ingest', {
    method: 'POST', headers: { authorization: `Bearer ${secret}`, 'content-type': 'application/json' },
    body: JSON.stringify({ sources: [sourceId], mode: 'delta', scheduled: true,
      checkpointId: `daily:${sourceId}:${new Date().toISOString().slice(0, 10)}`, maxItems: 12, refreshProjection: false, ...overrides }),
  }), environment, 'private');
  return { status: response.status, body: await response.json() };
}

function documentResponse(url) {
  const response = Response.json({ document: { title: 'Cisco fixture', tracking: { id: new URL(url).pathname } } });
  Object.defineProperty(response, 'url', { value: url });
  return response;
}

test('scheduled Cisco API resumes the saved discovery at offset four and processes exactly three remaining advisories', async () => {
  const db = await testDatabase();
  const originalFetch = globalThis.fetch;
  const fetched = [];
  try {
    const checkpoint = await setup(db);
    globalThis.fetch = async (url) => {
      assert.ok(checkpoint.refs.some(ref => ref.url === url), 'resumption must not rediscover under today\'s identity');
      fetched.push(url);
      return documentResponse(url);
    };
    const environment = env(db);
    for (const offset of [5, 6, 7]) {
      const response = await invoke(environment);
      assert.equal(response.status, offset < 7 ? 202 : 200, JSON.stringify(response.body));
      assert.equal(response.body.status, offset < 7 ? 'pending' : 'success');
      const result = response.body.results[0];
      assert.equal(result.checkpoint.id, checkpoint.id);
      assert.equal(result.processed, 1, 'scheduled Cisco enforces one advisory even if caller requests twelve');
      assert.equal(result.checkpoint.windowStart, checkpoint.windowStart);
      assert.equal(result.checkpoint.windowEnd, checkpoint.windowEnd);
      assert.equal(result.checkpoint.continuation, offset < 7 ? `offset:${offset}` : null);
    }
    assert.deepEqual(fetched, checkpoint.refs.slice(4).map(ref => ref.url));
    assert.equal((await db.prepare('SELECT COUNT(*) count FROM ingestion_checkpoints').first()).count, 1);
    // Completion is followed by a genuinely new discovery, including revisions
    // inside the overlap, rather than a completed checkpoint being returned forever.
    const discovered = [];
    globalThis.fetch = async (url) => {
      if (url.startsWith('https://id.cisco.com/')) return Response.json({ access_token: 'test', expires_in: 3600 });
      assert.ok(url.startsWith('https://apix.cisco.com/'));
      discovered.push(url);
      return Response.json({ advisories: [] });
    };
    let fresh = await invoke(environment);
    assert.equal(fresh.status, 202, JSON.stringify(fresh.body));
    assert.notEqual(fresh.body.results[0].checkpoint.id, checkpoint.id);
    assert.ok(Date.parse(fresh.body.results[0].checkpoint.coverageEnd) > Date.parse(checkpoint.coverageEnd));
    assert.equal(fresh.body.results[0].checkpoint.coverageStart, new Date(Date.parse(checkpoint.coverageEnd) - 3 * 86_400_000).toISOString());
    const freshId = fresh.body.results[0].checkpoint.id;
    fresh = await invoke(environment);
    assert.equal(fresh.status, 200, JSON.stringify(fresh.body));
    assert.equal(fresh.body.results[0].checkpoint.id, freshId);
    assert.equal(fresh.body.results[0].checkpoint.status, 'complete');
    assert.ok(discovered.length > 0);
  } finally { globalThis.fetch = originalFetch; await db.close(); }
});

test('interruption after committing a batch recovers its saved output without refetching', async () => {
  const db = await testDatabase();
  const originalFetch = globalThis.fetch;
  try {
    const checkpoint = await setup(db);
    const repo = new PostgresIngestionRepository(db);
    const { runId } = await repo.beginRun(sourceId, checkpointBatchKey(checkpoint), {
      mode: 'delta', windowStart: checkpoint.windowStart, windowEnd: checkpoint.windowEnd,
      continuationIn: checkpoint.continuation, checkpointId: checkpoint.id, maxItems: 1,
    });
    await repo.finishRun(runId, { status: 'partial', mode: 'delta', window: { since: checkpoint.windowStart, until: checkpoint.windowEnd },
      processed: 1, continuation: 'offset:5', boundHit: true, counts: { discovered: 7, inserted: 1, changed: 0, unchanged: 0, failed: 0 }, errors: [] });
    globalThis.fetch = async () => { throw Error('a committed batch must be reused'); };
    const response = await invoke(env(db));
    assert.equal(response.status, 202, JSON.stringify(response.body));
    assert.equal(response.body.results[0].runId, runId);
    assert.equal(response.body.results[0].checkpoint.continuation, 'offset:5');
    assert.equal((await db.prepare('SELECT COUNT(*) count FROM source_runs').first()).count, 1);
  } finally { globalThis.fetch = originalFetch; await db.close(); }
});

test('a rate-limit failure preserves the offset, persists cooldown, and blocks early retries', async () => {
  const db = await testDatabase();
  const originalFetch = globalThis.fetch;
  let requests = 0;
  try {
    const checkpoint = await setup(db);
    globalThis.fetch = async () => { requests++; return new Response(null, { status: 429, headers: { 'retry-after': '3600' } }); };
    const environment = env(db);
    const failed = await invoke(environment);
    assert.equal(failed.status, 207, JSON.stringify(failed.body));
    assert.equal(failed.body.results[0].checkpoint.status, 'failed');
    assert.equal(failed.body.results[0].checkpoint.continuation, checkpoint.continuation);
    assert.ok(Date.parse(failed.body.results[0].retryAfter) > Date.now(), 'the runner must see the persisted upstream cooldown on the failing batch');
    assert.equal(requests, 1);
    const paused = await invoke(environment);
    assert.equal(paused.status, 202, JSON.stringify(paused.body));
    assert.equal(paused.body.status, 'pending');
    assert.ok(Date.parse(paused.body.results[0].retryAfter) > Date.now());
    assert.equal(requests, 1);
    const saved = await db.prepare('SELECT continuation_token FROM ingestion_checkpoints WHERE id=?').bind(checkpoint.id).first();
    assert.equal(saved.continuation_token, checkpoint.continuation);
  } finally { globalThis.fetch = originalFetch; await db.close(); }
});

test('source lease contention reports pending and cannot create or advance checkpoints', async () => {
  const db = await testDatabase();
  try {
    const checkpoint = await setup(db);
    assert.equal(await acquireLease(db, sourceId, 'other-run'), true);
    const response = await invoke(env(db));
    assert.equal(response.status, 202, JSON.stringify(response.body));
    assert.equal(response.body.status, 'pending');
    assert.equal((await db.prepare('SELECT COUNT(*) count FROM ingestion_checkpoints').first()).count, 1);
    const saved = await db.prepare('SELECT continuation_token FROM ingestion_checkpoints WHERE id=?').bind(checkpoint.id).first();
    assert.equal(saved.continuation_token, 'offset:4');
    await releaseLease(db, sourceId, 'other-run');
  } finally { await db.close(); }
});

test('concurrent scheduled requests cannot process the same Cisco advisory twice', async () => {
  const db = await testDatabase();
  const originalFetch = globalThis.fetch;
  let unblock;
  let entered;
  const blocked = new Promise(resolve => { unblock = resolve; });
  const started = new Promise(resolve => { entered = resolve; });
  let first;
  let requests = 0;
  try {
    const checkpoint = await setup(db);
    globalThis.fetch = async (url) => { requests++; entered(); await blocked; return documentResponse(url); };
    const environment = env(db);
    first = invoke(environment);
    await started;
    const second = await invoke(environment);
    assert.equal(second.status, 202, JSON.stringify(second.body));
    assert.match(second.body.results[0].reason, /already running/);
    assert.equal(requests, 1);
    assert.equal((await db.prepare('SELECT continuation_token FROM ingestion_checkpoints WHERE id=?').bind(checkpoint.id).first()).continuation_token, 'offset:4');
    unblock();
    const completed = await first;
    assert.equal(completed.status, 202, JSON.stringify(completed.body));
    assert.equal(completed.body.results[0].checkpoint.continuation, 'offset:5');
    assert.equal((await db.prepare('SELECT COUNT(*) count FROM source_runs').first()).count, 1);
  } finally { unblock(); await first; globalThis.fetch = originalFetch; await db.close(); }
});

test('retention preserves the latest completed Cisco coverage boundary across a prolonged outage', async () => {
  const db = await testDatabase();
  try {
    const checkpoint = await setup(db);
    await db.prepare(`UPDATE ingestion_checkpoints SET status='complete', continuation_token=NULL,
      coverage_start=now()-INTERVAL '48 days', window_start=now()-INTERVAL '48 days',
      coverage_end=now()-INTERVAL '45 days', window_end=now()-INTERVAL '45 days',
      completed_at=now()-INTERVAL '45 days', created_at=now()-INTERVAL '45 days' WHERE id=?`).bind(checkpoint.id).run();
    for (const id of ['daily:cisco:older', 'manual:cisco:old']) {
      await db.prepare(`INSERT INTO ingestion_checkpoints(id,source_id,mode,coverage_start,coverage_end,window_start,window_end,status,created_at,updated_at,completed_at)
        VALUES (?,?,'delta',now()-INTERVAL '49 days',now()-INTERVAL '46 days',now()-INTERVAL '49 days',now()-INTERVAL '46 days','complete',now()-INTERVAL '46 days',now()-INTERVAL '46 days',now()-INTERVAL '46 days')`).bind(id, sourceId).run();
      // The canonical range is unique; give the next fixture its own range.
      await db.prepare("UPDATE ingestion_checkpoints SET coverage_start=coverage_start-INTERVAL '1 hour' WHERE id=?").bind(id).run();
    }
    const result = await pruneRollingRetention(db);
    assert.equal(result.completedCheckpoints, 2);
    assert.deepEqual((await db.prepare('SELECT id FROM ingestion_checkpoints').all()).results, [{ id: checkpoint.id }]);
  } finally { await db.close(); }
});

test('manual and bootstrap-style clients retain partial and skipped batch statuses', async () => {
  const db = await testDatabase();
  const originalFetch = globalThis.fetch;
  try {
    const checkpoint = await setup(db);
    const manualId = 'bootstrap:test:cisco:delta';
    await db.prepare('UPDATE ingestion_checkpoints SET id=? WHERE id=?').bind(manualId, checkpoint.id).run();
    await db.prepare('UPDATE discovery_pages SET id=replace(id,?,?)').bind(checkpoint.id, manualId).run();
    globalThis.fetch = async (url) => documentResponse(url);
    const environment = env(db);
    const request = { scheduled: false, checkpointId: manualId, maxItems: 1 };
    const partial = await invoke(environment, request);
    assert.equal(partial.body.results[0].status, 'partial', JSON.stringify(partial.body));
    assert.equal(partial.body.results[0].checkpoint.continuation, 'offset:5');
    await db.prepare("UPDATE sources SET retry_after=now()+INTERVAL '1 hour' WHERE id=?").bind(sourceId).run();
    const deferred = await invoke(environment, request);
    assert.equal(deferred.body.results[0].status, 'skipped', JSON.stringify(deferred.body));
    await db.prepare("UPDATE sources SET retry_after=NULL,readiness='paused' WHERE id=?").bind(sourceId).run();
    const paused = await invoke(environment, request);
    assert.equal(paused.body.results[0].status, 'skipped', JSON.stringify(paused.body));
    assert.equal(await acquireLease(db, sourceId, 'manual-owner'), true);
    const contended = await invoke(environment, request);
    assert.equal(contended.body.results[0].status, 'skipped', JSON.stringify(contended.body));
    await releaseLease(db, sourceId, 'manual-owner');
  } finally { globalThis.fetch = originalFetch; await db.close(); }
});
