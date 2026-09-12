import { test } from 'node:test';
import assert from 'node:assert/strict';
import { gzipSync } from 'node:zlib';
import { setTimeout as delay } from 'node:timers/promises';
import { testDatabase } from './database.mjs';
import { seedIngestionCatalog } from '../../lib/ingestion/postgres-repository.ts';
import { ingestEpssBulk } from '../../lib/ingestion/enrichments/epss.ts';

const A = 'CVE-2026-1001';
const B = 'CVE-2026-1002';
const C = 'CVE-2026-1003';
const today = new Date().toISOString().slice(0, 10);
const yesterday = new Date(Date.now() - 86_400_000).toISOString().slice(0, 10);
const options = { url: 'https://test.invalid/epss', minimumRows: 1 };

function dataset(date = today) {
  return gzipSync(`#model_version:v1,score_date:${date}\ncve,epss,percentile\n${A},0.5,0.95\n${B},0.9,0.99\n${C},0.3,0.8\n`);
}

async function track(db, ids) {
  for (const id of ids) {
    await db.prepare('INSERT INTO cves (id,created_at,updated_at) VALUES (?,now(),now()) ON CONFLICT(id) DO NOTHING').bind(id).run();
    await db.prepare(`INSERT INTO kev_entries (cve_id,active,date_added,entry_hash,source_url,first_observed_at,last_observed_at)
      VALUES (?,TRUE,CURRENT_DATE,?,'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',now(),now())
      ON CONFLICT(cve_id) DO UPDATE SET active=TRUE`).bind(id, id).run();
  }
}

async function snapshot(db) {
  return {
    datasets: (await db.prepare('SELECT * FROM epss_datasets ORDER BY score_date').all()).results,
    observations: (await db.prepare('SELECT * FROM epss_observations ORDER BY score_date,cve_id').all()).results,
  };
}

async function assertCurrent(db, ids) {
  const rows = (await db.prepare('SELECT cve_id FROM epss_observations WHERE score_date=? ORDER BY cve_id').bind(today).all()).results;
  assert.deepEqual(rows.map(row => row.cve_id), ids);
  const current = (await db.prepare('SELECT score_date,matched_cve_count,status FROM epss_datasets WHERE is_current=TRUE').all()).results;
  assert.deepEqual(current, [{ score_date: today, matched_cve_count: ids.length, status: 'published' }]);
}

test('An unchanged EPSS file enriches newly tracked CVEs without inventing history; exact repeats preserve publication', async () => {
  const db = await testDatabase();
  const originalFetch = globalThis.fetch;
  let fetches = 0;
  let payload = dataset(yesterday);
  globalThis.fetch = async () => { fetches += 1; return new Response(payload); };
  try {
    await seedIngestionCatalog(db);
    await track(db, [A]);
    assert.equal((await ingestEpssBulk(db, 'membership-history', options)).status, 'success');
    const historical = (await snapshot(db)).observations;
    payload = dataset();
    assert.equal((await ingestEpssBulk(db, 'membership-initial', options)).status, 'success');
    await assertCurrent(db, [A]);
    await track(db, [B]);

    // Completed idempotency keys remain replays even when the tracked universe grows.
    const beforeReplayFetches = fetches;
    const replay = await ingestEpssBulk(db, 'membership-initial', options);
    assert.equal(replay.status, 'unchanged');
    assert.equal(replay.processed, 0);
    assert.equal(fetches, beforeReplayFetches);
    await assertCurrent(db, [A]);

    const repair = await ingestEpssBulk(db, 'membership-growth', options);
    assert.equal(repair.status, 'success');
    assert.equal(repair.counts.inserted, 2);
    await assertCurrent(db, [A, B]);
    const repaired = await snapshot(db);
    assert.deepEqual(repaired.observations.filter(row => row.score_date === yesterday), historical);
    assert.equal(repaired.observations.some(row => row.cve_id === C), false);

    const repeated = await ingestEpssBulk(db, 'membership-exact-repeat', options);
    assert.equal(repeated.status, 'unchanged');
    assert.equal(repeated.counts.unchanged, 2);
    assert.deepEqual(await snapshot(db), repaired, 'Exact repeats must preserve observation timestamps and publication provenance');
    await track(db, ['CVE-2026-1999']);
    assert.equal((await ingestEpssBulk(db, 'membership-absent-from-feed', options)).status, 'unchanged');
    assert.deepEqual(await snapshot(db), repaired, 'Tracked CVEs absent from the feed must not force republishing');
  } finally {
    globalThis.fetch = originalFetch;
    await db.close();
  }
});

test('An unchanged EPSS file republishes same-count membership swaps and shrinking scope', async () => {
  const db = await testDatabase();
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response(dataset());
  try {
    await seedIngestionCatalog(db);
    await track(db, [A, B]);
    assert.equal((await ingestEpssBulk(db, 'swap-initial', options)).status, 'success');
    const hash = (await db.prepare('SELECT source_hash FROM epss_datasets WHERE is_current=TRUE').first()).source_hash;
    await db.prepare('UPDATE kev_entries SET active=FALSE WHERE cve_id=?').bind(A).run();
    await track(db, [C]);
    assert.equal((await ingestEpssBulk(db, 'swap-repair', options)).status, 'success');
    await assertCurrent(db, [B, C]);
    await db.prepare('UPDATE kev_entries SET active=FALSE WHERE cve_id=?').bind(B).run();
    assert.equal((await ingestEpssBulk(db, 'shrink-repair', options)).status, 'success');
    await assertCurrent(db, [C]);
    assert.equal((await db.prepare('SELECT source_hash FROM epss_datasets WHERE is_current=TRUE').first()).source_hash, hash);
    await db.prepare('UPDATE kev_entries SET active=FALSE WHERE cve_id=?').bind(C).run();
    assert.equal((await ingestEpssBulk(db, 'empty-scope-repair', options)).status, 'success');
    await assertCurrent(db, []);
    assert.equal((await ingestEpssBulk(db, 'empty-scope-repeat', options)).status, 'unchanged');
  } finally {
    globalThis.fetch = originalFetch;
    await db.close();
  }
});

test('Same-hash EPSS growth rolls back rows and publication metadata together when an insert fails', async () => {
  const db = await testDatabase();
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response(dataset());
  try {
    await seedIngestionCatalog(db);
    await track(db, [A]);
    assert.equal((await ingestEpssBulk(db, 'rollback-initial', options)).status, 'success');
    const before = await snapshot(db);
    await track(db, [B]);
    await db.prepare('ALTER TABLE epss_observations ADD CONSTRAINT membership_reject_score CHECK (score<0.8)').run();
    const failed = await ingestEpssBulk(db, 'rollback-growth', options);
    assert.equal(failed.status, 'failed');
    assert.match(failed.errors.join(' '), /membership_reject_score/);
    assert.deepEqual(await snapshot(db), before);
    await assertCurrent(db, [A]);
    const audit = await db.prepare('SELECT status,records_failed FROM source_runs WHERE id=?').bind(failed.runId).first();
    assert.deepEqual(audit, { status: 'failed', records_failed: 1 });
    await db.prepare('ALTER TABLE epss_observations DROP CONSTRAINT membership_reject_score').run();
    assert.equal((await ingestEpssBulk(db, 'rollback-growth-retry', options)).status, 'success');
    await assertCurrent(db, [A, B]);
  } finally {
    globalThis.fetch = originalFetch;
    await db.close();
  }
});

test('An unchanged EPSS file repairs stored score/model and matched-count inconsistencies', async () => {
  const db = await testDatabase();
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response(dataset());
  try {
    await seedIngestionCatalog(db);
    await track(db, [A]);
    assert.equal((await ingestEpssBulk(db, 'inconsistency-initial', options)).status, 'success');
    await db.prepare('UPDATE epss_observations SET score=0.1,percentile=0.2,model_version=NULL').run();
    assert.equal((await ingestEpssBulk(db, 'inconsistency-values', options)).status, 'success');
    assert.deepEqual(await db.prepare('SELECT score,percentile,model_version FROM epss_observations').first(), { score: 0.5, percentile: 0.95, model_version: 'v1' });
    await db.prepare('UPDATE epss_datasets SET matched_cve_count=0').run();
    assert.equal((await ingestEpssBulk(db, 'inconsistency-count', options)).status, 'success');
    await assertCurrent(db, [A]);
    const repaired = await snapshot(db);
    assert.equal((await ingestEpssBulk(db, 'inconsistency-repeat', options)).status, 'unchanged');
    assert.deepEqual(await snapshot(db), repaired);
  } finally {
    globalThis.fetch = originalFetch;
    await db.close();
  }
});

test('A waiting EPSS publisher reads tracked membership after acquiring the publication lock', {
  skip: !process.env.TEST_DATABASE_URL && 'Requires real PostgreSQL advisory-lock wait state',
}, async () => {
  const db = await testDatabase();
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response(dataset());
  let releaseLock;
  let holding;
  let waiting;
  try {
    await seedIngestionCatalog(db);
    await track(db, [A]);
    assert.equal((await ingestEpssBulk(db, 'waiting-initial', options)).status, 'success');
    let acquired;
    const locked = new Promise(resolve => { acquired = resolve; });
    const release = new Promise(resolve => { releaseLock = resolve; });
    holding = db.transaction(async tx => {
      await tx.prepare("SELECT pg_advisory_xact_lock(hashtextextended('epss:publication',0))").run();
      acquired();
      await release;
    });
    await Promise.race([locked, holding.then(() => { throw new Error('Publication lock was not held'); })]);
    waiting = ingestEpssBulk(db, 'waiting-repair', options);

    // Observe a real lock wait rather than assuming the publisher reached it
    // after a fixed sleep. The timeout only bounds a failing regression.
    const deadline = Date.now() + 5_000;
    let blocked = false;
    while (Date.now() < deadline) {
      const state = await db.prepare(`SELECT EXISTS(SELECT 1 FROM pg_stat_activity
        WHERE datname=current_database() AND wait_event='advisory'
          AND query LIKE '%epss:publication%') waiting`).first();
      if (state.waiting) { blocked = true; break; }
      await delay(10);
    }
    assert.equal(blocked, true, 'The competing publisher must wait on the publication lock');
    await track(db, [B]);
    releaseLock();
    await holding;
    assert.equal((await waiting).status, 'success');
    await assertCurrent(db, [A, B]);
  } finally {
    releaseLock?.();
    await Promise.allSettled([holding, waiting].filter(Boolean));
    globalThis.fetch = originalFetch;
    await db.close();
  }
});
