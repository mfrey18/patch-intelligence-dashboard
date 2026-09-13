import {test} from 'node:test';
import assert from 'node:assert/strict';
import {handleApi,acquireLease,releaseLease} from '../../server/api.ts';
import {ResponseCache} from '../../server/cache.ts';
import {testDatabase} from './database.mjs';
import {seedIngestionCatalog,PostgresIngestionRepository} from '../../lib/ingestion/postgres-repository.ts';
import {connectDatabase} from '../../db/index.ts';
import {bindParameters} from '../../db/database.ts';

test('Public API excludes internal handlers, handles CORS, and fails closed',async()=>{
 const db=await testDatabase();const cache=new ResponseCache();
 const env={DB:db,cache,INGEST_SECRET:'test-secret-longer-than-thirty-two-characters',PUBLIC_DASHBOARD_ORIGINS:'https://mfrey18.github.io'};
 try{
  for(const method of ['GET','POST','OPTIONS'])assert.equal((await handleApi(new Request('https://test/api/internal/ingest',{method}),env,'public')).status,404);
  assert.equal((await handleApi(new Request('https://test/api/internal/health'),env,'private')).status,401);
  assert.equal((await handleApi(new Request('https://test/api/dashboard'),env,'private')).status,404);
  const request=new Request('https://test/api/dashboard?include=core',{headers:{Origin:'https://mfrey18.github.io'}});
  const result=await handleApi(request,env,'public');assert.equal(result.status,200);assert.equal(result.headers.get('access-control-allow-origin'),'https://mfrey18.github.io');
  const dashboard=await result.json();assert.equal(dashboard.metrics.total,0);assert.equal(dashboard.demo,false);
  const other=await handleApi(new Request(request.url,{headers:{Origin:'https://untrusted.invalid'}}),env,'public');assert.equal(other.headers.get('access-control-allow-origin'),null);
  cache.clear();
  const failing={...env,DB:{prepare(){throw Error('database offline');}}};
  const unavailable=await handleApi(request,failing,'public');assert.equal(unavailable.status,503);assert.equal(unavailable.headers.get('cache-control'),'no-store');
  assert.equal((await handleApi(new Request('https://test/api/dashboard/export?format=xml'),env,'public')).status,400);
  assert.equal((await handleApi(new Request('https://test/api/dashboard/export?format=csv'),env,'public')).status,200);
  assert.equal((await handleApi(new Request('https://test/api/cves/CVE-2026-999999'),env,'public')).status,404);
 }finally{await db.close();}
});

test('Lease contention, release ownership and expired lease takeover',async()=>{
 const db=await testDatabase();try{
  await seedIngestionCatalog(db);
  const winners=await Promise.all(['first','second'].map(holder=>acquireLease(db,'microsoft-msrc-csaf',holder)));
  assert.equal(winners.filter(Boolean).length,1);
  const winner=winners[0]?'first':'second';
  await releaseLease(db,'microsoft-msrc-csaf','not-holder');assert.equal(await acquireLease(db,'microsoft-msrc-csaf','third'),false);
  await releaseLease(db,'microsoft-msrc-csaf',winner);assert.equal(await acquireLease(db,'microsoft-msrc-csaf','third'),true);
  await db.prepare("UPDATE ingestion_leases SET expires_at=now()-interval '1 minute'").run();assert.equal(await acquireLease(db,'microsoft-msrc-csaf','fourth'),true);
  const repo=new PostgresIngestionRepository(db);
  const outcomes=await Promise.allSettled([1,2].map(()=>repo.beginRun('microsoft-msrc-csaf','same-key',{mode:'delta',maxItems:12})));
  assert.equal(outcomes.filter(result=>result.status==='fulfilled').length,1);
 }finally{await db.close();}
});

test('Reader credentials cannot write, including through the production driver',{skip:!process.env.TEST_DATABASE_URL && 'Requires the PostgreSQL TCP integration job'},async()=>{
 const db=await testDatabase();const role=`patch_reader_test_${process.pid}`;let reader;
 try{
  await db.prepare(`CREATE ROLE ${role} LOGIN PASSWORD 'isolated-test-only'`).run();
  await db.prepare(`GRANT USAGE ON SCHEMA public TO ${role}`).run();
  await db.prepare(`GRANT SELECT ON ALL TABLES IN SCHEMA public TO ${role}`).run();
  const url=new URL(process.env.TEST_DATABASE_URL);url.username=role;url.password='isolated-test-only';reader=connectDatabase(url.href,true);
  assert.equal((await reader.prepare('SELECT count(*) count FROM cves').first()).count,0);
  await assert.rejects(reader.prepare("INSERT INTO cves(id,created_at,updated_at) VALUES ('deny',now(),now())").run());
 }finally{await reader?.close();await db.prepare(`DROP OWNED BY ${role}`).run();await db.prepare(`DROP ROLE ${role}`).run();await db.close();}
});

test('Bind markers inside string literals are not changed',()=>{
 assert.equal(bindParameters("SELECT '?' AS literal, ? AS value, 'it''s ?' AS quoted"),"SELECT '?' AS literal, $1 AS value, 'it''s ?' AS quoted");
});

test('Cache is bounded, expires, and separates query strings',async()=>{
 const cache=new ResponseCache(1);const a=new Request('https://test/a?q=1'),b=new Request('https://test/a?q=2');
 await cache.put(a,new Response('a',{headers:{'cache-control':'max-age=30'}}));
 await cache.put(b,new Response('b',{headers:{'cache-control':'max-age=30'}}));
 assert.equal(await cache.match(a),undefined);assert.equal(await(await cache.match(b)).text(),'b');
 const epoch=cache.epoch;cache.clear();assert.equal(await cache.match(b),undefined);
 await cache.put(a,new Response('stale'),epoch);assert.equal(await cache.match(a),undefined);
 await cache.put(a,new Response('old',{headers:{'cache-control':'max-age=0'}}));assert.equal(await cache.match(a),undefined);
});
