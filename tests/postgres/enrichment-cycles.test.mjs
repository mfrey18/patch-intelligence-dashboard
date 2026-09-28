import test from 'node:test';
import assert from 'node:assert/strict';
import {testDatabase} from './database.mjs';
import {seedIngestionCatalog} from '../../lib/ingestion/postgres-repository.ts';
import {loadEnrichmentCycle,requireChangedMembers,enrichmentProgress} from '../../lib/ingestion/enrichment-cycles.ts';
import {ingestCveEnrichment} from '../../lib/ingestion/enrichments/cve.ts';
async function addCve(db,id,at=new Date().toISOString()) {await db.prepare('INSERT INTO cves(id,created_at,updated_at) VALUES (?,?,?)').bind(id,at,at).run();}

test('finite membership survives midnight and deferred members prevent completion',async()=>{
 const db=await testDatabase();try{
  await seedIngestionCatalog(db);await addCve(db,'CVE-2026-10001','2026-09-20T00:00:00Z');
  const first=await loadEnrichmentCycle(db,'nvd-cve','2026-09-21T23:59:59Z');
  await addCve(db,'CVE-2026-10002','2026-09-22T00:00:01Z');
  assert.equal((await loadEnrichmentCycle(db,'nvd-cve','2026-09-22T00:00:02Z')).id,first.id);
  assert.equal(first.member_count,1);
  await db.prepare("UPDATE enrichment_cycle_members SET retry_at=now()+INTERVAL '1 hour' WHERE cycle_id=?").bind(first.id).run();
  const progress=await enrichmentProgress(db,first);assert.equal(progress.remaining,1);assert.equal(progress.eligible,0);assert.equal(progress.updatesComplete,false);
  await requireChangedMembers(db,first,[{id:'CVE-2026-10002',modified:'2026-09-22T00:00:01Z'}]);
  assert.equal((await db.prepare('SELECT COUNT(*) total FROM enrichment_cycle_members WHERE cycle_id=?').bind(first.id).first()).total,1);
 }finally{await db.close();}
});

test('revised requirement invalidates a previously satisfied member exactly once',async()=>{
 const db=await testDatabase();try{
  await seedIngestionCatalog(db);await addCve(db,'CVE-2026-10001','2026-09-20T00:00:00Z');
  const cycle=await loadEnrichmentCycle(db,'nvd-cve','2026-09-22T00:00:00Z');
  await db.prepare('UPDATE enrichment_cycle_members SET satisfied_generation=required_generation WHERE cycle_id=?').bind(cycle.id).run();
  const changes=[{id:'CVE-2026-10001',modified:'2026-09-21T00:00:00Z'}];
  await requireChangedMembers(db,cycle,changes);await requireChangedMembers(db,cycle,changes);
  const member=await db.prepare('SELECT required_generation,satisfied_generation FROM enrichment_cycle_members WHERE cycle_id=?').bind(cycle.id).first();
  assert.deepEqual(member,{required_generation:2,satisfied_generation:1});
 }finally{await db.close();}
});

test('missing CVE is recorded without an endless failure loop; completion is certified and followed by a new cycle',async()=>{
 const db=await testDatabase(),original=globalThis.fetch;try{
  await seedIngestionCatalog(db);await addCve(db,'CVE-2026-10001');
  globalThis.fetch=async url=>String(url).includes('/commits/')?Response.json({sha:'a'.repeat(40)}):String(url).endsWith('deltaLog.json')?Response.json([]):new Response('',{status:404});
  const first=await ingestCveEnrichment(db,'cve-list-v5',undefined,'missing-test');
  assert.equal(first.counts.failed,0,JSON.stringify(first.errors));assert.equal(first.boundHit,false);
  assert.equal((await db.prepare('SELECT outcome FROM enrichment_cycle_members').first()).outcome,'not_found');
  assert.equal((await db.prepare('SELECT COUNT(*) total FROM source_completion_evidence').first()).total,1);
  const old=await db.prepare('SELECT id FROM enrichment_cycles').first();
  const next=await loadEnrichmentCycle(db,'cve-list-v5');assert.notEqual(next.id,old.id);assert.equal(next.kind,'delta');
 }finally{globalThis.fetch=original;await db.close();}
});
