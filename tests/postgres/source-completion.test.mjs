import test from 'node:test';
import assert from 'node:assert/strict';
import { testDatabase } from './database.mjs';
import { seedIngestionCatalog } from '../../lib/ingestion/postgres-repository.ts';
import { loadOrCreateCheckpoint, advanceCheckpoint } from '../../lib/ingestion/orchestration.ts';
import { recordSourceCompletion } from '../../lib/ingestion/source-completion.ts';
import { setSourceReadiness } from '../../lib/ingestion/source-readiness.ts';
import { leasedSourceDatabase, runSourceOperation, SourceBudgetExpired, SourceLeaseLost } from '../../lib/ingestion/source-execution.ts';
import { acquireLease, releaseLease } from '../../server/api.ts';

const source='red-hat-csaf';
const now=new Date('2026-09-22T12:00:00.000Z');
async function ready(){const db=await testDatabase();await seedIngestionCatalog(db);return db;}
async function run(db,cp,id='run'){
  await db.prepare("INSERT INTO source_runs(id,source_id,started_at,completed_at,status,ingestion_mode,checkpoint_id,records_inserted) VALUES (?,?,now(),now(),'success',?,?,1)").bind(id,source,cp.mode,cp.id).run();
  await db.prepare("INSERT INTO source_run_results(id,source_run_id,source_ref,status,duration_ms,observed_at) VALUES (?,?,?,'inserted',0,now())").bind(`${id}-item`,id,'RHSA-1').run();
  return {sourceId:source,runId:id,status:'success',mode:cp.mode,window:{since:cp.windowStart,until:cp.windowEnd},processed:1,continuation:null,boundHit:false,counts:{discovered:1,inserted:1,changed:0,unchanged:0,failed:0},errors:[],startedAt:now.toISOString(),completedAt:now.toISOString()};
}
test('all scheduled vendors resume oldest work across midnight and preserve manual replay identities',async()=>{
 const db=await ready();try{
  const first=await loadOrCreateCheckpoint(db,source,{scheduled:true,checkpointId:'daily:red-hat-csaf:2026-09-21'},now);
  assert.equal(first.coverageStart,'2026-03-22T00:00:00.000Z');
  await db.prepare("UPDATE ingestion_checkpoints SET continuation_token='offset:3',status='failed' WHERE id=?").bind(first.id).run();
  const resumed=await loadOrCreateCheckpoint(db,source,{scheduled:true,checkpointId:'daily:red-hat-csaf:2026-09-23'},new Date('2026-09-23T12:00:00Z'));
  assert.equal(resumed.id,first.id);assert.equal(resumed.continuation,'offset:3');
  const manual=await loadOrCreateCheckpoint(db,source,{mode:'replay',checkpointId:'manual-redhat',since:'2026-09-22T00:00:00Z',until:now.toISOString()},now);
  assert.equal(manual.id,'manual-redhat');assert.equal(manual.scheduled,false);
 }finally{await db.close();}
});
test('weekly reconciliation yields to fresh overlap then becomes due without renaming old owners',async()=>{
 const db=await ready();try{
  const first=await loadOrCreateCheckpoint(db,source,{scheduled:true},now);
  await db.prepare("UPDATE ingestion_checkpoints SET status='complete',completed_at=? WHERE id=?").bind(now.toISOString(),first.id).run();
  const tomorrow=new Date(now.getTime()+86400000);
  const delta=await loadOrCreateCheckpoint(db,source,{scheduled:true},tomorrow);
  assert.equal(delta.coverageStart,new Date(now.getTime()-3*86400000).toISOString());
  await db.prepare("UPDATE ingestion_checkpoints SET status='complete',completed_at=? WHERE id=?").bind(tomorrow.toISOString(),delta.id).run();
  const week=await loadOrCreateCheckpoint(db,source,{scheduled:true},new Date(now.getTime()+8*86400000));
  assert.equal(week.coverageStart,'2026-03-30T00:00:00.000Z');
 }finally{await db.close();}
});
test('expired backlog is retired without certification and requested old identity is not reopened',async()=>{
 const db=await ready();try{
  const id='daily:red-hat-csaf:old';
  await db.prepare("INSERT INTO ingestion_checkpoints(id,source_id,mode,coverage_start,coverage_end,window_start,window_end,status,created_at,updated_at,scheduled) VALUES (?,?,'delta','2026-01-01','2026-01-02','2026-01-01','2026-01-02','pending','2026-01-01','2026-01-01',true)").bind(id,source).run();
  const fresh=await loadOrCreateCheckpoint(db,source,{scheduled:true,checkpointId:id},now);
  assert.notEqual(fresh.id,id);
  assert.ok((await db.prepare('SELECT retired_at FROM ingestion_checkpoints WHERE id=?').bind(id).first()).retired_at);
  assert.equal((await db.prepare('SELECT COUNT(*) count FROM source_completion_evidence').first()).count,0);
 }finally{await db.close();}
});
test('batch completion cannot certify unfinished windows; final advancement and certificate commit together',async()=>{
 const db=await ready();try{
  const cp=await loadOrCreateCheckpoint(db,source,{scheduled:true},now);
  // A persisted legacy calendar window must retain its position after the planner changes.
  cp.windowEnd=new Date(Date.parse(cp.coverageStart)+3*86400000-1).toISOString();
  await db.prepare('UPDATE ingestion_checkpoints SET window_end=? WHERE id=?').bind(cp.windowEnd,cp.id).run();
  const result=await run(db,cp);
  const next=await advanceCheckpoint(db,cp,result);
  assert.equal(next.status,'pending');assert.equal((await db.prepare('SELECT COUNT(*) count FROM source_completion_evidence').first()).count,0);
  const final={...next,windowStart:next.coverageEnd,windowEnd:next.coverageEnd};
  await db.prepare('UPDATE ingestion_checkpoints SET window_start=?,window_end=? WHERE id=?').bind(final.windowStart,final.windowEnd,final.id).run();
  const terminal=await run(db,final,'final');
  await assert.rejects(db.transaction(async tx=>{await advanceCheckpoint(tx,final,terminal);throw new Error('crash');}),/crash/);
  assert.equal((await db.prepare('SELECT status FROM ingestion_checkpoints WHERE id=?').bind(cp.id).first()).status,'pending');
  assert.equal((await db.prepare('SELECT COUNT(*) count FROM source_completion_evidence').first()).count,0);
  await advanceCheckpoint(db,final,terminal);await advanceCheckpoint(db,final,terminal);
  const evidence=await db.prepare('SELECT member_count,coverage_end FROM source_completion_evidence').all();
  assert.equal(evidence.results.length,1);assert.equal(evidence.results[0].member_count,1);assert.equal(evidence.results[0].coverage_end,cp.coverageEnd);
 }finally{await db.close();}
});
test('promotion rejects successful batch dates without cycle evidence and empty enrichment evidence',async()=>{
 const db=await ready();try{
  for(const date of ['2026-09-21','2026-09-22'])await db.prepare("INSERT INTO source_runs(id,source_id,started_at,completed_at,status,ingestion_mode,records_inserted) VALUES (?,?,?,?,'success','delta',1)").bind(date,source,date,date).run();
  await assert.rejects(setSourceReadiness(db,source,'production'),/two completed delta cycles/);
  const src='cve-list-v5';
  for(const days of [0,1]){const at=new Date(Date.now()-days*86400000).toISOString();await recordSourceCompletion(db,{sourceId:src,ownerKind:'enrichment',ownerId:`done-${days}`,kind:'delta',coverageStart:at,coverageEnd:at,completedAt:at,memberCount:4});}
  await assert.rejects(setSourceReadiness(db,src,'production'),/captured initial/);
  const at=new Date().toISOString();await recordSourceCompletion(db,{sourceId:src,ownerKind:'enrichment',ownerId:'initial',kind:'initial_enrichment',coverageStart:at,coverageEnd:at,completedAt:at,memberCount:4});
  await assert.rejects(setSourceReadiness(db,src,'production'),/Zero records/);
 }finally{await db.close();}
});
test('lost lease and exhausted deadline fence all mutations, including nested transactions',async()=>{
 const db=await ready();try{
  assert.equal(await acquireLease(db,source,'first'),true);
  const guarded=leasedSourceDatabase(db,source,'first');
  await guarded.prepare("UPDATE sources SET readiness_reason='valid owner' WHERE id=?").bind(source).run();
  await releaseLease(db,source,'first');await acquireLease(db,source,'second');
  await assert.rejects(guarded.transaction(tx=>tx.prepare("UPDATE sources SET readiness_reason='stale' WHERE id=?").bind(source).run()),SourceLeaseLost);
  const current=leasedSourceDatabase(db,source,'second');
  const aborted=new AbortController();aborted.abort();
  await assert.rejects(runSourceOperation(1000,aborted.signal,()=>current.prepare("UPDATE sources SET readiness_reason='expired' WHERE id=?").bind(source).run()),SourceBudgetExpired);
  assert.equal((await db.prepare('SELECT readiness_reason FROM sources WHERE id=?').bind(source).first()).readiness_reason,'valid owner');
 }finally{await db.close();}
});
test('configured document subsets cannot certify historical backfills',async()=>{
 const db=await ready();try{
  const cp=await loadOrCreateCheckpoint(db,source,{mode:'backfill',since:'2026-09-22T00:00:00.000Z',until:now.toISOString(),checkpointId:'subset'},now);
  const result=await run(db,cp);
  const completed=await advanceCheckpoint(db,cp,result,{historicalCoverage:false});
  assert.equal(completed.status,'complete');
  assert.equal((await db.prepare('SELECT COUNT(*) count FROM source_completion_evidence').first()).count,0);
 }finally{await db.close();}
});
test('enrichment promotion requires actual records and a fresh passing projection',async()=>{
 const db=await ready();try{
  const src='cve-list-v5';const at=new Date().toISOString();
  for(const days of [0,1]){const date=new Date(Date.now()-days*86400000).toISOString();await recordSourceCompletion(db,{sourceId:src,ownerKind:'enrichment',ownerId:`delta-${days}`,kind:'delta',coverageStart:date,coverageEnd:date,completedAt:date,memberCount:1});}
  await recordSourceCompletion(db,{sourceId:src,ownerKind:'enrichment',ownerId:'initial',kind:'initial_enrichment',coverageStart:at,coverageEnd:at,completedAt:at,memberCount:1});
  await db.prepare("INSERT INTO cves(id,created_at,updated_at) VALUES ('CVE-2026-12345',now(),now())").run();
  await db.prepare("INSERT INTO cve_enrichments(cve_id,source_id,content_hash,payload,source_url,observed_at) VALUES ('CVE-2026-12345',?,'hash','{}','https://www.cve.org/CVERecord?id=CVE-2026-12345',now())").bind(src).run();
  await assert.rejects(setSourceReadiness(db,src,'production'),/fresh projection/);
  await db.prepare("INSERT INTO dashboard_projection_state(id,projection_version,generated_at,cve_count,status,parity_status,last_attempt_status) VALUES ('current',2,now(),1,'published','passed','success') ON CONFLICT(id) DO UPDATE SET generated_at=now(),parity_status='passed',last_attempt_status='success'").run();
  await db.prepare("UPDATE dashboard_projection_state SET generated_at=now()-INTERVAL '1 hour' WHERE id='current'").run();
  await db.prepare("INSERT INTO source_runs(id,source_id,started_at,completed_at,status,ingestion_mode,records_changed) VALUES ('unprojected',?,now(),now(),'success','delta',1)").bind(src).run();
  await assert.rejects(setSourceReadiness(db,src,'production'),/fresh projection/);
  await db.prepare("UPDATE dashboard_projection_state SET generated_at=now() WHERE id='current'").run();
  await setSourceReadiness(db,src,'production');
  assert.equal((await db.prepare('SELECT readiness FROM sources WHERE id=?').bind(src).first()).readiness,'production');
 }finally{await db.close();}
});
test('historical coverage capability is retained across windows and cannot be upgraded at the final batch',async()=>{
 const db=await ready();try{
  const cp=await loadOrCreateCheckpoint(db,source,{mode:'backfill',since:'2026-09-21T00:00:00Z',until:now.toISOString(),checkpointId:'verified'},now,{historicalCoverage:true});
  assert.equal(cp.historicalCoverageVerified,true);
  cp.windowEnd='2026-09-21T23:59:59.999Z';
  await db.prepare('UPDATE ingestion_checkpoints SET window_end=? WHERE id=?').bind(cp.windowEnd,cp.id).run();
  const first=await run(db,cp,'window1');
  await advanceCheckpoint(db,cp,first,{historicalCoverage:false});
  const resumed=await loadOrCreateCheckpoint(db,source,{mode:'backfill',checkpointId:cp.id},now,{historicalCoverage:true});
  assert.equal(resumed.historicalCoverageVerified,false);
  const final=await run(db,resumed,'window2');
  assert.equal((await advanceCheckpoint(db,resumed,final,{historicalCoverage:true})).status,'complete');
  assert.equal((await db.prepare('SELECT COUNT(*) count FROM source_completion_evidence').first()).count,0);
  const verified=await loadOrCreateCheckpoint(db,source,{mode:'backfill',since:'2026-09-22T00:00:00Z',until:now.toISOString(),checkpointId:'entirely-verified'},now,{historicalCoverage:true});
  await advanceCheckpoint(db,verified,await run(db,verified,'all'),{historicalCoverage:true});
  assert.equal((await db.prepare('SELECT kind FROM source_completion_evidence').first()).kind,'backfill');
 }finally{await db.close();}
});
