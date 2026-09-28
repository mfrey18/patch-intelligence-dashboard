import test from 'node:test';
import assert from 'node:assert/strict';
import {testDatabase} from './database.mjs';
import {seedIngestionCatalog,PostgresIngestionRepository} from '../../lib/ingestion/postgres-repository.ts';
import {captureOperationalMonitor} from '../../lib/operations/operational-monitor.ts';
import {loadEnrichmentCycle} from '../../lib/ingestion/enrichment-cycles.ts';
import {recordSourceCompletion} from '../../lib/ingestion/source-completion.ts';
import {queryDashboard} from '../../lib/api/dashboard-query.ts';
test('expansion freshness uses completed coverage, while incomplete enrichment alerts on age',async()=>{
 const db=await testDatabase();try{
 await seedIngestionCatalog(db);await db.prepare("UPDATE sources SET enabled=TRUE,readiness='production' WHERE id='nvd-cve'").run();
 const now=new Date().toISOString();await db.prepare('INSERT INTO cves(id,created_at,updated_at) VALUES (?,?,?)').bind('CVE-2026-10001',now,now).run();
 const cycle=await loadEnrichmentCycle(db,'nvd-cve');const repo=new PostgresIngestionRepository(db);
 const {runId}=await repo.beginRun('nvd-cve','monitor-pending',{mode:'delta',maxItems:1});
 await repo.finishRun(runId,{status:'partial',mode:'delta',window:{},processed:1,continuation:'remaining:1',boundHit:true,counts:{discovered:1,inserted:0,changed:1,unchanged:0,failed:0},errors:[]});
 let monitor=await captureOperationalMonitor(db,new Date(),async()=>1);let source=monitor.sources.find(s=>s.sourceId==='nvd-cve');
 assert.equal(source.lastSuccess,null);assert.equal(source.pending,true);assert.equal(source.result,'pending');
 await recordSourceCompletion(db,{sourceId:'nvd-cve',ownerKind:'enrichment',ownerId:'prior',kind:'delta',coverageStart:now,coverageEnd:now,completedAt:now,memberCount:1});
 monitor=await captureOperationalMonitor(db,new Date(),async()=>1);source=monitor.sources.find(s=>s.sourceId==='nvd-cve');assert.equal(source.lastSuccess,now);assert.equal(source.pending,true);
 await db.prepare("UPDATE enrichment_cycles SET started_at=now()-INTERVAL '3 days' WHERE id=?").bind(cycle.id).run();
 monitor=await captureOperationalMonitor(db,new Date(),async()=>1);assert.ok(monitor.alerts.some(a=>a.sourceId==='nvd-cve'&&a.code==='source_pending_backlog_stale'));
 const dashboard=await queryDashboard(db,new URL('http://test/api/dashboard?include=core'));assert.equal(dashboard.sourceHealth.find(s=>s.sourceId==='nvd-cve').pending,true);
 }finally{await db.close();}
});

test('active cycle queue and repeated no-progress attempts remain visible across runs',async()=>{
 const db=await testDatabase();try{
 await seedIngestionCatalog(db);await db.prepare("UPDATE sources SET enabled=TRUE,readiness='production' WHERE id='nvd-cve'").run();
 const now=new Date().toISOString();await db.prepare('INSERT INTO cves(id,created_at,updated_at) VALUES (?,?,?)').bind('CVE-2026-10002',now,now).run();
 const cycle=await loadEnrichmentCycle(db,'nvd-cve');
 await db.prepare("UPDATE enrichment_queue SET checked_at=now() WHERE source_id='nvd-cve'").run();
 const repo=new PostgresIngestionRepository(db);
 for(let i=0;i<2;i++){
  const {runId}=await repo.beginRun('nvd-cve',`stalled-${i}`,{mode:'delta',maxItems:1});
  await db.prepare('UPDATE source_runs SET checkpoint_id=?,continuation_in=? WHERE id=?').bind(cycle.id,'remaining:1',runId).run();
  await repo.finishRun(runId,{status:'partial',mode:'delta',window:{},processed:0,continuation:'remaining:1',boundHit:true,counts:{discovered:0,inserted:0,changed:0,unchanged:0,failed:0},errors:[]});
 }
 const monitor=await captureOperationalMonitor(db,new Date(),async()=>1);
 assert.ok(monitor.alerts.some(a=>a.sourceId==='nvd-cve'&&a.code==='source_pending_stalled'));
 assert.equal(monitor.projection.latestIngestionSuccess,null);
 const dashboard=await queryDashboard(db,new URL('http://test/api/dashboard?include=core'));
 assert.deepEqual(dashboard.sourceHealth.find(s=>s.sourceId==='nvd-cve').enrichmentQueue,{total:1,pending:1});
 }finally{await db.close();}
});
