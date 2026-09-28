import test from 'node:test';
import assert from 'node:assert/strict';
import {runDailyIngestion} from '../scripts/daily-ingestion.mjs';
import {selectExpansionSources} from '../scripts/sync-expansion.mjs';

test('hourly selection excludes current daily sources and unvalidated adapters',()=>{
 const sources=[{id:'cisco-psirt-csaf',enabled:true,readiness:'production'},{id:'red-hat-csaf',enabled:true,readiness:'production'},{id:'adobe-psirt-csaf',enabled:false,readiness:'pending_feed'}];
 assert.deepEqual(selectExpansionSources(sources),['red-hat-csaf']);
 assert.deepEqual(selectExpansionSources(sources,'adobe-psirt-csaf'),['adobe-psirt-csaf']);
});
test('enrichment progress requires certified fresh coverage and resumes across midnight',async()=>{
 let time=Date.parse('2026-09-22T23:59:59Z'),calls=0;const bodies=[];
 const summary=await runDailyIngestion({sourceId:'nvd-cve',secret:'test',origin:'http://test',now:()=>time,fetchImpl:async(_url,init)=>{
  bodies.push(JSON.parse(init.body));calls++;time+=2000;
  const progress=calls===1?{state:'pending',ownerId:'saved-cycle',position:'page:2',coverageEnd:null}:{state:'complete',ownerId:'saved-cycle',position:null,coverageEnd:new Date(time).toISOString()};
  return Response.json({results:[{status:calls===1?'pending':'unchanged',counts:{failed:0},progress}]});
 }});
 assert.equal(summary.status,'complete');assert.equal(calls,2);assert.equal(bodies[0].checkpointId,bodies[1].checkpointId);assert.equal(bodies[0].invocationStartedAt,bodies[1].invocationStartedAt);assert.equal(bodies[0].maxItems,1);
});
test('enrichment cooldown beyond budget remains pending and never reports a complete cycle',async()=>{
 const now=Date.now();let calls=0;
 const summary=await runDailyIngestion({sourceId:'nvd-cve',secret:'test',origin:'http://test',now:()=>now,fetchImpl:async()=>{
  calls++;return Response.json({results:[{status:'pending',progress:{state:'pending',ownerId:'cycle',position:'remaining:4',retryAt:new Date(now+3600000).toISOString()}}]},{status:202});
 }});
 assert.equal(calls,1);assert.equal(summary.status,'pending');assert.equal(summary.alert,false);
});

test('current daily vendors retain twelve-advisory throughput and require fresh coverage',async()=>{
 const time=Date.parse('2026-09-28T07:17:00Z');const bodies=[];
 const summary=await runDailyIngestion({sourceId:'mozilla-mfsa-yaml',secret:'test',origin:'http://test',maxBatches:4,now:()=>time,fetchImpl:async(_url,init)=>{
  bodies.push(JSON.parse(init.body));return Response.json({results:[{status:'success',checkpoint:{id:`saved:${bodies.length}`,status:'complete',coverageEnd:bodies.length===1?'2026-09-27T07:17:00Z':new Date(time).toISOString()}}]});
 }});
 assert.equal(summary.status,'complete');assert.equal(bodies.length,2);assert.ok(bodies.every(body=>body.maxItems===12&&body.scheduled));
});
test('manual validation delta is scheduled, but explicit manual ranges retain their identity',async()=>{
 for(const [env,expected] of [[{},true],[{CHECKPOINT_ID:'daily:cisco:2026-09-27'},true],[{CHECKPOINT_ID:'operator-replay',SINCE:'2026-09-01',INGEST_MODE:'replay'},false]]) {
  let body;await runDailyIngestion({env,secret:'test',origin:'http://test',maxBatches:1,fetchImpl:async(_url,init)=>{body=JSON.parse(init.body);return Response.json({results:[{status:'pending'}]});}});
  assert.equal(body.scheduled,expected);if(env.CHECKPOINT_ID)assert.equal(body.checkpointId,env.CHECKPOINT_ID);
 }
});
test('checkpointless manual pending never becomes completed and paused exits pending',async()=>{
 for(const run of [{status:'pending'},{status:'pending',reason:'Source is paused'}]){
  let calls=0;const summary=await runDailyIngestion({scheduled:false,sourceId:'first-epss',secret:'test',origin:'http://test',fetchImpl:async()=>{calls++;return Response.json({results:[run]});}});
  assert.equal(summary.status,'pending');assert.equal(summary.alert,false);assert.equal(calls,1);
 }
});
test('projection is attempted after EPSS fails and both failures are reported',async()=>{
 const {refreshExpansionProjection}=await import('../scripts/sync-expansion.mjs');const paths=[];
 await assert.rejects(refreshExpansionProjection({},async(_env,path)=>{paths.push(path);if(path.endsWith('/ingest'))throw new Error('EPSS unavailable');return {status:'failed'};}),error=>error instanceof AggregateError && error.errors.length===2 && /EPSS unavailable/.test(error.message));
 assert.deepEqual(paths,['/api/internal/ingest','/api/internal/projection']);
});
test('matrix completion requires exactly one complete report for each daily source',async()=>{
 const {dailyReportsComplete,DAILY_MATRIX_SOURCES}=await import('../scripts/aggregate-daily.mjs');
 const reports=DAILY_MATRIX_SOURCES.map(source=>({source,status:'complete'}));assert.equal(dailyReportsComplete(reports),true);
 assert.equal(dailyReportsComplete(reports.slice(1)),false);assert.equal(dailyReportsComplete([...reports,reports[0]]),false);
 reports[0].status='pending';assert.equal(dailyReportsComplete(reports),false);
});
