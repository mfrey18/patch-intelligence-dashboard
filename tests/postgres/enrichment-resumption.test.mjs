import test from 'node:test';
import assert from 'node:assert/strict';
import {testDatabase} from './database.mjs';
import {seedIngestionCatalog} from '../../lib/ingestion/postgres-repository.ts';
import {ingestCveEnrichment} from '../../lib/ingestion/enrichments/cve.ts';
import {loadEnrichmentCycle,requireChangedMembers} from '../../lib/ingestion/enrichment-cycles.ts';

async function setup(){const db=await testDatabase();await seedIngestionCatalog(db);return db;}
async function add(db,id,at=new Date().toISOString()){await db.prepare('INSERT INTO cves(id,created_at,updated_at) VALUES (?,?,?)').bind(id,at,at).run();}
async function evidenceCount(db){return Number((await db.prepare('SELECT COUNT(*) count FROM source_completion_evidence').first()).count);}

test('NVD outage resumes every page and seven-day window through the fixed cycle target before certification',async()=>{
 const db=await setup(),original=globalThis.fetch;
 try{
  const start=new Date(Date.now()-16*86400000).toISOString();
  await db.prepare("INSERT INTO enrichment_cycles(id,source_id,kind,started_at,target_through,updates_from,updates_covered_through,completed_at,member_count) VALUES ('previous','nvd-cve','initial_enrichment',?,?,?,?,?,0)").bind(start,start,start,start,start).run();
  const ids=['CVE-2026-21001','CVE-2026-21002'];
  for(const id of ids){await add(db,id,new Date(Date.now()-30*86400000).toISOString());await db.prepare('INSERT INTO enrichment_queue(cve_id,source_id,checked_at) VALUES (?,\'nvd-cve\',now())').bind(id).run();}
  const pages=[],records=[];let firstWindow;
  const modified=new Date(Date.now()-1000).toISOString();
  globalThis.fetch=async input=>{
   const url=new URL(input);
   if(url.searchParams.has('cveId')){
    const id=url.searchParams.get('cveId');records.push(id);
    return Response.json({totalResults:1,vulnerabilities:[{cve:{id,vulnStatus:'Analyzed',published:modified,lastModified:modified,descriptions:[{lang:'en',value:'Verified NVD record'}]}}]});
   }
   const page={since:url.searchParams.get('lastModStartDate'),until:url.searchParams.get('lastModEndDate'),offset:Number(url.searchParams.get('startIndex'))};
   pages.push(page);firstWindow??=page.until;
   if(page.until===firstWindow)return Response.json({totalResults:2,startIndex:page.offset,vulnerabilities:[{cve:{id:ids[page.offset],lastModified:new Date(Date.parse(page.since)+(page.offset+1)*86400000).toISOString()}}]});
   return Response.json({totalResults:0,startIndex:0,vulnerabilities:[]});
  };
  let target;
  for(let batch=0;batch<4;batch++){
   const result=await ingestCveEnrichment(db,'nvd-cve','existing-key',`outage-${batch}`);
   assert.equal(result.counts.failed,0,JSON.stringify(result.errors));
   const cycle=await db.prepare("SELECT id,target_through,completed_at FROM enrichment_cycles WHERE id<>'previous'").first();
   target??=cycle.target_through;assert.equal(cycle.target_through,target,'resumption must not move target');
   assert.equal(result.boundHit,batch<3,JSON.stringify(result));
   assert.equal(await evidenceCount(db),batch<3?0:1,'one finished page is not a completed update cycle');
  }
  assert.deepEqual(pages.map(p=>p.offset),[0,1,0,0]);
  assert.equal(pages[0].since,pages[1].since);assert.equal(pages[0].until,pages[1].until);
  assert.equal(Date.parse(pages[0].until)-Date.parse(pages[0].since),7*86400000);
  assert.equal(pages[2].since,pages[1].until);assert.equal(pages[3].since,pages[2].until);assert.equal(pages[3].until,target);
  assert.deepEqual(records,ids);
  assert.equal((await db.prepare('SELECT coverage_end FROM source_completion_evidence').first()).coverage_end,target);
 }finally{globalThis.fetch=original;await db.close();}
});

test('all-deferred membership stays pending and replaying its idempotency key preserves the saved bound and cursor',async()=>{
 const db=await setup(),original=globalThis.fetch;
 try{
  await add(db,'CVE-2026-22001');const cycle=await loadEnrichmentCycle(db,'nvd-cve');
  await db.prepare('UPDATE enrichment_cycles SET updates_covered_through=target_through WHERE id=?').bind(cycle.id).run();
  await db.prepare("UPDATE enrichment_cycle_members SET retry_at=now()+INTERVAL '1 hour' WHERE cycle_id=?").bind(cycle.id).run();
  globalThis.fetch=async()=>{throw new Error('Deferred members must not fetch');};
  const first=await ingestCveEnrichment(db,'nvd-cve','existing-key','deferred-key');
  assert.equal(first.counts.failed,0);assert.equal(first.boundHit,true);assert.ok(first.continuation);
  assert.ok((await db.prepare("SELECT retry_after FROM sources WHERE id='nvd-cve'").first()).retry_after);
  const repeated=await ingestCveEnrichment(db,'nvd-cve','existing-key','deferred-key');
  assert.equal(repeated.runId,first.runId);assert.equal(repeated.boundHit,true);assert.equal(repeated.continuation,first.continuation);
  assert.equal(await evidenceCount(db),0);
  // A later update invalidates only the requirement; it must not erase a real retry deadline.
  const change={id:'CVE-2026-22001',modified:new Date(Date.parse(cycle.target_through)-1).toISOString()};
  await requireChangedMembers(db,cycle,[change]);await requireChangedMembers(db,cycle,[change]);
  const member=await db.prepare('SELECT required_generation,satisfied_generation,retry_at FROM enrichment_cycle_members WHERE cycle_id=?').bind(cycle.id).first();
  assert.equal(member.required_generation,2);assert.equal(member.satisfied_generation,0);assert.ok(member.retry_at);
 }finally{globalThis.fetch=original;await db.close();}
});

test('a CVE admitted during a cycle waits for the next captured membership without blocking the old cycle',async()=>{
 const db=await setup(),original=globalThis.fetch;
 try{
  await add(db,'CVE-2026-23001');const cycle=await loadEnrichmentCycle(db,'nvd-cve');
  await add(db,'CVE-2026-23002',new Date(Date.parse(cycle.started_at)+1).toISOString());
  await db.prepare('UPDATE enrichment_cycles SET updates_covered_through=target_through WHERE id=?').bind(cycle.id).run();
  await db.prepare('UPDATE enrichment_cycle_members SET satisfied_generation=required_generation,checked_at=now() WHERE cycle_id=?').bind(cycle.id).run();
  await db.prepare("UPDATE enrichment_queue SET checked_at=now() WHERE source_id='nvd-cve'").run();
  globalThis.fetch=async()=>{throw new Error('Completed old membership requires no fetch');};
  const completed=await ingestCveEnrichment(db,'nvd-cve','existing-key','old-membership');
  assert.equal(completed.counts.failed,0,JSON.stringify(completed.errors));assert.equal(completed.boundHit,false);assert.equal(await evidenceCount(db),1);
  const next=await loadEnrichmentCycle(db,'nvd-cve');
  assert.notEqual(next.id,cycle.id);
  assert.deepEqual((await db.prepare('SELECT cve_id FROM enrichment_cycle_members WHERE cycle_id=? ORDER BY cve_id').bind(next.id).all()).results,[{cve_id:'CVE-2026-23002'}]);
 }finally{globalThis.fetch=original;await db.close();}
});

test('CVE Program pins one fresh revision for every batch in a cycle and refreshes it for the next cycle',async()=>{
 const db=await setup(),original=globalThis.fetch;
 try{
  for(let index=0;index<51;index++)await add(db,`CVE-2026-${24000+index}`);
  let commits=0;const documentRevisions=[];
  globalThis.fetch=async input=>{
   const url=String(input);
   if(url.includes('/commits/'))return Response.json({sha:(++commits===1?'a':'b').repeat(40)});
   const revision=/cvelistV5\/([ab]{40})\//.exec(url)?.[1];assert.ok(revision,`unexpected URL ${url}`);
   if(url.endsWith('deltaLog.json'))return Response.json([]);
   documentRevisions.push(revision);return new Response('',{status:404});
  };
  const first=await ingestCveEnrichment(db,'cve-list-v5',undefined,'pinned-1');
  assert.equal(first.counts.failed,0,JSON.stringify(first.errors));assert.equal(first.boundHit,true);assert.equal(commits,1);
  const second=await ingestCveEnrichment(db,'cve-list-v5',undefined,'pinned-2');
  assert.equal(second.counts.failed,0,JSON.stringify(second.errors));assert.equal(second.boundHit,false);assert.equal(commits,1);
  assert.deepEqual(new Set(documentRevisions),new Set(['a'.repeat(40)]));assert.equal(await evidenceCount(db),1);
  const third=await ingestCveEnrichment(db,'cve-list-v5',undefined,'pinned-3');
  assert.equal(third.counts.failed,0,JSON.stringify(third.errors));assert.equal(commits,2);assert.equal(documentRevisions.at(-1),'b'.repeat(40));
 }finally{globalThis.fetch=original;await db.close();}
});
