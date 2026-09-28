import test from 'node:test';
import assert from 'node:assert/strict';
import { gzipSync } from 'node:zlib';
import { testDatabase } from './database.mjs';
import { handleApi } from '../../server/api.ts';
import { ResponseCache } from '../../server/cache.ts';

const id='CVE-2026-10000';
const today=new Date().toISOString().slice(0,10);
const snapshot={catalogVersion:today,dateReleased:new Date().toISOString(),count:1,vulnerabilities:[{cveID:id,vendorProject:'Vendor',product:'Product',vulnerabilityName:'Issue',dateAdded:today,shortDescription:'Issue',requiredAction:'Update',dueDate:today,cwes:[]}]};
async function invoke(db,sourceId) {
 const startedAt=new Date().toISOString();
 const response=await handleApi(new Request('http://test/api/internal/ingest',{method:'POST',headers:{authorization:'Bearer test','content-type':'application/json'},body:JSON.stringify({sources:[sourceId],mode:'delta',scheduled:true,checkpointId:`daily:${sourceId}:${today}`,refreshProjection:false})}),{DB:db,cache:new ResponseCache(),INGEST_SECRET:'test'},'private');
 const payload=await response.json();assert.equal(response.status,200,JSON.stringify(payload));
 const run=payload.results[0];assert.equal(run.progress.state,'complete');assert.ok(Date.parse(run.progress.coverageEnd)>=Date.parse(startedAt));
 return run;
}
test('scheduled CISA and EPSS certify fresh success and unchanged snapshots; empty membership records removal',async()=>{
 const db=await testDatabase(),originalFetch=globalThis.fetch;
 try {
  globalThis.fetch=async()=>Response.json(snapshot);
  assert.equal((await invoke(db,'cisa-kev')).status,'success');
  assert.equal((await invoke(db,'cisa-kev')).status,'unchanged');
  const csv=`#model_version:v1,score_date:${today}\ncve,epss,percentile\n`+Array.from({length:100000},(_,index)=>`CVE-2026-${10000+index},0.5,0.95\n`).join('');
  const compressed=gzipSync(csv);
  globalThis.fetch=async()=>new Response(compressed);
  assert.equal((await invoke(db,'first-epss')).status,'success');
  assert.equal((await invoke(db,'first-epss')).status,'unchanged');
  await db.prepare('UPDATE kev_entries SET active=FALSE').run();
  const removed=await invoke(db,'first-epss');assert.equal(removed.counts.inserted,0);assert.equal(removed.counts.changed,1);
  assert.equal((await db.prepare('SELECT COUNT(*) count FROM epss_observations').first()).count,0);
  const certificates=(await db.prepare('SELECT source_id,COUNT(*) count FROM source_completion_evidence GROUP BY source_id ORDER BY source_id').all()).results;
  assert.deepEqual(certificates,[{source_id:'cisa-kev',count:2},{source_id:'first-epss',count:3}]);
 } finally {globalThis.fetch=originalFetch;await db.close();}
});

test('CISA reactivation and missing-evidence repair signal committed changes',async()=>{
 const db=await testDatabase(),originalFetch=globalThis.fetch;
 try {
  globalThis.fetch=async()=>Response.json(snapshot);
  await invoke(db,'cisa-kev');
  await db.prepare('UPDATE kev_entries SET active=FALSE,removed_at=now() WHERE cve_id=?').bind(id).run();
  const reactivated=await invoke(db,'cisa-kev');
  assert.equal(reactivated.status,'success');assert.equal(reactivated.counts.changed,1);assert.equal(reactivated.counts.unchanged,0);
  assert.equal((await db.prepare('SELECT active FROM kev_entries WHERE cve_id=?').bind(id).first()).active,true);
  await db.prepare("DELETE FROM exploit_evidence WHERE cve_id=? AND source_id='cisa-kev'").bind(id).run();
  const repaired=await invoke(db,'cisa-kev');
  assert.equal(repaired.status,'success');assert.equal(repaired.counts.changed,1);assert.equal(repaired.counts.unchanged,0);
  assert.equal((await db.prepare("SELECT COUNT(*) count FROM exploit_evidence WHERE cve_id=? AND source_id='cisa-kev' AND status='confirmed'").bind(id).first()).count,1);
  const unchanged=await invoke(db,'cisa-kev');assert.equal(unchanged.status,'unchanged');assert.equal(unchanged.counts.changed,0);
 } finally {globalThis.fetch=originalFetch;await db.close();}
});
