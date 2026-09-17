import test from 'node:test';
import assert from 'node:assert/strict';
import {broadcomAdapter,parseBroadcomPage} from '../lib/ingestion/adapters/broadcom.ts';
import {sanitizeText} from '../lib/ingestion/safety.ts';
const row={documentId:'VCDSA38288',affectedCve:'CVE-2026-59346 and CVE-2026-59347',notificationUrl:'https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/38288',published:'03 September 2026',updated:'2026-09-03T08:58:26.960422',severity:'CRITICAL',title:'VMware security advisory',supportProducts:'VMware Fusion,VMware Work...',workAround:'None'};
function page(item=row){return {success:true,data:{list:[item],pageInfo:{currentPage:0,nextPage:1,lastPage:1,totalCount:2}}};}
test('Broadcom retains provenance and does not invent per-CVE severity, products or fixes',async()=>{
 const result=parseBroadcomPage(page(),0,'2026-03-17T00:00:00.000Z');assert.equal(result.nextCursor,'1');assert.equal(result.refs.length,1);
 const raw=await broadcomAdapter.fetch(result.refs[0]);const [advisory]=await broadcomAdapter.normalize(raw,{sanitizeText});
 assert.equal(advisory.cves.length,2);assert.equal(advisory.vendorSeverity,'CRITICAL');assert.ok(advisory.cves.every(c=>c.normalizedSeverity==='unknown'));
 assert.deepEqual(advisory.affectedProducts,[]);assert.deepEqual(advisory.remediations,[]);assert.equal(advisory.exploitationStatus,'unknown');
 assert.equal(advisory.sourceUpdatedAt,'2026-09-03T08:58:26.960Z');
});
test('Broadcom rejects bad pagination, identities and untrusted links',()=>{
 assert.throws(()=>parseBroadcomPage(page(),1),/index page/);
 const stalled=page();stalled.data.pageInfo.nextPage=0;assert.throws(()=>parseBroadcomPage(stalled,0),/did not advance/);
 assert.throws(()=>parseBroadcomPage(page({...row,affectedCve:'CVE-2026-invalid'}),0),/CVE identifier/);
 assert.throws(()=>parseBroadcomPage(page({...row,notificationUrl:'https://example.com/private'}),0),/origin/);
 assert.equal(parseBroadcomPage(page(),0,'2026-09-04T00:00:00.000Z').refs.length,0);
 assert.equal(parseBroadcomPage(page({...row,affectedCve:'CVE-2018-12130,andCVE-2019-11091CVE-2020-12345'}),0).refs.length,1);
});
