import test from 'node:test';
import assert from 'node:assert/strict';
import {createSapHtmlAdapter} from '../lib/ingestion/adapters/sap.ts';
import {DEFAULT_SOURCE_POLICY} from '../lib/ingestion/contracts.ts';

test('SAP discovery visits only months intersecting the saved date window',async()=>{
 const seen=[];
 const fetch=async(url)=>{
  seen.push(url);
  return new Response(url.endsWith('security-notes-news.html')
   ? '<a href="/en/my-support/knowledge-base/security-notes-news/january-2026.html">January</a><a href="/en/my-support/knowledge-base/security-notes-news/september-2026.html">September</a>'
   : '<a href="https://me.sap.com/notes/1234567/E">Security Note</a>',{headers:{'content-type':'text/html'}});
 };
 const refs=await createSapHtmlAdapter().discover({fetch,policy:DEFAULT_SOURCE_POLICY,since:'2026-09-01T00:00:00Z',until:'2026-09-28T00:00:00Z'});
 assert.deepEqual(refs,[{id:'SAP-1234567',url:'https://me.sap.com/notes/1234567/E'}]);
 assert.equal(seen.length,2);assert.ok(seen[1].endsWith('/september-2026.html'));
});
