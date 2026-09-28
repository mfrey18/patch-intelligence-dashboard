import test from 'node:test';
import assert from 'node:assert/strict';
import { createCitrixAdapter } from '../lib/ingestion/adapters/citrix.ts';
const base='https://support.citrix.com/';
const detail=n=>`${base}external/article/CTX${n}/security-bulletin.html`;
const index=urls=>`<sitemapindex>${urls.map(url=>`<sitemap><loc>${url}</loc></sitemap>`).join('')}</sitemapindex>`;
const urlset=urls=>`<urlset>${urls.map(url=>`<url><loc>${url}</loc></url>`).join('')}</urlset>`;
function context(pages,calls=[]) {return {policy:{timeoutMs:1000,maxResponseBytes:5_000_000,retries:0,retryBaseMs:1},fetch:async url=>{calls.push(url);if(!(url in pages))throw new Error(`unresolved ${url}`);return new Response(pages[url]);}};}
test('root urlset returns every detail reference without fetching details',async()=>{
 const calls=[];const urls=Array.from({length:12},(_,n)=>detail(10000+n));
 const refs=await createCitrixAdapter().discover(context({[`${base}sitemap.xml`]:urlset(urls)},calls));
 assert.deepEqual(refs.map(ref=>ref.url),urls);assert.equal(calls.length,1);
});
test('nested sitemap indexes traverse beyond eight children and decode XML locations',async()=>{
 const children=Array.from({length:9},(_,n)=>`${base}child${n}.xml`);
 const pages={[`${base}sitemap.xml`]:index([`${base}nested.xml`]),[`${base}nested.xml`]:index(children)};
 children.forEach((url,n)=>{pages[url]=urlset([`${detail(10000+n)}?a=1&amp;b=2`]);});
 const refs=await createCitrixAdapter().discover(context(pages));assert.equal(refs.length,9);assert.ok(refs[0].url.endsWith('?a=1&b=2'));
});
test('incomplete, unresolved, cyclic and over-limit maps fail rather than certify partial discovery',async()=>{
 const root=`${base}sitemap.xml`;
 for(const pages of [
  {[root]:index([`${base}missing.xml`])},
  {[root]:index([root])},
  {[root]:index(Array.from({length:32},(_,n)=>`${base}map${n}.xml`))},
  {[root]:urlset([detail(10000)]).replace('</urlset>','')},
  {[root]:'<sitemapindex><sitemap/></sitemapindex>'},
  {[root]:index([`${base}html.xml`]),[`${base}html.xml`]:'<html>blocked</html>'},
  {[root]:urlset(Array.from({length:20001},(_,n)=>detail(10000+n)))},
 ]) await assert.rejects(createCitrixAdapter().discover(context(pages)),/unresolved|cyclic|limit|incomplete|location|resolve/);
});
test('general support sitemap and custom indexes cannot claim complete security history',async()=>{
 assert.equal(createCitrixAdapter().historicalCoverage,undefined);
 assert.equal(createCitrixAdapter({detailUrls:[detail(10000)]}).historicalCoverage,'configured_subset');
 const custom=createCitrixAdapter({indexUrl:`${base}custom`});assert.equal(custom.historicalCoverage,undefined);
 assert.equal(createCitrixAdapter({sitemapUrl:`${base}custom.xml`}).historicalCoverage,undefined);
 assert.equal((await custom.discover(context({[`${base}custom`]:`<a href="${detail(10000)}">bulletin</a>`}))).length,1);
});

test('excess nesting and unexpected sitemap entries cannot claim full history',async()=>{
 const pages={};for(let depth=0;depth<10;depth++)pages[depth===0?`${base}sitemap.xml`:`${base}depth${depth}.xml`]=index([`${base}depth${depth+1}.xml`]);
 await assert.rejects(createCitrixAdapter().discover(context(pages)),/depth limit/);
 await assert.rejects(createCitrixAdapter().discover(context({[`${base}sitemap.xml`]:`<urlset><url><loc>${detail(10000)}</loc></url><unknown><loc>${detail(10001)}</loc></unknown></urlset>`})),/unresolved entry/);
});

test('truncated security, CVE and vendor advisory slugs remain discovery candidates',async()=>{
 const urls=[
  `${base}external/article/CTX675851/citrix-workspace-app-for-mac-security-bu.html`,
  `${base}external/article/CTX616982/citrix-hypervisor-security-update-for-cv.html`,
  `${base}external/article/CTX633151/xenserver-and-citrix-hypervisor-security.html`,
  `${base}external/article/CTX677069/cloud-software-group-security-advisory-f.html`,
  `${base}external/article/CTX696604/netscaler-adc-and-netscaler-gateway-secu.html`,
 ];
 const adapter=createCitrixAdapter();
 const refs=await adapter.discover(context({[`${base}sitemap.xml`]:urlset(urls)}));
 assert.deepEqual(refs.map(ref=>ref.url),urls);assert.equal(adapter.historicalCoverage,undefined);
});

test('candidate normalization accepts declared CVE bulletins and skips explicitly ordinary support Articles',async()=>{
 const adapter=createCitrixAdapter();
 const normalize=body=>adapter.normalize({body,ref:{id:'CTX10000',url:detail(10000)},resolvedUrl:detail(10000),contentType:'text/html',fetchedAt:new Date().toISOString()},{observedAt:new Date().toISOString(),sanitizeText:value=>typeof value==='string'?value:undefined});
 const page=(headline,keywords=[],body='CVE-2026-12345')=>`<html><head><script type="application/ld+json">${JSON.stringify({'@type':'Article',headline,keywords,name:'Product',datePublished:'2026-06-30'})}</script></head><body><main>${body}</main></body></html>`;
 for(const title of ['Product Security Bulletin','Product Security Advisory','Product Security Update'])assert.equal((await normalize(page(title))).length,1);
 assert.equal((await normalize(page('Product issue',['Security Bulletin','NetScaler']))).length,1);
 assert.deepEqual(await normalize(page('How to configure security settings',['How To'])),[]);
 assert.deepEqual(await normalize(page('How to install a security update',['How To'])),[]);
 assert.deepEqual(await normalize(page('Troubleshooting CVE-2026-12345 detection',['Troubleshooting'])),[]);
 assert.deepEqual(await normalize(page('Product network configuration',[],'Help content')),[]);
 await assert.rejects(normalize('<html><h1>Just a moment</h1></html>'),/challenge/);
 await assert.rejects(normalize('<html><h1>Product security bulletin CVE-2026-12345</h1></html>'),/metadata/);
 await assert.rejects(normalize(page('Product vulnerability information')),/ambiguous/);
 await assert.rejects(normalize(page('Security Bulletin',[],'Content unavailable')),/no CVE context/);
});

test('explicit initial publication governs rolling scope while later metadata remains the update date',async()=>{
 const body=`<html><head><script type="application/ld+json">${JSON.stringify({'@type':'Article',headline:'Product Security Bulletin',datePublished:'2026-07-20T14:33:00Z',dateModified:'2026-07-20T14:33:00Z'})}</script></head><body><main>CVE-2026-12345<table><tr><th>Date</th><th>Change</th></tr><tr><td>2026-07-20</td><td>Updated fixed versions</td></tr><tr><td>2026-06-30</td><td>Initial Publication</td></tr></table></main></body></html>`;
 const [advisory]=await createCitrixAdapter().normalize({body,ref:{id:'CTX10000',url:detail(10000)},resolvedUrl:detail(10000),contentType:'text/html',fetchedAt:new Date().toISOString()},{observedAt:new Date().toISOString(),sanitizeText:value=>typeof value==='string'?value:undefined});
 assert.equal(advisory.publishedAt,'2026-06-30T00:00:00.000Z');assert.equal(advisory.sourceUpdatedAt,'2026-07-20T14:33:00.000Z');
 assert.equal(advisory.cves[0].publishedAt,advisory.publishedAt);
});
