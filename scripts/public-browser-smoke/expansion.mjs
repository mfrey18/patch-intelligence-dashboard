import assert from 'node:assert/strict';
import {mkdir} from 'node:fs/promises';
import {chromium} from '@playwright/test';
import {testDatabase} from '../../tests/postgres/database.mjs';
import {seedIngestionCatalog,PostgresIngestionRepository} from '../../lib/ingestion/postgres-repository.ts';
import {parseVulnCheckSnapshot,publishVulnCheckSnapshot} from '../../lib/ingestion/enrichments/vulncheck.ts';
import {parseCveRecord,saveCveEnrichment} from '../../lib/ingestion/enrichments/cve.ts';
import {createApiServer} from '../../server/index.ts';
import {ResponseCache} from '../../server/cache.ts';
const base='http://127.0.0.1:4179';
const db=await testDatabase();let server,browser;
try {
 await seedIngestionCatalog(db);const repo=new PostgresIngestionRepository(db);
 const {runId}=await repo.beginRun('vulncheck-kev',undefined,{mode:'delta',maxItems:1});
 const id='CVE-2026-99999',now=new Date().toISOString();
 await publishVulnCheckSnapshot(db,runId,parseVulnCheckSnapshot({data:[{cve:[id],date_added:now,vulnerabilityName:'Local test vulnerability',vulncheck_reported_exploitation:[{url:'https://example.com/evidence',date_added:now}]}]}));
 const {runId:cr}=await repo.beginRun('cve-list-v5',undefined,{mode:'delta',maxItems:1});
 await saveCveEnrichment(db,'cve-list-v5',cr,parseCveRecord({cveMetadata:{cveId:id,state:'PUBLISHED',datePublished:now,dateUpdated:now},containers:{cna:{providerMetadata:{shortName:'Fixture'},descriptions:[{lang:'en',value:'Local fixture: source-labelled vulnerability intelligence.'}],metrics:[{cvssV4_0:{version:'4.0',baseScore:8.7,vectorString:'CVSS:4.0/fixture'}}]}}},'https://raw.githubusercontent.com/CVEProject/cvelistV5/test/fixture.json'));
 server=createApiServer({DB:db,cache:new ResponseCache(),PUBLIC_DASHBOARD_ORIGINS:base},'public');await new Promise(resolve=>server.listen(4301,'127.0.0.1',resolve));
 browser=await chromium.launch();const page=await browser.newPage();const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await mkdir('work/source-expansion',{recursive:true});
 for(const width of [1440,390,320]) {
  await page.setViewportSize({width,height:1000});await page.goto(base);await page.getByText(id,{exact:true}).first().waitFor();
  await page.getByLabel('VulnCheck KEV',{exact:true}).selectOption('true');await page.waitForURL(/vulncheck=true/);
  await page.getByLabel('Exploitation source',{exact:true}).selectOption('vulncheck-kev');await page.waitForURL(/exploitationSource=vulncheck-kev/);
  assert.equal(await page.getByLabel('Vendor',{exact:true}).locator('option[value="red-hat"]').count(),1);
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth),true,`overflow at ${width}`);
  await page.screenshot({path:`work/source-expansion/dashboard-${width}.png`,fullPage:true});
 }
 await page.goto(`${base}/#/cve/${id}`);
 await page.getByRole('heading',{name:'CVE Enrichment',exact:true}).waitFor();
 await page.getByRole('heading',{name:'VulnCheck KEV',exact:true}).waitFor();
 await page.screenshot({path:'work/source-expansion/detail.png',fullPage:true});
 assert.deepEqual(errors,[]);console.log('Expansion browser checks passed: 3 widths, filters, Red Hat, enrichment and VulnCheck details.');
}finally{await browser?.close();if(server)await new Promise(resolve=>server.close(resolve));await db.close();}
