import test from 'node:test';
import assert from 'node:assert/strict';
import {testDatabase} from './database.mjs';
import {seedIngestionCatalog,PostgresIngestionRepository} from '../../lib/ingestion/postgres-repository.ts';
import {saveCveEnrichment,parseCveRecord,parseNvdRecord,selectCanonical} from '../../lib/ingestion/enrichments/cve.ts';
import {parseVulnCheckSnapshot,publishVulnCheckSnapshot} from '../../lib/ingestion/enrichments/vulncheck.ts';
import {queryDashboard} from '../../lib/api/dashboard-query.ts';
import {refreshDashboardProjection} from '../../lib/operations/dashboard-projection.ts';
import {queryCveDetail} from '../../lib/api/cve-query.ts';
import {runVendorAdapter} from '../../lib/ingestion/pipeline.ts';

const cve='CVE-2026-12345';
function cna(status='PUBLISHED') {return parseCveRecord({cveMetadata:{cveId:cve,state:status,datePublished:new Date().toISOString(),dateUpdated:new Date().toISOString()},containers:{cna:{providerMetadata:{shortName:'test'},descriptions:[{lang:'en',value:'A vulnerability with canonical source provenance.'}],metrics:[{cvssV3_1:{version:'3.1',baseScore:9.8,vectorString:'CVSS:3.1/test'}},{cvssV4_0:{version:'4.0',baseScore:8.7,vectorString:'CVSS:4.0/test'}}],problemTypes:[{descriptions:[{cweId:'CWE-79'}]}]}}},'https://raw.githubusercontent.com/CVEProject/cvelistV5/abc/test.json');}
function snapshot(ids=[cve]) {return parseVulnCheckSnapshot({data:ids.map(id=>({cve:[id],date_added:new Date().toISOString(),vulncheck_xdb:[{xdb_url:'https://vulncheck.com/xdb/test'}],vulncheck_reported_exploitation:[{url:'https://example.com/evidence',date_added:new Date().toISOString()}]}))});}

test('VulnCheck scope, canonical fallback, source filters, rejection and projection parity',async()=>{
 const db=await testDatabase();try{
 await seedIngestionCatalog(db);
 const repo=new PostgresIngestionRepository(db);
 const {runId}=await repo.beginRun('vulncheck-kev',undefined,{mode:'delta',maxItems:1});
 const entries=snapshot();await publishVulnCheckSnapshot(db,runId,entries);
 assert.equal((await publishVulnCheckSnapshot(db,runId,entries)).unchanged,1);
 const {runId:cr}=await repo.beginRun('cve-list-v5',undefined,{mode:'delta',maxItems:1});
 const record=cna();assert.equal(await saveCveEnrichment(db,'cve-list-v5',cr,record),true);
 assert.equal(await saveCveEnrichment(db,'cve-list-v5',cr,record),false);
 let data=await queryDashboard(db,new URL('http://local/api/dashboard?vulncheck=true&severity=high&exploitationSource=vulncheck-kev'));
 assert.equal(data.metrics.total,1);assert.equal(data.metrics.kev,0);assert.equal(data.metrics.knownExploited,1);assert.equal(data.metrics.zeroDay,0);assert.equal(data.rows[0].cvss,8.7);assert.equal(data.rows[0].vulncheck,true);
 const filteredUrl=new URL('http://local/api/dashboard?q=canonical&publishedFrom='+new Date().toISOString().slice(0,10));
 assert.equal((await queryDashboard(db,filteredUrl)).metrics.total,1);
 await refreshDashboardProjection(db);
 assert.equal((await queryDashboard(db,filteredUrl)).metrics.total,1);
 data=await queryDashboard(db,new URL('http://local/api/dashboard?vulncheck=true&severity=high&exploitationSource=vulncheck-kev'));
 assert.equal(data.rows.length,1);assert.deepEqual(data.rows[0].exploitationSources,['vulncheck-kev']);
 const detail=await queryCveDetail(db,cve);assert.equal(detail.canonical.status,'published');assert.equal(detail.enrichment.length,1);assert.equal(detail.vulncheck.active,true);assert.equal(detail.kev,null);
 const rejected={...record,status:'rejected',modifiedAt:new Date(Date.now()+1000).toISOString()};await saveCveEnrichment(db,'cve-list-v5',cr,rejected);
 await refreshDashboardProjection(db);assert.equal((await queryDashboard(db,new URL('http://local/api/dashboard'))).metrics.total,0);
 assert.equal((await queryCveDetail(db,cve)).canonical.status,'rejected');
 }finally{await db.close();}
});

test('failed discovery batches retry the persisted page without dropping work',async()=>{
 const db=await testDatabase();try{
 await seedIngestionCatalog(db);const repo=new PostgresIngestionRepository(db);let discoveries=0,fail=true;
 const adapter={vendor:'oracle',sourceId:'oracle-cpu-csaf',async discover(){throw Error('unexpected');},async discoverPage(){discoveries++;return {refs:[{id:'one',url:'https://oracle.com/one'}],nextCursor:'next'};},async fetch(ref){if(fail)throw Error('temporary');return{ref};},async normalize(){return[{vendor:'oracle',sourceId:'oracle-cpu-csaf',vendorAdvisoryId:'one',title:'Oracle test',sourceUrl:'https://oracle.com/one',publishedAt:new Date().toISOString(),exploitationStatus:'unknown',zeroDayStatus:'unknown',cves:[],affectedProducts:[],remediations:[],exploitEvidence:[]}];}};
 const options={checkpointId:'test-page',idempotencyKey:'page-start',since:new Date().toISOString(),until:new Date().toISOString()};
 const first=await runVendorAdapter(adapter,repo,options);assert.equal(first.counts.failed,1);fail=false;
 const second=await runVendorAdapter(adapter,repo,options);assert.equal(second.counts.failed,0);assert.equal(discoveries,1);assert.match(second.continuation,/^page:/);
 await runVendorAdapter(adapter,repo,{...options,idempotencyKey:"new-replay",discoveryGeneration:"new-replay"});assert.equal(discoveries,2);
 }finally{await db.close();}
});

test('CNA score precedence, source regression, and missing snapshot validation',()=>{
 const c=cna();const n=parseNvdRecord({vulnerabilities:[{cve:{id:cve,metrics:{cvssMetricV31:[{source:'nvd@nist.gov',cvssData:{version:'3.1',baseScore:10}}]}}}]},'https://nvd.nist.gov/vuln/detail/'+cve);
 assert.equal(selectCanonical([n,c]).assessment.score,8.7);
 assert.throws(()=>parseVulnCheckSnapshot({data:[]}));
 assert.throws(()=>parseVulnCheckSnapshot({data:[{cve:[cve],date_added:'bad'}]}));
});

test('membership removal retains history and partial snapshots cannot remove entries',async()=>{
 const db=await testDatabase();try{
 await seedIngestionCatalog(db);const repo=new PostgresIngestionRepository(db);const {runId}=await repo.beginRun('vulncheck-kev',undefined,{mode:'delta',maxItems:1});
 const a=snapshot([cve,'CVE-2026-12346']);await publishVulnCheckSnapshot(db,runId,a);assert.equal((await publishVulnCheckSnapshot(db,runId,[a[0]])).changed,1);
 assert.equal((await db.prepare('SELECT active FROM vulncheck_entries WHERE cve_id=?').bind('CVE-2026-12346').first()).active,false);
 assert.equal((await queryCveDetail(db,'CVE-2026-12346')).exploitation.knownExploited,true);
 // A malformed input is rejected before publication, leaving current membership unchanged.
 assert.throws(()=>parseVulnCheckSnapshot({data:[{cve:[cve],date_added:'invalid'}]}));
 assert.equal((await db.prepare('SELECT active FROM vulncheck_entries WHERE cve_id=?').bind(cve).first()).active,true);
 }finally{await db.close();}
});

test('source readiness survives seeding; cooldown persists; interrupted runs recover',async()=>{
 const db=await testDatabase();try{
 await seedIngestionCatalog(db);
 const {setSourceReadiness}=await import('../../lib/ingestion/source-readiness.ts');
 await assert.rejects(setSourceReadiness(db,'red-hat-csaf','production'),/two completed delta/);
 await setSourceReadiness(db,'red-hat-csaf','paused','Operator paused validation');await seedIngestionCatalog(db);
 assert.equal((await db.prepare("SELECT readiness FROM sources WHERE id='red-hat-csaf'").first()).readiness,'paused');
 const repo=new PostgresIngestionRepository(db),deadline=new Date(Date.now()+7200000).toISOString();await repo.deferSource('nvd-cve',deadline);
 assert.equal((await db.prepare("SELECT retry_after FROM sources WHERE id='nvd-cve'").first()).retry_after,deadline);
 const first=await repo.beginRun('oracle-cpu-csaf','interrupted',{mode:'delta',maxItems:1});
 await db.prepare("UPDATE source_runs SET started_at=now()-INTERVAL '20 minutes' WHERE id=?").bind(first.runId).run();
 const retry=await repo.beginRun('oracle-cpu-csaf','interrupted',{mode:'delta',maxItems:1});assert.notEqual(retry.runId,first.runId);
 }finally{await db.close();}
});

test('Red Hat index excludes non-security bulletins and validates paths',async()=>{
 const {parseRedHatChanges}=await import('../../lib/ingestion/adapters/red-hat.ts');
 const refs=parseRedHatChanges('"2026/rhsa-2026_1.json","2026-09-16T00:00:00Z"\n"2026/rhba-2026_2.json","2026-09-16T00:00:00Z"');
 assert.equal(refs.length,1);assert.match(refs[0].url,/rhsa-/);
 assert.throws(()=>parseRedHatChanges('"../private.json","2026-09-16T00:00:00Z"'));
});
