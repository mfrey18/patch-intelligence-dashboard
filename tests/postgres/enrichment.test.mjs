import {test} from 'node:test';
import assert from 'node:assert/strict';
import {gzipSync} from 'node:zlib';
import {testDatabase} from './database.mjs';
import {seedIngestionCatalog,PostgresIngestionRepository} from '../../lib/ingestion/postgres-repository.ts';
import {ingestCisaKev} from '../../lib/ingestion/enrichments/cisa.ts';
import {ingestEpssBulk} from '../../lib/ingestion/enrichments/epss.ts';
import {queryCveDetail} from '../../lib/api/cve-query.ts';
import {refreshDashboardProjection} from '../../lib/operations/dashboard-projection.ts';
import {makeAdvisory} from '../fixtures/normalized-advisory.mjs';

test('KEV and EPSS use native types and preserve the last snapshot on failed publication',async()=>{
 const db=await testDatabase();const original=globalThis.fetch;
 const today=new Date().toISOString().slice(0,10);const id='CVE-2026-1000';
 try{
  await seedIngestionCatalog(db);
  const payload={catalogVersion:'test',dateReleased:`${today}T12:00:00Z`,count:1,vulnerabilities:[{cveID:id,vendorProject:'Example',product:'Example',vulnerabilityName:'Example',dateAdded:today,shortDescription:'Example',requiredAction:'Apply vendor guidance',dueDate:today,cwes:[]}]};
  globalThis.fetch=async()=>new Response(JSON.stringify(payload));
  assert.equal((await ingestCisaKev(db,'kev-test')).status,'success');
  assert.equal((await db.prepare('SELECT active FROM kev_entries WHERE cve_id=?').bind(id).first()).active,true);
  const csv=`#model_version:v1,score_date:${today}\ncve,epss,percentile\n${id},0.5,0.95\n`;
  globalThis.fetch=async()=>new Response(gzipSync(csv));
  assert.equal((await ingestEpssBulk(db,'epss-test',{url:'https://test.invalid/scores',minimumRows:1})).status,'success');
  const cve=await queryCveDetail(db,id);assert.equal(cve.epss.current.scoreDate,today);assert.equal(cve.epss.current.percentile,0.95);
  assert.equal((await ingestEpssBulk(db,'epss-repeat',{url:'https://test.invalid/scores',minimumRows:1})).status,'unchanged');
  // A same-date changed feed that fails mid-write must not change the published dataset.
  await db.prepare("ALTER TABLE epss_observations ADD CONSTRAINT test_reject_high_score CHECK (score<0.8)").run();
  globalThis.fetch=async()=>new Response(gzipSync(csv.replace('0.5,0.95','0.9,0.99')));
  assert.equal((await ingestEpssBulk(db,'epss-fail',{url:'https://test.invalid/scores',minimumRows:1})).status,'failed');
  assert.equal((await queryCveDetail(db,id)).epss.current.percentile,0.95);
  assert.equal((await db.prepare('SELECT status,is_current FROM epss_datasets').first()).is_current,true);
 }finally{globalThis.fetch=original;await db.close();}
});

test('Projection parity failure rolls back staging and preserves published facts',async()=>{
 const db=await testDatabase();try{
  await seedIngestionCatalog(db);const repo=new PostgresIngestionRepository(db);
  const {runId}=await repo.beginRun('microsoft-msrc-csaf','projection-fixture',{mode:'delta',maxItems:12});
  await repo.saveAdvisory(runId,makeAdvisory({sourceId:'microsoft-msrc-csaf',publishedAt:new Date().toISOString()}),['NEW_CVE']);
  await refreshDashboardProjection(db);
  const before=(await db.prepare('SELECT * FROM cve_dashboard_facts').all()).results;
  await db.prepare('CREATE FUNCTION test_skip_projection() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$').run();
  await db.prepare('CREATE TRIGGER test_skip BEFORE INSERT ON cve_dashboard_facts_staging FOR EACH ROW EXECUTE FUNCTION test_skip_projection()').run();
  await assert.rejects(refreshDashboardProjection(db),/parity failed/);
  assert.deepEqual((await db.prepare('SELECT * FROM cve_dashboard_facts').all()).results,before);
  assert.equal((await db.prepare("SELECT last_attempt_status FROM dashboard_projection_state WHERE id='current'").first()).last_attempt_status,'failed');
  assert.equal((await db.prepare('SELECT count(*) count FROM cve_dashboard_facts_staging').first()).count,0);
 }finally{await db.close();}
});
