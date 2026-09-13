import { test } from 'node:test';
import assert from 'node:assert/strict';
import { testDatabase } from './database.mjs';
import { seedIngestionCatalog, PostgresIngestionRepository } from '../../lib/ingestion/postgres-repository.ts';
import { queryDashboard, queryDashboardAnalytics, DASHBOARD_ANALYTICS_PANELS } from '../../lib/api/dashboard-query.ts';
import { refreshDashboardProjection } from '../../lib/operations/dashboard-projection.ts';
import { queryCveDetail } from '../../lib/api/cve-query.ts';
import { captureOperationalMonitor } from '../../lib/operations/operational-monitor.ts';
import { capturePostgresProductionBaseline, pruneRollingRetention } from '../../lib/operations/postgres-health.ts';
import { makeAdvisory } from '../fixtures/normalized-advisory.mjs';

test('PostgreSQL schema, ingestion, queries, projections, and rollback', async () => {
  const db = await testDatabase();
  try {
    await seedIngestionCatalog(db);
    const empty = await queryDashboard(db,new URL('https://test/api/dashboard'));
    assert.equal(empty.metrics.total,0);
    const repo = new PostgresIngestionRepository(db);
    const {runId} = await repo.beginRun('microsoft-msrc-csaf','integration',{mode:'delta',maxItems:12});
    const advisory = makeAdvisory({ sourceId: "microsoft-msrc-csaf" });
    advisory.publishedAt = new Date().toISOString(); advisory.sourceUpdatedAt = advisory.publishedAt;
    assert.equal(await repo.saveAdvisory(runId,advisory,['NEW_CVE']),'inserted');
    assert.equal(await repo.saveAdvisory(runId,advisory,[]),'unchanged');
    const canonical = await queryDashboard(db,new URL('https://test/api/dashboard'));
    assert.ok(canonical.metrics.total>0);
    await refreshDashboardProjection(db);
    const projected = await queryDashboard(db,new URL('https://test/api/dashboard'));
    assert.deepEqual(projected.metrics,canonical.metrics);
    for (const panel of DASHBOARD_ANALYTICS_PANELS) await queryDashboardAnalytics(db,new URL('https://test/api/dashboard'),panel);
    for (const filter of ['q=MICROSOFT','publishedTo=2099-01-01','kev=false','patchAvailable=true','priority=P1','view=changed','vendor=microsoft','product=windows','sort=epss']) await queryDashboard(db,new URL(`https://test/api/dashboard?${filter}`));
    assert.ok(await queryCveDetail(db, advisory.cves[0].cveId));
    await captureOperationalMonitor(db);
    await capturePostgresProductionBaseline(db);
    await pruneRollingRetention(db);
    await assert.rejects(db.transaction(async tx => {await tx.prepare("INSERT INTO cves(id,created_at,updated_at) VALUES ('rollback',now(),now())").run();throw Error('rollback');}));
    assert.equal(await db.prepare("SELECT id FROM cves WHERE id='rollback'").first(),null);
    const b={...advisory,title:'Changed title'};
    assert.equal(await repo.saveAdvisory(runId,b,['ADVISORY_REVISED']),'changed');
    assert.equal(await repo.saveAdvisory(runId,advisory,['ADVISORY_REVISED']),'changed');
  } finally { await db.close(); }
});
