import { test } from 'node:test';
import assert from 'node:assert/strict';
import { testDatabase } from './database.mjs';
import { seedIngestionCatalog } from '../../lib/ingestion/postgres-repository.ts';
import { queryDashboard } from '../../lib/api/dashboard-query.ts';
import { captureOperationalMonitor } from '../../lib/operations/operational-monitor.ts';

test('PostgreSQL monitoring keeps scheduled Cisco partial progress pending until its checkpoint completes', async () => {
  const db = await testDatabase();
  try {
    await seedIngestionCatalog(db);
    await db.prepare(`INSERT INTO ingestion_checkpoints
      (id,source_id,mode,coverage_start,coverage_end,window_start,window_end,continuation_token,status,created_at,updated_at,completed_at)
      VALUES
      ('daily:cisco-psirt-csaf:previous','cisco-psirt-csaf','delta','2026-08-21T00:00:00Z','2026-08-21T23:59:59Z','2026-08-21T00:00:00Z','2026-08-21T23:59:59Z',NULL,'complete','2026-08-26T10:00:00Z','2026-08-26T11:00:00Z','2026-08-26T11:00:00Z'),
      ('daily:cisco-psirt-csaf:oldest','cisco-psirt-csaf','delta','2026-08-25T00:00:00Z','2026-08-25T23:59:59Z','2026-08-25T00:00:00Z','2026-08-25T23:59:59Z','offset:5','pending','2026-08-26T09:00:00Z','2026-08-26T11:30:00Z',NULL),
      ('daily:cisco-psirt-csaf:today','cisco-psirt-csaf','delta','2026-08-26T00:00:00Z','2026-08-26T23:59:59Z','2026-08-26T00:00:00Z','2026-08-26T23:59:59Z','offset:4','pending','2026-08-26T10:00:00Z','2026-08-26T11:45:00Z',NULL),
      ('manual:cisco-later','cisco-psirt-csaf','delta','2026-08-24T00:00:00Z','2026-08-24T23:59:59Z','2026-08-24T00:00:00Z','2026-08-24T23:59:59Z','offset:9','pending','2026-08-26T11:50:00Z','2026-08-26T11:55:00Z',NULL)`).run();
    await db.prepare(`INSERT INTO source_runs
      (id,source_id,idempotency_key,started_at,completed_at,status,ingestion_mode,window_start,window_end,continuation_in,continuation_out,checkpoint_id,max_items,bound_hit,records_discovered,records_inserted,records_changed,records_unchanged,records_failed)
      VALUES
      ('cisco-stalled-1','cisco-psirt-csaf','cisco-stalled-1','2026-08-26T11:10:00Z','2026-08-26T11:11:00Z','partial','delta','2026-08-25T00:00:00Z','2026-08-25T23:59:59Z','offset:4','offset:4','daily:cisco-psirt-csaf:oldest',1,TRUE,1,1,0,0,0),
      ('cisco-stalled-2','cisco-psirt-csaf','cisco-stalled-2','2026-08-26T11:12:00Z','2026-08-26T11:13:00Z','partial','delta','2026-08-25T00:00:00Z','2026-08-25T23:59:59Z','offset:4','offset:4','daily:cisco-psirt-csaf:oldest',1,TRUE,1,1,0,0,0),
      ('cisco-progress','cisco-psirt-csaf','cisco-progress','2026-08-26T11:20:00Z','2026-08-26T11:30:00Z','partial','delta','2026-08-25T00:00:00Z','2026-08-25T23:59:59Z','offset:4','offset:5','daily:cisco-psirt-csaf:oldest',1,TRUE,1,1,0,0,0)`).run();

    const monitored = await captureOperationalMonitor(db, new Date('2026-08-26T12:00:00Z'), async () => 1);
    const cisco = monitored.sources.find((source) => source.sourceId === 'cisco-psirt-csaf');
    assert.equal(cisco.lastSuccess, '2026-08-26T11:00:00.000Z');
    assert.equal(cisco.pending, true);
    assert.equal(cisco.pendingStalledAttempts, 1);
    assert.ok(!monitored.alerts.some((alert) => alert.sourceId === 'cisco-psirt-csaf' && alert.code === 'source_pending_stalled'));
    assert.ok(!monitored.alerts.some((alert) => alert.sourceId === 'cisco-psirt-csaf' && alert.code === 'source_repeated_bound_hits'));
    assert.ok(monitored.alerts.some((alert) => alert.sourceId === 'cisco-psirt-csaf' && alert.code === 'source_stale'));

    const dashboard = await queryDashboard(db, new URL('https://test/api/dashboard?include=core&limit=1'));
    const source = dashboard.sourceHealth.find((row) => row.sourceId === 'cisco-psirt-csaf');
    assert.equal(source.lastSuccess, '2026-08-26T11:00:00.000Z');
    assert.equal(source.pending, true);
    assert.equal(source.checkpoint.id, 'daily:cisco-psirt-csaf:oldest');
    assert.equal(source.checkpoint.status, 'pending');
    assert.equal(source.freshness, 'stale');

    // With no earlier successful progress, repeated positions still alert
    // without requiring a non-null progress timestamp.
    await db.prepare("DELETE FROM source_runs WHERE id='cisco-progress'").run();
    const stalled = await captureOperationalMonitor(db, new Date('2026-08-26T12:00:00Z'), async () => 1);
    assert.ok(stalled.alerts.some(alert => alert.code === 'source_pending_stalled'));
    await db.prepare("UPDATE source_runs SET continuation_out='offset:5',completed_at='2026-08-26T11:50:00Z' WHERE id='cisco-stalled-2'").run();
    const recovered = await captureOperationalMonitor(db, new Date('2026-08-26T12:00:00Z'), async () => 1);
    assert.ok(!recovered.alerts.some(alert => alert.code === 'source_pending_stalled'));

    // A newer pending checkpoint cannot hide the oldest failed checkpoint.
    await db.prepare("UPDATE ingestion_checkpoints SET status='failed',created_at='2026-08-24T00:00:00Z' WHERE id='daily:cisco-psirt-csaf:oldest'").run();
    const failed = await captureOperationalMonitor(db, new Date('2026-08-26T12:00:00Z'), async () => 1);
    assert.equal(failed.sources.find(row => row.sourceId === 'cisco-psirt-csaf').pending, false);
    assert.ok(failed.alerts.some(alert => alert.code === 'source_scheduled_checkpoint_failed'));
    assert.ok(failed.alerts.some(alert => alert.code === 'source_pending_backlog_stale'));
    const failedDashboard = await queryDashboard(db, new URL('https://test/api/dashboard?include=core&limit=1'));
    assert.equal(failedDashboard.sourceHealth.find(row => row.sourceId === 'cisco-psirt-csaf').result, 'failed');
  } finally {
    await db.close();
  }
});
