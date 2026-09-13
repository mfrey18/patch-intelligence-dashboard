import type { Database, StatementResult } from "../../db/database";
import { stat, statfs } from "node:fs/promises";
import { EPSS_DAILY_RETENTION_DAYS, INTELLIGENCE_WINDOW_MONTHS, rollingWindowStart } from "../ingestion/operational-policy";
import { queryDashboard } from "../api/dashboard-query";

export async function capturePostgresProductionBaseline(db: Database) {
  const tables = await db.prepare("SELECT relname AS name, pg_total_relation_size(relid)::bigint AS bytes, n_live_tup AS estimated_rows FROM pg_stat_user_tables ORDER BY pg_total_relation_size(relid) DESC").all();
  const size = await db.prepare("SELECT pg_database_size(current_database())::bigint AS bytes, (SELECT count(*) FROM pg_stat_activity WHERE datname=current_database()) AS connections").first<{ bytes: number; connections: number }>();
  const indexes = await db.prepare("SELECT indexname AS name,tablename AS table_name,indexdef AS sql FROM pg_indexes WHERE schemaname='public' ORDER BY tablename,indexname").all();
  const started = performance.now();
  await queryDashboard(db,new URL("https://health.invalid/api/dashboard?include=core&limit=1"));
  let diskFreeBytes: number | null = null;
  let lastBackupAt: string | null = null;
  let lastRestoreAt: string | null = null;
  try { const disk = await statfs(process.env.PATCH_DATA_ROOT ?? process.cwd()); diskFreeBytes = disk.bavail * disk.bsize; } catch { /* Report unavailable, not zero. */ }
  try { lastBackupAt = (await stat(`${process.env.PATCH_DATA_ROOT}/backups/latest-success.json`)).mtime.toISOString(); } catch { /* No verified backup yet. */ }
  try { lastRestoreAt = (await stat(`${process.env.PATCH_DATA_ROOT}/backups/latest-restore.json`)).mtime.toISOString(); } catch { /* Restore not verified. */ }
  return { capturedAt: new Date().toISOString(), databaseEngine: "postgresql", databaseBytes: Number(size?.bytes ?? 0), connections: Number(size?.connections ?? 0), tables: tables.results, indexes: indexes.results,
    intelligenceWindowMonths: INTELLIGENCE_WINDOW_MONTHS, dashboardCoreLatencyMs: Math.round(performance.now()-started), diskFreeBytes, lastBackupAt, lastRestoreAt,
    backupStale: !lastBackupAt || Date.now()-Date.parse(lastBackupAt)>36*3600000 };
}

export async function pruneRollingRetention(db: Database, now = new Date()): Promise<{ cutoff: string; dailyCutoff: string; epssObservations: number; epssDatasets: number; completedCheckpoints: number; abandonedRuns: number; expiredLeases: number; preservedAuditHistory: true }> {
  const cutoff = rollingWindowStart(now).toISOString().slice(0, 10);
  const dailyCutoff = new Date(now.getTime() - EPSS_DAILY_RETENTION_DAYS * 86_400_000).toISOString().slice(0, 10);
  const checkpointCutoff = new Date(now.getTime() - 30 * 86_400_000).toISOString();
  const expiredObservations = await db.prepare("DELETE FROM epss_observations WHERE score_date < ?").bind(cutoff).run();
  const downsampledObservations = await db.prepare(`DELETE FROM epss_observations
    WHERE score_date>=? AND score_date<? AND score_date NOT IN (
      SELECT MAX(score_date) FROM epss_datasets
      WHERE score_date>=? AND score_date<? AND status='published'
      GROUP BY date_trunc('week',score_date)
    )`).bind(cutoff, dailyCutoff, cutoff, dailyCutoff).run();
  const datasets = await db.prepare("DELETE FROM epss_datasets WHERE is_current=FALSE AND NOT EXISTS(SELECT 1 FROM epss_observations eo WHERE eo.score_date=epss_datasets.score_date)").run();
  const checkpoints = await db.prepare("DELETE FROM ingestion_checkpoints WHERE status='complete' AND completed_at < ?").bind(checkpointCutoff).run();
  const abandonedRuns = await db.prepare("UPDATE source_runs SET status='failed', completed_at=?, records_failed=GREATEST(records_failed,1), error_summary=COALESCE(error_summary,'Ingestion lease expired before the run completed') WHERE status='running' AND started_at < ?").bind(now.toISOString(), new Date(now.getTime() - 15 * 60_000).toISOString()).run();
  const leases = await db.prepare("DELETE FROM ingestion_leases WHERE expires_at < ?").bind(now.toISOString()).run();
  return { cutoff, dailyCutoff, epssObservations: changes(expiredObservations) + changes(downsampledObservations), epssDatasets: changes(datasets), completedCheckpoints: changes(checkpoints), abandonedRuns: changes(abandonedRuns), expiredLeases: changes(leases), preservedAuditHistory: true };
}

function changes(result: StatementResult): number { return result.meta.changes; }
