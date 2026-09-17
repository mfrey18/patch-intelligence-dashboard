import type { Database } from '../../db/database';
import { SOURCE_CATALOG, type SourceReadiness } from './source-catalog';
export async function setSourceReadiness(db:Database,id:string,state:SourceReadiness,reason:string|null=null) {
  const source=SOURCE_CATALOG.find(s=>s.id===id);
  if(!source)throw new Error('Unknown source');
  if(!['pending_feed','pending_credentials','validating','production','paused'].includes(state))throw new Error('Invalid readiness state');
  if(state==='production') {
    const cycles=await db.prepare("SELECT COUNT(DISTINCT started_at::date) count FROM source_runs WHERE source_id=? AND ingestion_mode='delta' AND status IN ('success','unchanged') AND records_failed=0 AND bound_hit=FALSE AND started_at>now()-INTERVAL '7 days'").bind(id).first<{count:number}>();
    if(Number(cycles?.count)<2)throw new Error('Promotion requires two completed delta cycles on distinct dates within seven days');
    if(source.kind==='vendor_advisory') {
      const replay=await db.prepare("SELECT id FROM ingestion_checkpoints WHERE source_id=? AND mode='backfill' AND status='complete' AND coverage_start<=now()-INTERVAL '6 months'+INTERVAL '7 days' AND coverage_end>=now()-INTERVAL '7 days' LIMIT 1").bind(id).first();
      if(!replay)throw new Error('Promotion requires a completed six-month backfill');
    }
    const records=await db.prepare('SELECT COALESCE(SUM(records_inserted+records_changed),0) count FROM source_runs WHERE source_id=? AND records_failed=0').bind(id).first<{count:number}>();
    if(!Number(records?.count))throw new Error('Zero records are not evidence of usable coverage');
  }
  await db.prepare('UPDATE sources SET readiness=?,readiness_reason=?,enabled=?,updated_at=now() WHERE id=?').bind(state,reason,state==='production',id).run();
}
