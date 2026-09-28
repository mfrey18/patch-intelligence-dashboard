import type { Database } from '../../db/database';
import { SOURCE_CATALOG, type SourceReadiness } from './source-catalog';

/** Only durable completed cycles can promote a source; successful batches cannot. */
export async function setSourceReadiness(db:Database,id:string,state:SourceReadiness,reason:string|null=null) {
  const source=SOURCE_CATALOG.find(s=>s.id===id);
  if(!source)throw new Error('Unknown source');
  if(!['pending_feed','pending_credentials','validating','production','paused'].includes(state))throw new Error('Invalid readiness state');
  await db.transaction(async tx=>{
    await tx.prepare('SELECT id FROM sources WHERE id=? FOR UPDATE').bind(id).run();
    if(state==='production') {
      const lease=await tx.prepare('SELECT holder FROM ingestion_leases WHERE source_id=? AND expires_at>now()').bind(id).first();
      if(lease)throw new Error('Promotion requires source ingestion to finish');
      const latest=await tx.prepare('SELECT status,records_failed,bound_hit FROM source_runs WHERE source_id=? ORDER BY started_at DESC,id DESC LIMIT 1').bind(id).first<{status:string;records_failed:number;bound_hit:boolean}>();
      if(latest && (latest.status==='failed' || latest.status==='running' || Number(latest.records_failed)>0 || latest.bound_hit))throw new Error('Promotion requires the latest source attempt to finish without failures');
      const cycles=await tx.prepare(`SELECT COUNT(DISTINCT (completed_at AT TIME ZONE 'UTC')::date) count,
        MAX(coverage_end) coverage_end FROM source_completion_evidence
        WHERE source_id=? AND kind='delta' AND completed_at>now()-INTERVAL '7 days'`).bind(id).first<{count:number;coverage_end:string|null}>();
      if(Number(cycles?.count)<2)throw new Error('Promotion requires two completed delta cycles on distinct UTC dates within seven days');
      if(!cycles?.coverage_end || Date.parse(cycles.coverage_end)<Date.now()-36*3_600_000)throw new Error('Promotion requires fresh completed source coverage');
      const incomplete=await tx.prepare(`SELECT 1 FROM ingestion_checkpoints WHERE source_id=? AND status<>'complete' AND retired_at IS NULL
        UNION ALL SELECT 1 FROM enrichment_cycles WHERE source_id=? AND completed_at IS NULL LIMIT 1`).bind(id,id).first();
      if(incomplete)throw new Error('Promotion requires unfinished source coverage to complete');
      if(source.kind==='vendor_advisory') {
        const backfill=await tx.prepare(`SELECT id FROM source_completion_evidence WHERE source_id=? AND kind='backfill' AND member_count>0
          AND coverage_start<=now()-INTERVAL '6 months'+INTERVAL '7 days' AND coverage_end>=now()-INTERVAL '7 days' LIMIT 1`).bind(id).first();
        if(!backfill)throw new Error('Promotion requires a completed six-month backfill with nonempty coverage evidence');
      }
      if(source.kind==='cve_enrichment') {
        const initial=await tx.prepare("SELECT id FROM source_completion_evidence WHERE source_id=? AND kind='initial_enrichment' AND member_count>0 LIMIT 1").bind(id).first();
        if(!initial)throw new Error('Promotion requires completion of the captured initial enrichment membership');
      }
      // Missing/rejected enrichment members may finish a queue but do not invent usable data.
      const usable=source.kind==='vendor_advisory'
        ? await tx.prepare(`SELECT COUNT(*) count FROM advisories a WHERE a.source_id=?
            AND EXISTS(SELECT 1 FROM advisory_cves ac WHERE ac.advisory_id=a.id)
            AND EXISTS(SELECT 1 FROM affected_products ap WHERE ap.advisory_id=a.id)
            AND EXISTS(SELECT 1 FROM remediations r WHERE r.advisory_id=a.id)`).bind(id).first<{count:number}>()
        : source.kind==='cve_enrichment'
          ? await tx.prepare('SELECT COUNT(*) count FROM cve_enrichments WHERE source_id=?').bind(id).first<{count:number}>()
          : await tx.prepare('SELECT COALESCE(SUM(records_inserted+records_changed),0) count FROM source_runs WHERE source_id=? AND records_failed=0').bind(id).first<{count:number}>();
      if(!Number(usable?.count))throw new Error('Zero records are not evidence of usable coverage; vendor evidence must include CVEs, affected products and remediation');
      const projection=await tx.prepare(`SELECT id FROM dashboard_projection_state p WHERE id='current' AND parity_status='passed' AND last_attempt_status='success' AND generated_at>now()-INTERVAL '36 hours'
        AND NOT EXISTS(SELECT 1 FROM source_runs r WHERE r.source_id=? AND (r.records_inserted>0 OR r.records_changed>0) AND r.completed_at>p.generated_at)`).bind(id).first();
      if(!projection)throw new Error('Promotion requires a fresh projection with passing canonical parity');
    }
    await tx.prepare('UPDATE sources SET readiness=?,readiness_reason=?,enabled=?,updated_at=now() WHERE id=?').bind(state,reason,state==='production',id).run();
  });
}
