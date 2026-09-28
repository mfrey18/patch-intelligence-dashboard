import type { Database } from '../../db/database';

export interface EnrichmentCycle {
  id: string; source_id: string; kind: 'delta' | 'initial_enrichment';
  started_at: string; target_through: string; updates_from: string;
  updates_covered_through: string | null; member_count: number; source_revision: string | null;
}

/** Capture finite membership once. Later CVEs belong to the next cycle. */
export async function loadEnrichmentCycle(db: Database, sourceId: string, now = new Date().toISOString()): Promise<EnrichmentCycle> {
  return db.transaction(async tx => {
    await tx.prepare('SELECT id FROM sources WHERE id=? FOR UPDATE').bind(sourceId).first();
    const active = await tx.prepare('SELECT * FROM enrichment_cycles WHERE source_id=? AND completed_at IS NULL ORDER BY started_at,id LIMIT 1').bind(sourceId).first<EnrichmentCycle>();
    if (active) return active;
    const previous = await tx.prepare('SELECT target_through FROM enrichment_cycles WHERE source_id=? AND completed_at IS NOT NULL ORDER BY target_through DESC LIMIT 1').bind(sourceId).first<{target_through:string}>();
    const id = crypto.randomUUID();
    const from = new Date(previous ? Date.parse(previous.target_through)-86400000 : Date.parse(now)-3*86400000).toISOString();
    const kind = previous ? 'delta' : 'initial_enrichment';
    await tx.prepare('INSERT INTO enrichment_cycles(id,source_id,kind,started_at,target_through,updates_from,member_count) VALUES (?,?,?,?,?,?,0)').bind(id,sourceId,kind,now,now,from).run();
    await tx.prepare('INSERT INTO enrichment_queue(cve_id,source_id) SELECT id,? FROM cves ON CONFLICT DO NOTHING').bind(sourceId).run();
    // Initial cycles verify every retained CVE; later cycles capture stale and new members.
    await tx.prepare(`INSERT INTO enrichment_cycle_members(cycle_id,cve_id) SELECT ?,q.cve_id FROM enrichment_queue q
      WHERE q.source_id=? AND (? OR q.checked_at IS NULL OR q.checked_at<?::timestamptz-INTERVAL '7 days')`).bind(id,sourceId,!previous,now).run();
    await tx.prepare('UPDATE enrichment_cycles SET member_count=(SELECT COUNT(*) FROM enrichment_cycle_members WHERE cycle_id=?) WHERE id=?').bind(id,id).run();
    return (await tx.prepare('SELECT * FROM enrichment_cycles WHERE id=?').bind(id).first<EnrichmentCycle>())!;
  });
}

/** Change-feed discovery can add or invalidate members, only through the fixed target. */
export async function requireChangedMembers(db: Database, cycle: EnrichmentCycle, changes: Array<{id:string;modified:string}>) {
  await db.prepare(`INSERT INTO enrichment_cycle_members(cycle_id,cve_id,required_modified_through)
    SELECT ?,c.id,u.modified FROM cves c JOIN
      (SELECT value->>'id' id,MAX((value->>'modified')::timestamptz) modified FROM jsonb_array_elements(?::jsonb) GROUP BY value->>'id') u ON u.id=c.id
    WHERE u.modified<=?::timestamptz AND c.created_at<=?::timestamptz
    ON CONFLICT(cycle_id,cve_id) DO UPDATE SET required_modified_through=excluded.required_modified_through,
      required_generation=enrichment_cycle_members.required_generation+1
    WHERE enrichment_cycle_members.required_modified_through IS NULL OR enrichment_cycle_members.required_modified_through<excluded.required_modified_through`).bind(cycle.id,JSON.stringify(changes),cycle.target_through,cycle.started_at).run();
  await db.prepare('UPDATE enrichment_cycles SET member_count=(SELECT COUNT(*) FROM enrichment_cycle_members WHERE cycle_id=?) WHERE id=?').bind(cycle.id,cycle.id).run();
}

export async function enrichmentProgress(db: Database, cycle: EnrichmentCycle) {
  const remaining = await db.prepare(`SELECT COUNT(*) total,MIN(retry_at) retry_at,
    COUNT(*) FILTER (WHERE retry_at IS NULL OR retry_at<=now()) eligible,
    SUM(satisfied_generation) satisfied FROM enrichment_cycle_members WHERE cycle_id=? AND satisfied_generation<required_generation`).bind(cycle.id).first<{total:number;retry_at:string|null;eligible:number;satisfied:number|null}>();
  const state = await db.prepare('SELECT updates_covered_through FROM enrichment_cycles WHERE id=?').bind(cycle.id).first<{updates_covered_through:string|null}>();
  const updatesComplete = Boolean(state?.updates_covered_through && Date.parse(state.updates_covered_through)>=Date.parse(cycle.target_through));
  return {remaining:Number(remaining?.total??0),retryAt:remaining?.retry_at??null,eligible:Number(remaining?.eligible??0),updatesComplete};
}
