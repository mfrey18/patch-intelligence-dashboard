import type { Database } from '../../db/database';

/** Immutable certificate written only inside the transaction closing its durable owner. */
export interface SourceCompletion {
  sourceId: string;
  ownerKind: 'checkpoint' | 'enrichment' | 'snapshot';
  ownerId: string;
  kind: 'delta' | 'backfill' | 'initial_enrichment';
  coverageStart: string;
  coverageEnd: string;
  completedAt: string;
  memberCount: number;
  sourceRunId?: string | null;
}
export async function recordSourceCompletion(tx: Database, completion: SourceCompletion): Promise<void> {
  if (!Number.isSafeInteger(completion.memberCount) || completion.memberCount < 0 || !Number.isFinite(Date.parse(completion.coverageStart)) || !Number.isFinite(Date.parse(completion.coverageEnd)) || Date.parse(completion.coverageStart) > Date.parse(completion.coverageEnd) || !Number.isFinite(Date.parse(completion.completedAt)) || Date.parse(completion.coverageEnd)>Date.parse(completion.completedAt)) throw new Error('Invalid source completion evidence');
  await tx.prepare(`INSERT INTO source_completion_evidence
    (id,source_id,owner_kind,owner_id,kind,coverage_start,coverage_end,completed_at,member_count,source_run_id)
    VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT(owner_kind,owner_id,kind) DO NOTHING`)
    .bind(`${completion.ownerKind}:${completion.ownerId}:${completion.kind}`, completion.sourceId, completion.ownerKind, completion.ownerId, completion.kind, completion.coverageStart, completion.coverageEnd, completion.completedAt, completion.memberCount, completion.sourceRunId ?? null).run();
}

/** UI/automation reads the same completion evidence as readiness, never batch success. */
export async function sourceProgress(db: Database, sourceId?: string) {
  return (await db.prepare(`SELECT s.id,s.kind,s.readiness,s.readiness_reason,s.enabled,s.retry_after,
    evidence.coverage_end AS completed_coverage_through,evidence.completed_at AS cycle_completed_at,
    cp.id AS checkpoint_id,cp.status AS checkpoint_status,cp.coverage_start,cp.coverage_end,
    cp.historical_coverage_verified,cp.window_start,cp.window_end,cp.continuation_token,cp.updated_at AS progress_at,
    ec.id AS enrichment_cycle_id,ec.target_through AS enrichment_target_through,
    (SELECT COUNT(*) FROM enrichment_cycle_members m WHERE m.cycle_id=ec.id AND m.satisfied_generation<m.required_generation) AS enrichment_remaining
    FROM sources s
    LEFT JOIN LATERAL (SELECT coverage_end,completed_at FROM source_completion_evidence WHERE source_id=s.id AND kind='delta' ORDER BY coverage_end DESC,completed_at DESC LIMIT 1) evidence ON TRUE
    LEFT JOIN LATERAL (SELECT * FROM ingestion_checkpoints WHERE source_id=s.id AND scheduled=TRUE AND status<>'complete' AND retired_at IS NULL ORDER BY created_at,id LIMIT 1) cp ON TRUE
    LEFT JOIN enrichment_cycles ec ON ec.source_id=s.id AND ec.completed_at IS NULL
    WHERE (?::text IS NULL OR s.id=?) ORDER BY s.id`).bind(sourceId ?? null,sourceId ?? null).all()).results;
}
