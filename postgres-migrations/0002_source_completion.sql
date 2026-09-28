ALTER TABLE ingestion_checkpoints ADD COLUMN scheduled boolean NOT NULL DEFAULT false;
--> statement-breakpoint
ALTER TABLE ingestion_checkpoints ADD COLUMN historical_coverage_verified boolean NOT NULL DEFAULT false;
--> statement-breakpoint
ALTER TABLE ingestion_checkpoints ADD COLUMN retired_at timestamptz;
--> statement-breakpoint
ALTER TABLE ingestion_checkpoints ADD COLUMN retired_reason text;
--> statement-breakpoint
UPDATE ingestion_checkpoints SET scheduled=true WHERE mode='delta' AND (id LIKE 'daily:' || source_id || ':%' OR id LIKE 'expansion:' || source_id || ':delta:%' OR (source_id='cisco-psirt-csaf' AND id LIKE 'daily:cisco:%'));
--> statement-breakpoint
CREATE INDEX idx_checkpoints_scheduled_oldest ON ingestion_checkpoints(source_id,created_at,id) WHERE scheduled AND status<>'complete' AND retired_at IS NULL;
--> statement-breakpoint
CREATE TABLE source_completion_evidence (
 id text PRIMARY KEY, source_id text NOT NULL REFERENCES sources(id),
 owner_kind text NOT NULL CONSTRAINT source_completion_owner_kind CHECK(owner_kind IN ('checkpoint','enrichment','snapshot')), owner_id text NOT NULL,
 kind text NOT NULL CONSTRAINT source_completion_kind CHECK(kind IN ('delta','backfill','initial_enrichment')),
 coverage_start timestamptz NOT NULL, coverage_end timestamptz NOT NULL,
 completed_at timestamptz NOT NULL, member_count integer NOT NULL CONSTRAINT source_completion_members CHECK(member_count>=0),
 source_run_id text REFERENCES source_runs(id), CONSTRAINT source_completion_range CHECK(coverage_start<=coverage_end)
);
--> statement-breakpoint
CREATE UNIQUE INDEX source_completion_owner ON source_completion_evidence(owner_kind,owner_id,kind);
--> statement-breakpoint
CREATE INDEX idx_source_completion_recent ON source_completion_evidence(source_id,kind,completed_at);
--> statement-breakpoint
CREATE TABLE enrichment_cycles (
 id text PRIMARY KEY, source_id text NOT NULL REFERENCES sources(id),
 kind text NOT NULL CONSTRAINT enrichment_cycle_kind CHECK(kind IN ('initial_enrichment','delta')),
 started_at timestamptz NOT NULL, target_through timestamptz NOT NULL,
 updates_from timestamptz NOT NULL, updates_covered_through timestamptz, source_revision text,
 completed_at timestamptz, member_count integer NOT NULL DEFAULT 0 CONSTRAINT enrichment_cycle_members CHECK(member_count>=0)
);
--> statement-breakpoint
CREATE UNIQUE INDEX idx_enrichment_one_active_cycle ON enrichment_cycles(source_id) WHERE completed_at IS NULL;
--> statement-breakpoint
CREATE TABLE enrichment_cycle_members (
 cycle_id text NOT NULL REFERENCES enrichment_cycles(id), cve_id text NOT NULL REFERENCES cves(id),
 required_generation integer NOT NULL DEFAULT 1, satisfied_generation integer NOT NULL DEFAULT 0,
 outcome text CONSTRAINT enrichment_member_outcome CHECK(outcome IN ('published','rejected','not_found')), required_modified_through timestamptz, checked_at timestamptz, retry_at timestamptz, failures integer NOT NULL DEFAULT 0,
 PRIMARY KEY(cycle_id,cve_id), CONSTRAINT enrichment_member_generation CHECK(required_generation>=satisfied_generation AND satisfied_generation>=0)
);
--> statement-breakpoint
CREATE INDEX idx_enrichment_unmet_members ON enrichment_cycle_members(cycle_id,retry_at,cve_id) WHERE satisfied_generation<required_generation;

--> statement-breakpoint
UPDATE sources SET readiness_reason=CASE WHEN id='sap-configured-csaf'
 THEN 'Official adapter requires verified existing entitled access and complete historical discovery before production coverage can be claimed.'
 ELSE 'Official adapter available; complete historical discovery, representative details, and bounded replay must be validated before production coverage is claimed.' END
 WHERE readiness_reason='Awaiting a verified complete official structured feed and bounded replay; no production coverage claimed.';
