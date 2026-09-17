ALTER TABLE sources ADD COLUMN readiness text NOT NULL DEFAULT 'validating';
--> statement-breakpoint
ALTER TABLE sources ADD COLUMN readiness_reason text;
--> statement-breakpoint
UPDATE sources SET readiness=CASE WHEN enabled THEN 'production' ELSE 'validating' END;
--> statement-breakpoint
CREATE TABLE discovery_pages (id text PRIMARY KEY, source_id text NOT NULL REFERENCES sources(id), refs jsonb NOT NULL, next_cursor text, created_at timestamptz NOT NULL DEFAULT now());
--> statement-breakpoint
ALTER TABLE cves ADD COLUMN record_status text NOT NULL DEFAULT 'unknown';
--> statement-breakpoint
ALTER TABLE cves ADD COLUMN assessment_source text;
--> statement-breakpoint
CREATE TABLE cve_enrichments (cve_id text NOT NULL REFERENCES cves(id), source_id text NOT NULL REFERENCES sources(id), content_hash text NOT NULL, payload jsonb NOT NULL, source_url text NOT NULL, source_modified_at timestamptz, observed_at timestamptz NOT NULL, source_run_id text REFERENCES source_runs(id), PRIMARY KEY(cve_id,source_id,content_hash));
--> statement-breakpoint
CREATE INDEX cve_enrichments_latest ON cve_enrichments(cve_id,source_id,observed_at DESC);
--> statement-breakpoint
CREATE TABLE enrichment_queue (cve_id text NOT NULL REFERENCES cves(id), source_id text NOT NULL REFERENCES sources(id), checked_at timestamptz, retry_at timestamptz, failures integer NOT NULL DEFAULT 0, PRIMARY KEY(cve_id,source_id));
--> statement-breakpoint
CREATE TABLE vulncheck_entries (cve_id text PRIMARY KEY REFERENCES cves(id), active boolean NOT NULL, date_added timestamptz NOT NULL, source_modified_at timestamptz, payload jsonb NOT NULL, content_hash text NOT NULL, source_run_id text REFERENCES source_runs(id), first_observed_at timestamptz NOT NULL, last_observed_at timestamptz NOT NULL, removed_at timestamptz);
--> statement-breakpoint
CREATE INDEX vulncheck_entries_scope ON vulncheck_entries(active,date_added,cve_id);
--> statement-breakpoint
CREATE TABLE enrichment_updates (source_id text PRIMARY KEY REFERENCES sources(id), completed_at timestamptz, window_start timestamptz, window_end timestamptz, next_offset integer NOT NULL DEFAULT 0);
--> statement-breakpoint
UPDATE sources SET readiness='pending_feed',readiness_reason='Awaiting a verified complete official structured feed and bounded replay; no production coverage claimed.' WHERE enabled=FALSE AND id IN ('adobe-psirt-csaf','fortinet-psirt-csaf','ivanti-security-advisory-rss','apple-configured-csaf','sap-configured-csaf');
--> statement-breakpoint
ALTER TABLE sources ADD COLUMN retry_after timestamptz;
