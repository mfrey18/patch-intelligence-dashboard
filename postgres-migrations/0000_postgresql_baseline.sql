CREATE TABLE "advisories" (
	"id" text PRIMARY KEY NOT NULL,
	"vendor_id" text NOT NULL,
	"source_id" text NOT NULL,
	"vendor_advisory_id" text NOT NULL,
	"title" text NOT NULL,
	"summary" text,
	"source_url" text NOT NULL,
	"published_at" timestamp(3) with time zone,
	"source_updated_at" timestamp(3) with time zone,
	"withdrawn_at" timestamp(3) with time zone,
	"created_at" timestamp(3) with time zone NOT NULL,
	"updated_at" timestamp(3) with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "advisory_cves" (
	"advisory_id" text NOT NULL,
	"cve_id" text NOT NULL,
	"vendor_description" text,
	"vendor_cwe" text,
	"vendor_severity" text,
	"normalized_severity" text NOT NULL,
	"vendor_cvss_score" double precision,
	"vendor_cvss_vector" text,
	CONSTRAINT "advisory_cves_advisory_id_cve_id_pk" PRIMARY KEY("advisory_id","cve_id")
);
--> statement-breakpoint
CREATE TABLE "advisory_revisions" (
	"id" text PRIMARY KEY NOT NULL,
	"advisory_id" text NOT NULL,
	"source_run_id" text,
	"observed_at" timestamp(3) with time zone NOT NULL,
	"source_updated_at" timestamp(3) with time zone,
	"content_hash" text NOT NULL,
	"affected_products_hash" text NOT NULL,
	"remediation_hash" text NOT NULL,
	"exploitation_status" text NOT NULL,
	"vendor_severity" text,
	"cvss_score" double precision,
	"change_types_json" jsonb NOT NULL,
	"normalized_json" jsonb NOT NULL,
	"source_url" text NOT NULL
);
--> statement-breakpoint
CREATE TABLE "affected_products" (
	"id" text PRIMARY KEY NOT NULL,
	"advisory_id" text NOT NULL,
	"advisory_revision_id" text NOT NULL,
	"cve_id" text,
	"product_id" text NOT NULL,
	"affected_version" text,
	"fixed_version" text,
	"status" text NOT NULL,
	"source_product_id" text
);
--> statement-breakpoint
CREATE TABLE "cve_dashboard_facts" (
	"cve_id" text PRIMARY KEY NOT NULL,
	"title" text NOT NULL,
	"vendor" text NOT NULL,
	"vendor_ids" text NOT NULL,
	"product" text,
	"severity_rank" integer NOT NULL,
	"cvss" double precision,
	"epss" double precision,
	"epss_percentile" double precision,
	"kev" boolean NOT NULL,
	"known_exploited" boolean NOT NULL,
	"zero_day" boolean NOT NULL,
	"patch_available" boolean,
	"mitigation_available" boolean NOT NULL,
	"workaround_available" boolean NOT NULL,
	"published_at" timestamp(3) with time zone,
	"modified_at" timestamp(3) with time zone,
	"cwe" text,
	"priority" text NOT NULL,
	"projected_at" timestamp(3) with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "cve_dashboard_facts_staging" (
	"cve_id" text PRIMARY KEY NOT NULL,
	"title" text NOT NULL,
	"vendor" text NOT NULL,
	"vendor_ids" text NOT NULL,
	"product" text,
	"severity_rank" integer NOT NULL,
	"cvss" double precision,
	"epss" double precision,
	"epss_percentile" double precision,
	"kev" boolean NOT NULL,
	"known_exploited" boolean NOT NULL,
	"zero_day" boolean NOT NULL,
	"patch_available" boolean,
	"mitigation_available" boolean NOT NULL,
	"workaround_available" boolean NOT NULL,
	"published_at" timestamp(3) with time zone,
	"modified_at" timestamp(3) with time zone,
	"cwe" text,
	"priority" text NOT NULL,
	"projected_at" timestamp(3) with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "cves" (
	"id" text PRIMARY KEY NOT NULL,
	"description" text,
	"cwe" text,
	"cvss_score" double precision,
	"cvss_vector" text,
	"published_at" timestamp(3) with time zone,
	"modified_at" timestamp(3) with time zone,
	"canonical_source_url" text,
	"created_at" timestamp(3) with time zone NOT NULL,
	"updated_at" timestamp(3) with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "dashboard_projection_leases" (
	"id" text PRIMARY KEY NOT NULL,
	"holder" text NOT NULL,
	"acquired_at" timestamp(3) with time zone NOT NULL,
	"expires_at" timestamp(3) with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "dashboard_projection_state" (
	"id" text PRIMARY KEY NOT NULL,
	"projection_version" integer NOT NULL,
	"generated_at" timestamp(3) with time zone NOT NULL,
	"source_run_id" text,
	"cve_count" integer NOT NULL,
	"status" text NOT NULL,
	"parity_checked_at" timestamp(3) with time zone,
	"parity_status" text,
	"parity_json" jsonb,
	"last_attempt_at" timestamp(3) with time zone,
	"last_attempt_status" text,
	"last_attempt_error" text
);
--> statement-breakpoint
CREATE TABLE "epss_datasets" (
	"score_date" date PRIMARY KEY NOT NULL,
	"source_run_id" text NOT NULL,
	"model_version" text,
	"source_hash" text NOT NULL,
	"source_url" text NOT NULL,
	"row_count" integer NOT NULL,
	"matched_cve_count" integer NOT NULL,
	"status" text NOT NULL,
	"is_current" boolean DEFAULT false NOT NULL,
	"published_at" timestamp(3) with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "epss_observations" (
	"cve_id" text NOT NULL,
	"score_date" date NOT NULL,
	"score" double precision NOT NULL,
	"percentile" double precision NOT NULL,
	"model_version" text,
	"source_run_id" text NOT NULL,
	"observed_at" timestamp(3) with time zone NOT NULL,
	CONSTRAINT "epss_observations_cve_id_score_date_pk" PRIMARY KEY("cve_id","score_date"),
	CONSTRAINT "epss_score_range" CHECK ("epss_observations"."score" BETWEEN 0 AND 1 AND "epss_observations"."percentile" BETWEEN 0 AND 1)
);
--> statement-breakpoint
CREATE TABLE "exploit_evidence" (
	"id" text PRIMARY KEY NOT NULL,
	"cve_id" text NOT NULL,
	"advisory_id" text,
	"source_id" text NOT NULL,
	"evidence_type" text NOT NULL,
	"status" text NOT NULL,
	"evidence_date" date,
	"evidence_url" text NOT NULL,
	"summary" text,
	"first_observed_at" timestamp(3) with time zone NOT NULL,
	"last_observed_at" timestamp(3) with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "ingestion_checkpoints" (
	"id" text PRIMARY KEY NOT NULL,
	"source_id" text NOT NULL,
	"mode" text NOT NULL,
	"coverage_start" timestamp(3) with time zone NOT NULL,
	"coverage_end" timestamp(3) with time zone NOT NULL,
	"window_start" timestamp(3) with time zone NOT NULL,
	"window_end" timestamp(3) with time zone NOT NULL,
	"continuation_token" text,
	"status" text NOT NULL,
	"last_run_id" text,
	"last_error" text,
	"created_at" timestamp(3) with time zone NOT NULL,
	"updated_at" timestamp(3) with time zone NOT NULL,
	"completed_at" timestamp(3) with time zone
);
--> statement-breakpoint
CREATE TABLE "ingestion_leases" (
	"source_id" text PRIMARY KEY NOT NULL,
	"holder" text NOT NULL,
	"acquired_at" timestamp(3) with time zone NOT NULL,
	"expires_at" timestamp(3) with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "intelligence_changes" (
	"id" text PRIMARY KEY NOT NULL,
	"source_run_id" text NOT NULL,
	"entity_type" text NOT NULL,
	"entity_id" text NOT NULL,
	"cve_id" text,
	"advisory_id" text,
	"change_type" text NOT NULL,
	"observed_at" timestamp(3) with time zone NOT NULL,
	"before_json" jsonb,
	"after_json" jsonb,
	"summary" text NOT NULL
);
--> statement-breakpoint
CREATE TABLE "kev_entries" (
	"cve_id" text PRIMARY KEY NOT NULL,
	"source_run_id" text,
	"active" boolean NOT NULL,
	"date_added" date NOT NULL,
	"due_date" date,
	"required_action" text,
	"known_ransomware_campaign_use" text,
	"entry_hash" text NOT NULL,
	"source_url" text NOT NULL,
	"first_observed_at" timestamp(3) with time zone NOT NULL,
	"last_observed_at" timestamp(3) with time zone NOT NULL,
	"removed_at" timestamp(3) with time zone
);
--> statement-breakpoint
CREATE TABLE "product_versions" (
	"id" text PRIMARY KEY NOT NULL,
	"product_id" text NOT NULL,
	"version" text NOT NULL,
	"release" text,
	"created_at" timestamp(3) with time zone NOT NULL,
	"updated_at" timestamp(3) with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "products" (
	"id" text PRIMARY KEY NOT NULL,
	"vendor_id" text NOT NULL,
	"name" text NOT NULL,
	"family" text,
	"created_at" timestamp(3) with time zone NOT NULL,
	"updated_at" timestamp(3) with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "release_event_advisories" (
	"release_event_id" text NOT NULL,
	"advisory_id" text NOT NULL,
	CONSTRAINT "release_event_advisories_release_event_id_advisory_id_pk" PRIMARY KEY("release_event_id","advisory_id")
);
--> statement-breakpoint
CREATE TABLE "release_events" (
	"id" text PRIMARY KEY NOT NULL,
	"vendor_id" text NOT NULL,
	"event_type" text NOT NULL,
	"event_date" date NOT NULL,
	"label" text NOT NULL,
	"source_url" text,
	"reported_cve_count" integer,
	"reported_at" timestamp(3) with time zone,
	"reported_product_families_json" jsonb,
	"created_at" timestamp(3) with time zone NOT NULL,
	"updated_at" timestamp(3) with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "remediations" (
	"id" text PRIMARY KEY NOT NULL,
	"advisory_id" text NOT NULL,
	"advisory_revision_id" text NOT NULL,
	"cve_id" text,
	"product_id" text,
	"kind" text NOT NULL,
	"patch_available" boolean,
	"fixed_version" text,
	"action" text,
	"reboot_required" boolean,
	"superseded" boolean,
	"source_url" text NOT NULL,
	"published_at" timestamp(3) with time zone,
	"updated_at" timestamp(3) with time zone
);
--> statement-breakpoint
CREATE TABLE "source_run_results" (
	"id" text PRIMARY KEY NOT NULL,
	"source_run_id" text NOT NULL,
	"source_ref" text NOT NULL,
	"status" text NOT NULL,
	"change_types_json" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"error_summary" text,
	"duration_ms" integer DEFAULT 0 NOT NULL,
	"observed_at" timestamp(3) with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "source_runs" (
	"id" text PRIMARY KEY NOT NULL,
	"source_id" text NOT NULL,
	"idempotency_key" text,
	"started_at" timestamp(3) with time zone NOT NULL,
	"completed_at" timestamp(3) with time zone,
	"status" text NOT NULL,
	"ingestion_mode" text DEFAULT 'delta' NOT NULL,
	"window_start" timestamp(3) with time zone,
	"window_end" timestamp(3) with time zone,
	"continuation_in" text,
	"continuation_out" text,
	"checkpoint_id" text,
	"max_items" integer DEFAULT 12 NOT NULL,
	"bound_hit" boolean DEFAULT false NOT NULL,
	"dataset_date" timestamp(3) with time zone,
	"source_hash" text,
	"records_discovered" integer DEFAULT 0 NOT NULL,
	"records_inserted" integer DEFAULT 0 NOT NULL,
	"records_changed" integer DEFAULT 0 NOT NULL,
	"records_unchanged" integer DEFAULT 0 NOT NULL,
	"records_failed" integer DEFAULT 0 NOT NULL,
	"error_summary" text
);
--> statement-breakpoint
CREATE TABLE "sources" (
	"id" text PRIMARY KEY NOT NULL,
	"vendor_id" text,
	"name" text NOT NULL,
	"kind" text NOT NULL,
	"discovery_url" text NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"created_at" timestamp(3) with time zone NOT NULL,
	"updated_at" timestamp(3) with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "vendors" (
	"id" text PRIMARY KEY NOT NULL,
	"name" text NOT NULL,
	"homepage_url" text,
	"created_at" timestamp(3) with time zone NOT NULL,
	"updated_at" timestamp(3) with time zone NOT NULL
);
--> statement-breakpoint
ALTER TABLE "advisories" ADD CONSTRAINT "advisories_vendor_id_vendors_id_fk" FOREIGN KEY ("vendor_id") REFERENCES "public"."vendors"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "advisories" ADD CONSTRAINT "advisories_source_id_sources_id_fk" FOREIGN KEY ("source_id") REFERENCES "public"."sources"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "advisory_cves" ADD CONSTRAINT "advisory_cves_advisory_id_advisories_id_fk" FOREIGN KEY ("advisory_id") REFERENCES "public"."advisories"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "advisory_cves" ADD CONSTRAINT "advisory_cves_cve_id_cves_id_fk" FOREIGN KEY ("cve_id") REFERENCES "public"."cves"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "advisory_revisions" ADD CONSTRAINT "advisory_revisions_advisory_id_advisories_id_fk" FOREIGN KEY ("advisory_id") REFERENCES "public"."advisories"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "advisory_revisions" ADD CONSTRAINT "advisory_revisions_source_run_id_source_runs_id_fk" FOREIGN KEY ("source_run_id") REFERENCES "public"."source_runs"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "affected_products" ADD CONSTRAINT "affected_products_advisory_id_advisories_id_fk" FOREIGN KEY ("advisory_id") REFERENCES "public"."advisories"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "affected_products" ADD CONSTRAINT "affected_products_advisory_revision_id_advisory_revisions_id_fk" FOREIGN KEY ("advisory_revision_id") REFERENCES "public"."advisory_revisions"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "affected_products" ADD CONSTRAINT "affected_products_cve_id_cves_id_fk" FOREIGN KEY ("cve_id") REFERENCES "public"."cves"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "affected_products" ADD CONSTRAINT "affected_products_product_id_products_id_fk" FOREIGN KEY ("product_id") REFERENCES "public"."products"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "cve_dashboard_facts" ADD CONSTRAINT "cve_dashboard_facts_cve_id_cves_id_fk" FOREIGN KEY ("cve_id") REFERENCES "public"."cves"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "cve_dashboard_facts_staging" ADD CONSTRAINT "cve_dashboard_facts_staging_cve_id_cves_id_fk" FOREIGN KEY ("cve_id") REFERENCES "public"."cves"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "epss_datasets" ADD CONSTRAINT "epss_datasets_source_run_id_source_runs_id_fk" FOREIGN KEY ("source_run_id") REFERENCES "public"."source_runs"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "epss_observations" ADD CONSTRAINT "epss_observations_cve_id_cves_id_fk" FOREIGN KEY ("cve_id") REFERENCES "public"."cves"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "epss_observations" ADD CONSTRAINT "epss_observations_score_date_epss_datasets_score_date_fk" FOREIGN KEY ("score_date") REFERENCES "public"."epss_datasets"("score_date") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "epss_observations" ADD CONSTRAINT "epss_observations_source_run_id_source_runs_id_fk" FOREIGN KEY ("source_run_id") REFERENCES "public"."source_runs"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "exploit_evidence" ADD CONSTRAINT "exploit_evidence_cve_id_cves_id_fk" FOREIGN KEY ("cve_id") REFERENCES "public"."cves"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "exploit_evidence" ADD CONSTRAINT "exploit_evidence_advisory_id_advisories_id_fk" FOREIGN KEY ("advisory_id") REFERENCES "public"."advisories"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "exploit_evidence" ADD CONSTRAINT "exploit_evidence_source_id_sources_id_fk" FOREIGN KEY ("source_id") REFERENCES "public"."sources"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ingestion_checkpoints" ADD CONSTRAINT "ingestion_checkpoints_source_id_sources_id_fk" FOREIGN KEY ("source_id") REFERENCES "public"."sources"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ingestion_checkpoints" ADD CONSTRAINT "ingestion_checkpoints_last_run_id_source_runs_id_fk" FOREIGN KEY ("last_run_id") REFERENCES "public"."source_runs"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ingestion_leases" ADD CONSTRAINT "ingestion_leases_source_id_sources_id_fk" FOREIGN KEY ("source_id") REFERENCES "public"."sources"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "intelligence_changes" ADD CONSTRAINT "intelligence_changes_source_run_id_source_runs_id_fk" FOREIGN KEY ("source_run_id") REFERENCES "public"."source_runs"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "intelligence_changes" ADD CONSTRAINT "intelligence_changes_cve_id_cves_id_fk" FOREIGN KEY ("cve_id") REFERENCES "public"."cves"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "intelligence_changes" ADD CONSTRAINT "intelligence_changes_advisory_id_advisories_id_fk" FOREIGN KEY ("advisory_id") REFERENCES "public"."advisories"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "kev_entries" ADD CONSTRAINT "kev_entries_cve_id_cves_id_fk" FOREIGN KEY ("cve_id") REFERENCES "public"."cves"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "kev_entries" ADD CONSTRAINT "kev_entries_source_run_id_source_runs_id_fk" FOREIGN KEY ("source_run_id") REFERENCES "public"."source_runs"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "product_versions" ADD CONSTRAINT "product_versions_product_id_products_id_fk" FOREIGN KEY ("product_id") REFERENCES "public"."products"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "products" ADD CONSTRAINT "products_vendor_id_vendors_id_fk" FOREIGN KEY ("vendor_id") REFERENCES "public"."vendors"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "release_event_advisories" ADD CONSTRAINT "release_event_advisories_release_event_id_release_events_id_fk" FOREIGN KEY ("release_event_id") REFERENCES "public"."release_events"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "release_event_advisories" ADD CONSTRAINT "release_event_advisories_advisory_id_advisories_id_fk" FOREIGN KEY ("advisory_id") REFERENCES "public"."advisories"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "release_events" ADD CONSTRAINT "release_events_vendor_id_vendors_id_fk" FOREIGN KEY ("vendor_id") REFERENCES "public"."vendors"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "remediations" ADD CONSTRAINT "remediations_advisory_id_advisories_id_fk" FOREIGN KEY ("advisory_id") REFERENCES "public"."advisories"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "remediations" ADD CONSTRAINT "remediations_advisory_revision_id_advisory_revisions_id_fk" FOREIGN KEY ("advisory_revision_id") REFERENCES "public"."advisory_revisions"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "remediations" ADD CONSTRAINT "remediations_cve_id_cves_id_fk" FOREIGN KEY ("cve_id") REFERENCES "public"."cves"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "remediations" ADD CONSTRAINT "remediations_product_id_products_id_fk" FOREIGN KEY ("product_id") REFERENCES "public"."products"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "source_run_results" ADD CONSTRAINT "source_run_results_source_run_id_source_runs_id_fk" FOREIGN KEY ("source_run_id") REFERENCES "public"."source_runs"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "source_runs" ADD CONSTRAINT "source_runs_source_id_sources_id_fk" FOREIGN KEY ("source_id") REFERENCES "public"."sources"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sources" ADD CONSTRAINT "sources_vendor_id_vendors_id_fk" FOREIGN KEY ("vendor_id") REFERENCES "public"."vendors"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "idx_advisories_vendor_advisory" ON "advisories" USING btree ("vendor_id","vendor_advisory_id");--> statement-breakpoint
CREATE INDEX "idx_advisories_published" ON "advisories" USING btree ("published_at");--> statement-breakpoint
CREATE INDEX "idx_advisories_vendor_published" ON "advisories" USING btree ("vendor_id","published_at");--> statement-breakpoint
CREATE INDEX "idx_advisories_modified" ON "advisories" USING btree ("source_updated_at");--> statement-breakpoint
CREATE INDEX "idx_advisory_cves_cve" ON "advisory_cves" USING btree ("cve_id");--> statement-breakpoint
CREATE INDEX "idx_advisory_cves_severity" ON "advisory_cves" USING btree ("normalized_severity");--> statement-breakpoint
CREATE INDEX "idx_advisory_cves_severity_cve" ON "advisory_cves" USING btree ("normalized_severity","cve_id");--> statement-breakpoint
CREATE INDEX "idx_advisory_revisions_advisory_hash" ON "advisory_revisions" USING btree ("advisory_id","content_hash");--> statement-breakpoint
CREATE INDEX "idx_advisory_revisions_observed" ON "advisory_revisions" USING btree ("observed_at");--> statement-breakpoint
CREATE INDEX "idx_advisory_revisions_advisory_observed" ON "advisory_revisions" USING btree ("advisory_id","observed_at");--> statement-breakpoint
CREATE INDEX "idx_affected_products_advisory_revision" ON "affected_products" USING btree ("advisory_id","advisory_revision_id");--> statement-breakpoint
CREATE INDEX "idx_affected_products_cve" ON "affected_products" USING btree ("cve_id");--> statement-breakpoint
CREATE INDEX "idx_affected_products_product_cve_revision" ON "affected_products" USING btree ("product_id","cve_id","advisory_revision_id");--> statement-breakpoint
CREATE INDEX "idx_affected_products_revision_cve_product" ON "affected_products" USING btree ("advisory_revision_id","cve_id","product_id");--> statement-breakpoint
CREATE INDEX "idx_dashboard_facts_priority_sort" ON "cve_dashboard_facts" USING btree ("priority","severity_rank","epss_percentile","published_at","cve_id");--> statement-breakpoint
CREATE INDEX "idx_dashboard_facts_severity_cvss" ON "cve_dashboard_facts" USING btree ("severity_rank","cvss");--> statement-breakpoint
CREATE INDEX "idx_dashboard_facts_epss" ON "cve_dashboard_facts" USING btree ("epss_percentile");--> statement-breakpoint
CREATE INDEX "idx_dashboard_facts_published" ON "cve_dashboard_facts" USING btree ("published_at");--> statement-breakpoint
CREATE INDEX "idx_dashboard_facts_modified" ON "cve_dashboard_facts" USING btree ("modified_at");--> statement-breakpoint
CREATE INDEX "idx_dashboard_facts_threat" ON "cve_dashboard_facts" USING btree ("kev","known_exploited","zero_day");--> statement-breakpoint
CREATE INDEX "idx_cves_published" ON "cves" USING btree ("published_at");--> statement-breakpoint
CREATE INDEX "idx_cves_cwe_published" ON "cves" USING btree ("cwe","published_at");--> statement-breakpoint
CREATE INDEX "idx_epss_datasets_current_date" ON "epss_datasets" USING btree ("is_current","score_date");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_epss_one_current" ON "epss_datasets" USING btree ("is_current") WHERE "epss_datasets"."is_current";--> statement-breakpoint
CREATE INDEX "idx_epss_observations_date" ON "epss_observations" USING btree ("score_date");--> statement-breakpoint
CREATE INDEX "idx_epss_observations_cve_model_date" ON "epss_observations" USING btree ("cve_id","model_version","score_date");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_exploit_evidence_identity" ON "exploit_evidence" USING btree ("cve_id","source_id","evidence_type","evidence_url");--> statement-breakpoint
CREATE INDEX "idx_exploit_evidence_state_cve" ON "exploit_evidence" USING btree ("evidence_type","status","cve_id");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_ingestion_checkpoints_identity" ON "ingestion_checkpoints" USING btree ("source_id","mode","coverage_start","coverage_end");--> statement-breakpoint
CREATE INDEX "idx_ingestion_checkpoints_status_updated" ON "ingestion_checkpoints" USING btree ("status","updated_at");--> statement-breakpoint
CREATE INDEX "idx_intelligence_changes_observed" ON "intelligence_changes" USING btree ("observed_at");--> statement-breakpoint
CREATE INDEX "idx_intelligence_changes_cve" ON "intelligence_changes" USING btree ("cve_id");--> statement-breakpoint
CREATE INDEX "idx_intelligence_changes_type_observed_cve" ON "intelligence_changes" USING btree ("change_type","observed_at","cve_id");--> statement-breakpoint
CREATE INDEX "idx_intelligence_changes_cve_observed_type" ON "intelligence_changes" USING btree ("cve_id","observed_at","change_type");--> statement-breakpoint
CREATE INDEX "idx_kev_entries_active_due" ON "kev_entries" USING btree ("active","due_date");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_product_versions_product_version" ON "product_versions" USING btree ("product_id","version");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_products_vendor_name" ON "products" USING btree ("vendor_id","name");--> statement-breakpoint
CREATE INDEX "idx_products_vendor_family_name" ON "products" USING btree ("vendor_id","family","name");--> statement-breakpoint
CREATE INDEX "idx_release_event_advisories_advisory_event" ON "release_event_advisories" USING btree ("advisory_id","release_event_id");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_release_events_vendor_type_date" ON "release_events" USING btree ("vendor_id","event_type","event_date");--> statement-breakpoint
CREATE INDEX "idx_release_events_type_date" ON "release_events" USING btree ("event_type","event_date");--> statement-breakpoint
CREATE INDEX "idx_remediations_cve" ON "remediations" USING btree ("cve_id");--> statement-breakpoint
CREATE INDEX "idx_remediations_advisory_revision" ON "remediations" USING btree ("advisory_id","advisory_revision_id");--> statement-breakpoint
CREATE INDEX "idx_remediations_state_cve_revision" ON "remediations" USING btree ("patch_available","kind","cve_id","advisory_revision_id");--> statement-breakpoint
CREATE INDEX "idx_remediations_revision_cve_kind" ON "remediations" USING btree ("advisory_revision_id","cve_id","kind");--> statement-breakpoint
CREATE INDEX "idx_source_run_results_run" ON "source_run_results" USING btree ("source_run_id");--> statement-breakpoint
CREATE INDEX "idx_source_runs_source_started" ON "source_runs" USING btree ("source_id","started_at");--> statement-breakpoint
CREATE INDEX "idx_source_runs_status_completed" ON "source_runs" USING btree ("status","completed_at");--> statement-breakpoint
CREATE INDEX "idx_source_runs_checkpoint" ON "source_runs" USING btree ("checkpoint_id","started_at");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_source_runs_idempotency" ON "source_runs" USING btree ("source_id","idempotency_key");