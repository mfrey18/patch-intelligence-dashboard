CREATE TABLE `advisories` (
	`id` text PRIMARY KEY NOT NULL,
	`vendor_id` text NOT NULL,
	`source_id` text NOT NULL,
	`vendor_advisory_id` text NOT NULL,
	`title` text NOT NULL,
	`summary` text,
	`source_url` text NOT NULL,
	`published_at` text,
	`source_updated_at` text,
	`withdrawn_at` text,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL,
	FOREIGN KEY (`vendor_id`) REFERENCES `vendors`(`id`) ON UPDATE no action ON DELETE no action,
	FOREIGN KEY (`source_id`) REFERENCES `sources`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE UNIQUE INDEX `idx_advisories_vendor_advisory` ON `advisories` (`vendor_id`,`vendor_advisory_id`);--> statement-breakpoint
CREATE INDEX `idx_advisories_published` ON `advisories` (`published_at`);--> statement-breakpoint
CREATE TABLE `advisory_cves` (
	`advisory_id` text NOT NULL,
	`cve_id` text NOT NULL,
	`vendor_description` text,
	`vendor_cwe` text,
	`vendor_severity` text,
	`normalized_severity` text NOT NULL,
	`vendor_cvss_score` real,
	`vendor_cvss_vector` text,
	PRIMARY KEY(`advisory_id`, `cve_id`),
	FOREIGN KEY (`advisory_id`) REFERENCES `advisories`(`id`) ON UPDATE no action ON DELETE no action,
	FOREIGN KEY (`cve_id`) REFERENCES `cves`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE INDEX `idx_advisory_cves_cve` ON `advisory_cves` (`cve_id`);--> statement-breakpoint
CREATE INDEX `idx_advisory_cves_severity` ON `advisory_cves` (`normalized_severity`);--> statement-breakpoint
CREATE TABLE `advisory_revisions` (
	`id` text PRIMARY KEY NOT NULL,
	`advisory_id` text NOT NULL,
	`source_run_id` text,
	`observed_at` text NOT NULL,
	`source_updated_at` text,
	`content_hash` text NOT NULL,
	`affected_products_hash` text NOT NULL,
	`remediation_hash` text NOT NULL,
	`exploitation_status` text NOT NULL,
	`vendor_severity` text,
	`cvss_score` real,
	`change_types_json` text NOT NULL,
	`normalized_json` text NOT NULL,
	`source_url` text NOT NULL,
	FOREIGN KEY (`advisory_id`) REFERENCES `advisories`(`id`) ON UPDATE no action ON DELETE no action,
	FOREIGN KEY (`source_run_id`) REFERENCES `source_runs`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE UNIQUE INDEX `idx_advisory_revisions_advisory_hash` ON `advisory_revisions` (`advisory_id`,`content_hash`);--> statement-breakpoint
CREATE INDEX `idx_advisory_revisions_observed` ON `advisory_revisions` (`observed_at`);--> statement-breakpoint
CREATE TABLE `affected_products` (
	`id` text PRIMARY KEY NOT NULL,
	`advisory_id` text NOT NULL,
	`advisory_revision_id` text NOT NULL,
	`cve_id` text,
	`product_id` text NOT NULL,
	`affected_version` text,
	`fixed_version` text,
	`status` text NOT NULL,
	`source_product_id` text,
	FOREIGN KEY (`advisory_id`) REFERENCES `advisories`(`id`) ON UPDATE no action ON DELETE no action,
	FOREIGN KEY (`advisory_revision_id`) REFERENCES `advisory_revisions`(`id`) ON UPDATE no action ON DELETE no action,
	FOREIGN KEY (`cve_id`) REFERENCES `cves`(`id`) ON UPDATE no action ON DELETE no action,
	FOREIGN KEY (`product_id`) REFERENCES `products`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE INDEX `idx_affected_products_advisory_revision` ON `affected_products` (`advisory_id`,`advisory_revision_id`);--> statement-breakpoint
CREATE INDEX `idx_affected_products_cve` ON `affected_products` (`cve_id`);--> statement-breakpoint
CREATE TABLE `cves` (
	`id` text PRIMARY KEY NOT NULL,
	`description` text,
	`cwe` text,
	`cvss_score` real,
	`cvss_vector` text,
	`published_at` text,
	`modified_at` text,
	`canonical_source_url` text,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL
);
--> statement-breakpoint
CREATE INDEX `idx_cves_published` ON `cves` (`published_at`);--> statement-breakpoint
CREATE TABLE `epss_datasets` (
	`score_date` text PRIMARY KEY NOT NULL,
	`source_run_id` text NOT NULL,
	`model_version` text,
	`source_hash` text NOT NULL,
	`source_url` text NOT NULL,
	`row_count` integer NOT NULL,
	`matched_cve_count` integer NOT NULL,
	`status` text NOT NULL,
	`is_current` integer DEFAULT false NOT NULL,
	`published_at` text NOT NULL,
	FOREIGN KEY (`source_run_id`) REFERENCES `source_runs`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE TABLE `epss_observations` (
	`cve_id` text NOT NULL,
	`score_date` text NOT NULL,
	`score` real NOT NULL,
	`percentile` real NOT NULL,
	`model_version` text,
	`source_run_id` text NOT NULL,
	`observed_at` text NOT NULL,
	PRIMARY KEY(`cve_id`, `score_date`),
	FOREIGN KEY (`cve_id`) REFERENCES `cves`(`id`) ON UPDATE no action ON DELETE no action,
	FOREIGN KEY (`score_date`) REFERENCES `epss_datasets`(`score_date`) ON UPDATE no action ON DELETE no action,
	FOREIGN KEY (`source_run_id`) REFERENCES `source_runs`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE INDEX `idx_epss_observations_date` ON `epss_observations` (`score_date`);--> statement-breakpoint
CREATE TABLE `exploit_evidence` (
	`id` text PRIMARY KEY NOT NULL,
	`cve_id` text NOT NULL,
	`advisory_id` text,
	`source_id` text NOT NULL,
	`evidence_type` text NOT NULL,
	`status` text NOT NULL,
	`evidence_date` text,
	`evidence_url` text NOT NULL,
	`summary` text,
	`first_observed_at` text NOT NULL,
	`last_observed_at` text NOT NULL,
	FOREIGN KEY (`cve_id`) REFERENCES `cves`(`id`) ON UPDATE no action ON DELETE no action,
	FOREIGN KEY (`advisory_id`) REFERENCES `advisories`(`id`) ON UPDATE no action ON DELETE no action,
	FOREIGN KEY (`source_id`) REFERENCES `sources`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE UNIQUE INDEX `idx_exploit_evidence_identity` ON `exploit_evidence` (`cve_id`,`source_id`,`evidence_type`,`evidence_url`);--> statement-breakpoint
CREATE TABLE `ingestion_leases` (
	`source_id` text PRIMARY KEY NOT NULL,
	`holder` text NOT NULL,
	`acquired_at` text NOT NULL,
	`expires_at` text NOT NULL,
	FOREIGN KEY (`source_id`) REFERENCES `sources`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE TABLE `intelligence_changes` (
	`id` text PRIMARY KEY NOT NULL,
	`source_run_id` text NOT NULL,
	`entity_type` text NOT NULL,
	`entity_id` text NOT NULL,
	`cve_id` text,
	`advisory_id` text,
	`change_type` text NOT NULL,
	`observed_at` text NOT NULL,
	`before_json` text,
	`after_json` text,
	`summary` text NOT NULL,
	FOREIGN KEY (`source_run_id`) REFERENCES `source_runs`(`id`) ON UPDATE no action ON DELETE no action,
	FOREIGN KEY (`cve_id`) REFERENCES `cves`(`id`) ON UPDATE no action ON DELETE no action,
	FOREIGN KEY (`advisory_id`) REFERENCES `advisories`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE INDEX `idx_intelligence_changes_observed` ON `intelligence_changes` (`observed_at`);--> statement-breakpoint
CREATE INDEX `idx_intelligence_changes_cve` ON `intelligence_changes` (`cve_id`);--> statement-breakpoint
CREATE TABLE `kev_entries` (
	`cve_id` text PRIMARY KEY NOT NULL,
	`source_run_id` text,
	`active` integer NOT NULL,
	`date_added` text NOT NULL,
	`due_date` text,
	`required_action` text,
	`known_ransomware_campaign_use` text,
	`entry_hash` text NOT NULL,
	`source_url` text NOT NULL,
	`first_observed_at` text NOT NULL,
	`last_observed_at` text NOT NULL,
	`removed_at` text,
	FOREIGN KEY (`cve_id`) REFERENCES `cves`(`id`) ON UPDATE no action ON DELETE no action,
	FOREIGN KEY (`source_run_id`) REFERENCES `source_runs`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE INDEX `idx_kev_entries_active_due` ON `kev_entries` (`active`,`due_date`);--> statement-breakpoint
CREATE TABLE `product_versions` (
	`id` text PRIMARY KEY NOT NULL,
	`product_id` text NOT NULL,
	`version` text NOT NULL,
	`release` text,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL,
	FOREIGN KEY (`product_id`) REFERENCES `products`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE UNIQUE INDEX `idx_product_versions_product_version` ON `product_versions` (`product_id`,`version`);--> statement-breakpoint
CREATE TABLE `products` (
	`id` text PRIMARY KEY NOT NULL,
	`vendor_id` text NOT NULL,
	`name` text NOT NULL,
	`family` text,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL,
	FOREIGN KEY (`vendor_id`) REFERENCES `vendors`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE UNIQUE INDEX `idx_products_vendor_name` ON `products` (`vendor_id`,`name`);--> statement-breakpoint
CREATE TABLE `release_event_advisories` (
	`release_event_id` text NOT NULL,
	`advisory_id` text NOT NULL,
	PRIMARY KEY(`release_event_id`, `advisory_id`),
	FOREIGN KEY (`release_event_id`) REFERENCES `release_events`(`id`) ON UPDATE no action ON DELETE no action,
	FOREIGN KEY (`advisory_id`) REFERENCES `advisories`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE TABLE `release_events` (
	`id` text PRIMARY KEY NOT NULL,
	`vendor_id` text NOT NULL,
	`event_type` text NOT NULL,
	`event_date` text NOT NULL,
	`label` text NOT NULL,
	`source_url` text,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL,
	FOREIGN KEY (`vendor_id`) REFERENCES `vendors`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE UNIQUE INDEX `idx_release_events_vendor_type_date` ON `release_events` (`vendor_id`,`event_type`,`event_date`);--> statement-breakpoint
CREATE TABLE `remediations` (
	`id` text PRIMARY KEY NOT NULL,
	`advisory_id` text NOT NULL,
	`advisory_revision_id` text NOT NULL,
	`cve_id` text,
	`product_id` text,
	`kind` text NOT NULL,
	`patch_available` integer,
	`fixed_version` text,
	`action` text,
	`reboot_required` integer,
	`superseded` integer,
	`source_url` text NOT NULL,
	`published_at` text,
	`updated_at` text,
	FOREIGN KEY (`advisory_id`) REFERENCES `advisories`(`id`) ON UPDATE no action ON DELETE no action,
	FOREIGN KEY (`advisory_revision_id`) REFERENCES `advisory_revisions`(`id`) ON UPDATE no action ON DELETE no action,
	FOREIGN KEY (`cve_id`) REFERENCES `cves`(`id`) ON UPDATE no action ON DELETE no action,
	FOREIGN KEY (`product_id`) REFERENCES `products`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE INDEX `idx_remediations_cve` ON `remediations` (`cve_id`);--> statement-breakpoint
CREATE INDEX `idx_remediations_advisory_revision` ON `remediations` (`advisory_id`,`advisory_revision_id`);--> statement-breakpoint
CREATE TABLE `source_run_results` (
	`id` text PRIMARY KEY NOT NULL,
	`source_run_id` text NOT NULL,
	`source_ref` text NOT NULL,
	`status` text NOT NULL,
	`change_types_json` text DEFAULT '[]' NOT NULL,
	`error_summary` text,
	`duration_ms` integer DEFAULT 0 NOT NULL,
	`observed_at` text NOT NULL,
	FOREIGN KEY (`source_run_id`) REFERENCES `source_runs`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE INDEX `idx_source_run_results_run` ON `source_run_results` (`source_run_id`);--> statement-breakpoint
CREATE TABLE `source_runs` (
	`id` text PRIMARY KEY NOT NULL,
	`source_id` text NOT NULL,
	`idempotency_key` text,
	`started_at` text NOT NULL,
	`completed_at` text,
	`status` text NOT NULL,
	`dataset_date` text,
	`source_hash` text,
	`records_discovered` integer DEFAULT 0 NOT NULL,
	`records_inserted` integer DEFAULT 0 NOT NULL,
	`records_changed` integer DEFAULT 0 NOT NULL,
	`records_unchanged` integer DEFAULT 0 NOT NULL,
	`records_failed` integer DEFAULT 0 NOT NULL,
	`error_summary` text,
	FOREIGN KEY (`source_id`) REFERENCES `sources`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE INDEX `idx_source_runs_source_started` ON `source_runs` (`source_id`,`started_at`);--> statement-breakpoint
CREATE UNIQUE INDEX `idx_source_runs_idempotency` ON `source_runs` (`source_id`,`idempotency_key`);--> statement-breakpoint
CREATE TABLE `sources` (
	`id` text PRIMARY KEY NOT NULL,
	`vendor_id` text,
	`name` text NOT NULL,
	`kind` text NOT NULL,
	`discovery_url` text NOT NULL,
	`enabled` integer DEFAULT true NOT NULL,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL,
	FOREIGN KEY (`vendor_id`) REFERENCES `vendors`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE TABLE `vendors` (
	`id` text PRIMARY KEY NOT NULL,
	`name` text NOT NULL,
	`homepage_url` text,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL
);
