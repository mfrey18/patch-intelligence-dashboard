ALTER TABLE `source_runs` ADD COLUMN `ingestion_mode` text NOT NULL DEFAULT 'delta';
ALTER TABLE `source_runs` ADD COLUMN `window_start` text;
ALTER TABLE `source_runs` ADD COLUMN `window_end` text;
ALTER TABLE `source_runs` ADD COLUMN `continuation_in` text;
ALTER TABLE `source_runs` ADD COLUMN `continuation_out` text;
ALTER TABLE `source_runs` ADD COLUMN `checkpoint_id` text;
ALTER TABLE `source_runs` ADD COLUMN `max_items` integer NOT NULL DEFAULT 12;
ALTER TABLE `source_runs` ADD COLUMN `bound_hit` integer NOT NULL DEFAULT 0;

CREATE TABLE `ingestion_checkpoints` (
	`id` text PRIMARY KEY NOT NULL,
	`source_id` text NOT NULL,
	`mode` text NOT NULL,
	`coverage_start` text NOT NULL,
	`coverage_end` text NOT NULL,
	`window_start` text NOT NULL,
	`window_end` text NOT NULL,
	`continuation_token` text,
	`status` text NOT NULL,
	`last_run_id` text,
	`last_error` text,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL,
	`completed_at` text,
	FOREIGN KEY (`source_id`) REFERENCES `sources`(`id`) ON UPDATE no action ON DELETE no action,
	FOREIGN KEY (`last_run_id`) REFERENCES `source_runs`(`id`) ON UPDATE no action ON DELETE no action
);

CREATE UNIQUE INDEX `idx_ingestion_checkpoints_identity` ON `ingestion_checkpoints` (`source_id`,`mode`,`coverage_start`,`coverage_end`);
CREATE INDEX `idx_ingestion_checkpoints_status_updated` ON `ingestion_checkpoints` (`status`,`updated_at`);
CREATE INDEX `idx_source_runs_status_completed` ON `source_runs` (`status`,`completed_at`);
CREATE INDEX `idx_source_runs_checkpoint` ON `source_runs` (`checkpoint_id`,`started_at`);
CREATE INDEX `idx_advisories_vendor_published` ON `advisories` (`vendor_id`,`published_at`);
CREATE INDEX `idx_advisories_modified` ON `advisories` (`source_updated_at`);
CREATE INDEX `idx_advisory_revisions_advisory_observed` ON `advisory_revisions` (`advisory_id`,`observed_at`);
CREATE INDEX `idx_advisory_cves_severity_cve` ON `advisory_cves` (`normalized_severity`,`cve_id`);
CREATE INDEX `idx_affected_products_product_cve_revision` ON `affected_products` (`product_id`,`cve_id`,`advisory_revision_id`);
CREATE INDEX `idx_remediations_state_cve_revision` ON `remediations` (`patch_available`,`kind`,`cve_id`,`advisory_revision_id`);
CREATE INDEX `idx_exploit_evidence_state_cve` ON `exploit_evidence` (`evidence_type`,`status`,`cve_id`);
CREATE INDEX `idx_epss_datasets_current_date` ON `epss_datasets` (`is_current`,`score_date`);
CREATE INDEX `idx_intelligence_changes_type_observed_cve` ON `intelligence_changes` (`change_type`,`observed_at`,`cve_id`);
