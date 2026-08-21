import { index, integer, primaryKey, real, sqliteTable, text, uniqueIndex } from "drizzle-orm/sqlite-core";

const timestamps = { createdAt: text("created_at").notNull(), updatedAt: text("updated_at").notNull() };

export const vendors = sqliteTable("vendors", { id: text("id").primaryKey(), name: text("name").notNull(), homepageUrl: text("homepage_url"), ...timestamps });

export const products = sqliteTable("products", { id: text("id").primaryKey(), vendorId: text("vendor_id").notNull().references(() => vendors.id), name: text("name").notNull(), family: text("family"), ...timestamps }, (table) => [uniqueIndex("idx_products_vendor_name").on(table.vendorId, table.name)]);

export const productVersions = sqliteTable("product_versions", { id: text("id").primaryKey(), productId: text("product_id").notNull().references(() => products.id), version: text("version").notNull(), release: text("release"), ...timestamps }, (table) => [uniqueIndex("idx_product_versions_product_version").on(table.productId, table.version)]);

export const sources = sqliteTable("sources", { id: text("id").primaryKey(), vendorId: text("vendor_id").references(() => vendors.id), name: text("name").notNull(), kind: text("kind").notNull(), discoveryUrl: text("discovery_url").notNull(), enabled: integer("enabled", { mode: "boolean" }).notNull().default(true), ...timestamps });

export const sourceRuns = sqliteTable("source_runs", {
  id: text("id").primaryKey(), sourceId: text("source_id").notNull().references(() => sources.id), idempotencyKey: text("idempotency_key"), startedAt: text("started_at").notNull(), completedAt: text("completed_at"), status: text("status").notNull(), datasetDate: text("dataset_date"), sourceHash: text("source_hash"), recordsDiscovered: integer("records_discovered").notNull().default(0), recordsInserted: integer("records_inserted").notNull().default(0), recordsChanged: integer("records_changed").notNull().default(0), recordsUnchanged: integer("records_unchanged").notNull().default(0), recordsFailed: integer("records_failed").notNull().default(0), errorSummary: text("error_summary"),
}, (table) => [index("idx_source_runs_source_started").on(table.sourceId, table.startedAt), uniqueIndex("idx_source_runs_idempotency").on(table.sourceId, table.idempotencyKey)]);

export const sourceRunResults = sqliteTable("source_run_results", { id: text("id").primaryKey(), sourceRunId: text("source_run_id").notNull().references(() => sourceRuns.id), sourceRef: text("source_ref").notNull(), status: text("status").notNull(), changeTypesJson: text("change_types_json").notNull().default("[]"), errorSummary: text("error_summary"), durationMs: integer("duration_ms").notNull().default(0), observedAt: text("observed_at").notNull() }, (table) => [index("idx_source_run_results_run").on(table.sourceRunId)]);

export const releaseEvents = sqliteTable("release_events", { id: text("id").primaryKey(), vendorId: text("vendor_id").notNull().references(() => vendors.id), eventType: text("event_type").notNull(), eventDate: text("event_date").notNull(), label: text("label").notNull(), sourceUrl: text("source_url"), ...timestamps }, (table) => [uniqueIndex("idx_release_events_vendor_type_date").on(table.vendorId, table.eventType, table.eventDate)]);

export const advisories = sqliteTable("advisories", {
  id: text("id").primaryKey(), vendorId: text("vendor_id").notNull().references(() => vendors.id), sourceId: text("source_id").notNull().references(() => sources.id), vendorAdvisoryId: text("vendor_advisory_id").notNull(), title: text("title").notNull(), summary: text("summary"), sourceUrl: text("source_url").notNull(), publishedAt: text("published_at"), sourceUpdatedAt: text("source_updated_at"), withdrawnAt: text("withdrawn_at"), ...timestamps,
}, (table) => [uniqueIndex("idx_advisories_vendor_advisory").on(table.vendorId, table.vendorAdvisoryId), index("idx_advisories_published").on(table.publishedAt)]);

export const releaseEventAdvisories = sqliteTable("release_event_advisories", { releaseEventId: text("release_event_id").notNull().references(() => releaseEvents.id), advisoryId: text("advisory_id").notNull().references(() => advisories.id) }, (table) => [primaryKey({ columns: [table.releaseEventId, table.advisoryId] })]);

export const advisoryRevisions = sqliteTable("advisory_revisions", {
  id: text("id").primaryKey(), advisoryId: text("advisory_id").notNull().references(() => advisories.id), sourceRunId: text("source_run_id").references(() => sourceRuns.id), observedAt: text("observed_at").notNull(), sourceUpdatedAt: text("source_updated_at"), contentHash: text("content_hash").notNull(), affectedProductsHash: text("affected_products_hash").notNull(), remediationHash: text("remediation_hash").notNull(), exploitationStatus: text("exploitation_status").notNull(), vendorSeverity: text("vendor_severity"), cvssScore: real("cvss_score"), changeTypesJson: text("change_types_json").notNull(), normalizedJson: text("normalized_json").notNull(), sourceUrl: text("source_url").notNull(),
}, (table) => [uniqueIndex("idx_advisory_revisions_advisory_hash").on(table.advisoryId, table.contentHash), index("idx_advisory_revisions_observed").on(table.observedAt)]);

export const cves = sqliteTable("cves", { id: text("id").primaryKey(), description: text("description"), cwe: text("cwe"), cvssScore: real("cvss_score"), cvssVector: text("cvss_vector"), publishedAt: text("published_at"), modifiedAt: text("modified_at"), canonicalSourceUrl: text("canonical_source_url"), ...timestamps }, (table) => [index("idx_cves_published").on(table.publishedAt)]);

export const advisoryCves = sqliteTable("advisory_cves", { advisoryId: text("advisory_id").notNull().references(() => advisories.id), cveId: text("cve_id").notNull().references(() => cves.id), vendorDescription: text("vendor_description"), vendorCwe: text("vendor_cwe"), vendorSeverity: text("vendor_severity"), normalizedSeverity: text("normalized_severity").notNull(), vendorCvssScore: real("vendor_cvss_score"), vendorCvssVector: text("vendor_cvss_vector") }, (table) => [primaryKey({ columns: [table.advisoryId, table.cveId] }), index("idx_advisory_cves_cve").on(table.cveId), index("idx_advisory_cves_severity").on(table.normalizedSeverity)]);

export const affectedProducts = sqliteTable("affected_products", {
  id: text("id").primaryKey(), advisoryId: text("advisory_id").notNull().references(() => advisories.id), advisoryRevisionId: text("advisory_revision_id").notNull().references(() => advisoryRevisions.id), cveId: text("cve_id").references(() => cves.id), productId: text("product_id").notNull().references(() => products.id), affectedVersion: text("affected_version"), fixedVersion: text("fixed_version"), status: text("status").notNull(), sourceProductId: text("source_product_id"),
}, (table) => [index("idx_affected_products_advisory_revision").on(table.advisoryId, table.advisoryRevisionId), index("idx_affected_products_cve").on(table.cveId)]);

export const remediations = sqliteTable("remediations", {
  id: text("id").primaryKey(), advisoryId: text("advisory_id").notNull().references(() => advisories.id), advisoryRevisionId: text("advisory_revision_id").notNull().references(() => advisoryRevisions.id), cveId: text("cve_id").references(() => cves.id), productId: text("product_id").references(() => products.id), kind: text("kind").notNull(), patchAvailable: integer("patch_available", { mode: "boolean" }), fixedVersion: text("fixed_version"), action: text("action"), rebootRequired: integer("reboot_required", { mode: "boolean" }), superseded: integer("superseded", { mode: "boolean" }), sourceUrl: text("source_url").notNull(), publishedAt: text("published_at"), updatedAt: text("updated_at"),
}, (table) => [index("idx_remediations_cve").on(table.cveId), index("idx_remediations_advisory_revision").on(table.advisoryId, table.advisoryRevisionId)]);

export const exploitEvidence = sqliteTable("exploit_evidence", {
  id: text("id").primaryKey(), cveId: text("cve_id").notNull().references(() => cves.id), advisoryId: text("advisory_id").references(() => advisories.id), sourceId: text("source_id").notNull().references(() => sources.id), evidenceType: text("evidence_type").notNull(), status: text("status").notNull(), evidenceDate: text("evidence_date"), evidenceUrl: text("evidence_url").notNull(), summary: text("summary"), firstObservedAt: text("first_observed_at").notNull(), lastObservedAt: text("last_observed_at").notNull(),
}, (table) => [uniqueIndex("idx_exploit_evidence_identity").on(table.cveId, table.sourceId, table.evidenceType, table.evidenceUrl)]);

export const kevEntries = sqliteTable("kev_entries", {
  cveId: text("cve_id").primaryKey().references(() => cves.id), sourceRunId: text("source_run_id").references(() => sourceRuns.id), active: integer("active", { mode: "boolean" }).notNull(), dateAdded: text("date_added").notNull(), dueDate: text("due_date"), requiredAction: text("required_action"), knownRansomwareCampaignUse: text("known_ransomware_campaign_use"), entryHash: text("entry_hash").notNull(), sourceUrl: text("source_url").notNull(), firstObservedAt: text("first_observed_at").notNull(), lastObservedAt: text("last_observed_at").notNull(), removedAt: text("removed_at"),
}, (table) => [index("idx_kev_entries_active_due").on(table.active, table.dueDate)]);

export const epssDatasets = sqliteTable("epss_datasets", { scoreDate: text("score_date").primaryKey(), sourceRunId: text("source_run_id").notNull().references(() => sourceRuns.id), modelVersion: text("model_version"), sourceHash: text("source_hash").notNull(), sourceUrl: text("source_url").notNull(), rowCount: integer("row_count").notNull(), matchedCveCount: integer("matched_cve_count").notNull(), status: text("status").notNull(), isCurrent: integer("is_current", { mode: "boolean" }).notNull().default(false), publishedAt: text("published_at").notNull() });

export const epssObservations = sqliteTable("epss_observations", { cveId: text("cve_id").notNull().references(() => cves.id), scoreDate: text("score_date").notNull().references(() => epssDatasets.scoreDate), score: real("score").notNull(), percentile: real("percentile").notNull(), modelVersion: text("model_version"), sourceRunId: text("source_run_id").notNull().references(() => sourceRuns.id), observedAt: text("observed_at").notNull() }, (table) => [primaryKey({ columns: [table.cveId, table.scoreDate] }), index("idx_epss_observations_date").on(table.scoreDate)]);

export const intelligenceChanges = sqliteTable("intelligence_changes", {
  id: text("id").primaryKey(), sourceRunId: text("source_run_id").notNull().references(() => sourceRuns.id), entityType: text("entity_type").notNull(), entityId: text("entity_id").notNull(), cveId: text("cve_id").references(() => cves.id), advisoryId: text("advisory_id").references(() => advisories.id), changeType: text("change_type").notNull(), observedAt: text("observed_at").notNull(), beforeJson: text("before_json"), afterJson: text("after_json"), summary: text("summary").notNull(),
}, (table) => [index("idx_intelligence_changes_observed").on(table.observedAt), index("idx_intelligence_changes_cve").on(table.cveId)]);

export const ingestionLeases = sqliteTable("ingestion_leases", { sourceId: text("source_id").primaryKey().references(() => sources.id), holder: text("holder").notNull(), acquiredAt: text("acquired_at").notNull(), expiresAt: text("expires_at").notNull() });
