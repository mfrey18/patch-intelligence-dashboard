import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import "./helpers/register-typescript.mjs";

const policy = await import("../lib/ingestion/operational-policy.ts");
const { advanceCheckpoint, checkpointBatchKey, loadOrCreateCheckpoint, normalizeIngestionRequest } = await import("../lib/ingestion/orchestration.ts");
const { runVendorAdapter } = await import("../lib/ingestion/pipeline.ts");
const { calculatePriority } = await import("../lib/domain/priority.ts");
const { assertCveProvenance } = await import("../lib/api/provenance.ts");
const { normalizeRemediationRows } = await import("../lib/api/cve-query.ts");

test("rolling scope and Free-plan batch policy are centralized and calendar-safe", () => {
  assert.equal(policy.INTELLIGENCE_WINDOW_MONTHS, 6);
  assert.equal(policy.WORKERS_FREE_EXTERNAL_SUBREQUEST_LIMIT, 50);
  assert.equal(policy.MAX_ADVISORY_FETCHES_PER_INVOCATION, 12);
  assert.equal(policy.clampBatchSize(99), 12);
  assert.equal(policy.rollingWindowStart(new Date("2026-08-31T12:00:00Z")).toISOString(), "2026-02-28T00:00:00.000Z");
});

test("delta, replay, backfill, and Patch Tuesday requests create bounded deterministic checkpoints", () => {
  const now = new Date("2026-08-21T12:00:00.000Z");
  const delta = normalizeIngestionRequest("microsoft-msrc-csaf", { mode: "delta" }, now);
  assert.equal(delta.windowStart, "2026-08-18T12:00:00.000Z");
  assert.equal(delta.windowEnd, "2026-08-21T12:00:00.000Z");
  assert.match(delta.id, /^microsoft-msrc-csaf:delta:/);

  const backfill = normalizeIngestionRequest("microsoft-msrc-csaf", { mode: "backfill" }, now);
  assert.equal(backfill.coverageStart, "2026-02-21T00:00:00.000Z");
  assert.equal(backfill.windowEnd, "2026-02-21T23:59:59.999Z");
  const paloAltoBackfill = normalizeIngestionRequest("palo-alto-psirt-csaf", { mode: "backfill" }, now);
  assert.equal(paloAltoBackfill.windowEnd, "2026-02-27T23:59:59.999Z");

  const patchTuesday = normalizeIngestionRequest("microsoft-msrc-csaf", { mode: "patch_tuesday", since: "2026-08-11T00:00:00.000Z", until: "2026-08-12T00:00:00.000Z" }, now);
  assert.equal(patchTuesday.windowEnd, "2026-08-11T23:59:59.999Z");

  assert.throws(() => normalizeIngestionRequest("microsoft-msrc-csaf", { mode: "replay" }, now), /requires explicit/);
  assert.throws(() => normalizeIngestionRequest("microsoft-msrc-csaf", { mode: "backfill", since: "2026-02-20T23:59:59.999Z" }, now), /outside the rolling six-month/);
});

test("a default delta completes without a trailing checkpoint window", async () => {
  const now = new Date("2026-08-21T12:00:00.000Z");
  const planned = normalizeIngestionRequest("cisco-psirt-csaf", { mode: "delta" }, now);
  const writes = [];
  const db = {
    prepare(sql) {
      return { bind(...values) { return { async run() { writes.push({ sql, values }); return {}; } }; } };
    },
  };
  const checkpoint = { ...planned, continuation: null, status: "running" };
  const completed = await advanceCheckpoint(db, checkpoint, {
    sourceId: checkpoint.sourceId,
    runId: "run-success",
    status: "unchanged",
    mode: "delta",
    window: { since: checkpoint.windowStart, until: checkpoint.windowEnd },
    processed: 0,
    continuation: null,
    boundHit: false,
    counts: { discovered: 0, inserted: 0, changed: 0, unchanged: 0, failed: 0 },
    errors: [],
    startedAt: now.toISOString(),
    completedAt: now.toISOString(),
  });
  assert.equal(completed.status, "complete");
  assert.match(writes.at(-1).sql, /status='complete'/);
});

test("persisted checkpoints resume by identifier and do not advance a failed window", async () => {
  const stored = { id: "ms-six-month", source_id: "microsoft-msrc-csaf", mode: "backfill", coverage_start: "2026-02-21T00:00:00.000Z", coverage_end: "2026-08-21T12:00:00.000Z", window_start: "2026-02-21T00:00:00.000Z", window_end: "2026-02-21T23:59:59.999Z", continuation_token: "offset:12", status: "pending" };
  const writes = [];
  const db = {
    prepare(sql) {
      return { bind(...values) { return { async first() { return sql.startsWith("SELECT") ? stored : null; }, async run() { writes.push({ sql, values }); return {}; } }; } };
    },
  };
  const resumed = await loadOrCreateCheckpoint(db, "microsoft-msrc-csaf", { checkpointId: "ms-six-month", mode: "backfill" }, new Date("2026-08-22T12:00:00Z"));
  assert.equal(resumed.continuation, "offset:12");
  assert.equal(writes.length, 0);

  const failed = await advanceCheckpoint(db, resumed, { sourceId: resumed.sourceId, runId: "run-failed", status: "partial", mode: "backfill", window: { since: resumed.windowStart, until: resumed.windowEnd }, processed: 12, continuation: "offset:12", boundHit: true, counts: { discovered: 20, inserted: 10, changed: 0, unchanged: 0, failed: 2 }, errors: ["two source documents failed"], startedAt: "2026-08-21T00:00:00Z", completedAt: "2026-08-21T00:01:00Z" });
  assert.equal(failed.status, "failed");
  assert.equal(failed.windowStart, resumed.windowStart);
  assert.equal(writes.at(-1).values[0], "run-failed");
  assert.match(writes.at(-1).sql, /status='failed'/);
});

test("vendor pipeline stops at the Free-plan bound and resumes deterministically", async () => {
  const refs = Array.from({ length: 14 }, (_, index) => ({ id: `ADV-${String(index).padStart(2, "0")}`, url: `https://vendor.example/${index}`, sourceUpdatedAt: "2026-08-20T00:00:00.000Z" }));
  const adapter = {
    vendor: "microsoft",
    sourceId: "microsoft-msrc-csaf",
    async discover() { return refs; },
    async fetch(ref) { return { ref, contentType: "application/json", body: {}, fetchedAt: "2026-08-21T00:00:00.000Z", resolvedUrl: ref.url }; },
    async normalize(raw) { return [{ vendor: "microsoft", sourceId: "microsoft-msrc-csaf", vendorAdvisoryId: raw.ref.id, title: raw.ref.id, sourceUrl: raw.ref.url, exploitationStatus: "unknown", zeroDayStatus: "unknown", cves: [], affectedProducts: [], remediations: [], exploitEvidence: [] }]; },
  };
  const metadata = [];
  const repository = {
    async beginRun(_source, _key, value) { metadata.push(value); return { runId: crypto.randomUUID(), reused: false, continuation: null, boundHit: false }; },
    async finishRun() {},
    async latestRevision() { return null; },
    async saveAdvisory() { return "unchanged"; },
    async recordFailure() {},
  };
  const first = await runVendorAdapter(adapter, repository, { mode: "backfill", maxItems: 50, since: "2026-08-01T00:00:00.000Z", until: "2026-08-01T23:59:59.999Z" });
  assert.equal(first.processed, 12);
  assert.equal(first.continuation, "offset:12");
  assert.equal(first.boundHit, true);
  assert.equal(first.status, "partial");
  assert.equal(metadata[0].maxItems, 12);

  const second = await runVendorAdapter(adapter, repository, { mode: "backfill", continuation: first.continuation, maxItems: 12, since: first.window.since, until: first.window.until });
  assert.equal(second.processed, 2);
  assert.equal(second.continuation, null);
  assert.equal(second.boundHit, false);
});

test("CVE provenance acceptance requires authoritative links, observations, and explainable priority inputs", () => {
  const priority = calculatePriority({ kev: true, exploitationStatus: "known_exploited", severity: "critical", cvss: 9.8, epssPercentile: 0.97 });
  const detail = {
    canonical: { cveId: "CVE-2026-1000", description: null, cwe: null, cvss: null, cvssVector: null, publishedAt: null, modifiedAt: null, sourceUrl: null },
    priority,
    advisories: [{ id: "adv", sourceId: "microsoft-msrc-csaf", observedAt: "2026-08-21T00:00:00Z", vendor: "Microsoft", vendorAdvisoryId: "ADV", title: "Advisory", sourceUrl: "https://msrc.microsoft.com/update-guide/", vendorSeverity: "Critical", normalizedSeverity: "critical", vendorCvss: 9.8, vendorCvssVector: null, publishedAt: null, modifiedAt: null }],
    affectedProducts: [{ advisoryId: "adv", sourceId: "microsoft-msrc-csaf", vendor: "Microsoft", product: "Windows", affectedVersion: null, fixedVersion: "1.1", status: "affected", sourceProductId: null, sourceUrl: "https://msrc.microsoft.com/update-guide/", observedAt: "2026-08-21T00:00:00Z" }],
    remediations: [{ advisoryId: "adv", sourceId: "microsoft-msrc-csaf", observedAt: "2026-08-21T00:00:00Z", vendor: "Microsoft", kind: "fixed_version", patchAvailable: null, fixedVersion: "1.1", action: null, rebootRequired: null, superseded: null, sourceUrl: "https://msrc.microsoft.com/update-guide/", publishedAt: null, updatedAt: null }],
    exploitation: { knownExploited: true, zeroDay: false, evidence: [{ type: "known_exploitation", status: "confirmed", date: "2026-08-20", url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", summary: null, source: "CISA KEV", sourceId: "cisa-kev", observedAt: "2026-08-21T00:00:00Z" }] },
    kev: { active: true, dateAdded: "2026-08-20", dueDate: null, requiredAction: null, sourceUrl: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", sourceId: "cisa-kev", observedAt: "2026-08-21T00:00:00Z" },
    epss: { current: { scoreDate: "2026-08-21", score: 0.8, percentile: 0.97, modelVersion: null, sourceId: "first-epss", sourceUrl: "https://epss.empiricalsecurity.com/", observedAt: "2026-08-21T01:00:00Z" }, history: [{ scoreDate: "2026-08-21", score: 0.8, percentile: 0.97, modelVersion: null, sourceId: "first-epss", sourceUrl: "https://epss.empiricalsecurity.com/", observedAt: "2026-08-21T01:00:00Z" }] },
    advisoryRevisions: [], timeline: [], sourceLinks: [],
  };
  assert.doesNotThrow(() => assertCveProvenance(detail));
  assert.throws(() => assertCveProvenance({ ...detail, remediations: [{ ...detail.remediations[0], sourceUrl: "" }] }), /authoritative HTTPS source URL/);
  assert.throws(() => assertCveProvenance({ ...detail, priority: { ...priority, components: { ...priority.components, kev: false } } }), /Priority KEV component/);
});

test("production workflows apply migrations before Worker deployment and serialize Pages afterward", async () => {
  const worker = await readFile(new URL("../.github/workflows/cloudflare.yml", import.meta.url), "utf8");
  const pages = await readFile(new URL("../.github/workflows/pages.yml", import.meta.url), "utf8");
  const ingestion = await readFile(new URL("../.github/workflows/ingestion.yml", import.meta.url), "utf8");
  const vite = await readFile(new URL("../vite.config.ts", import.meta.url), "utf8");
  assert.ok(worker.indexOf("d1 migrations apply") < worker.indexOf("Deploy Worker and public assets"));
  assert.ok(worker.indexOf("Deploy Worker and public assets") < worker.indexOf("Smoke-test Worker"));
  assert.match(worker, /group: production-deployment/);
  assert.match(worker, /environment:\s+name: production-worker/);
  assert.match(worker, /wrangler d1 info .* --json/);
  assert.match(worker, /actions\/upload-artifact@v4/);
  assert.match(pages, /workflow_run:/);
  assert.match(pages, /group: production-deployment/);
  assert.match(ingestion, /ENABLE_SCHEDULED_INGESTION == 'true'/);
  assert.match(ingestion, /fail-fast: false/);
  assert.match(ingestion, /source: microsoft-msrc-csaf, max_attempts: 50/, "Microsoft must have enough resumable Worker invocations for the observed change volume");
  assert.match(ingestion, /if \$checkpoint == "" then \{\} else \{checkpointId:\$checkpoint\} end/, "manual dispatch must omit blank checkpoint IDs");
  assert.match(ingestion, /backfill:\$\{SOURCE_ID\}:six-month/, "backfills need a stable default checkpoint across workflow runs");
  assert.match(ingestion, /test "\$MAX_ATTEMPTS" -ge 1 && test "\$MAX_ATTEMPTS" -le 50/, "manual orchestration must remain bounded");
  assert.match(ingestion, /Checkpoint remains resumable/, "a bounded workflow run must preserve rather than fail valid partial progress");
  assert.match(ingestion, /source: cisco-psirt-csaf, max_attempts: 4, batch_size: 1/, "Cisco must isolate each large CSAF document within its own Workers Free invocation");
  assert.match(ingestion, /\[ "\$result_status" = "failed" \] \|\| \[ "\$result_status" = "skipped" \]/, "active or stuck source leases must not be reported as successful completion");
  const dailyMatrix = ingestion.slice(ingestion.indexOf("matrix:"), ingestion.indexOf("name: Daily source"));
  for (const source of ["microsoft-msrc-csaf", "cisco-psirt-csaf", "cisa-kev", "first-epss", "palo-alto-psirt-csaf", "mozilla-mfsa-yaml"]) assert.match(dailyMatrix, new RegExp(source));
  for (const quarantined of ["adobe-psirt-csaf", "fortinet-psirt-csaf", "ivanti-security-advisory-rss", "oracle-cpu-csaf", "atlassian-vulnerability-api"]) assert.doesNotMatch(dailyMatrix, new RegExp(quarantined));
  assert.doesNotMatch(ingestion, /sources:\s*\[[^\]]+,[^\]]+\]/, "each request must contain one source");
  assert.doesNotMatch(vite, /limits:\s*\{/, "Workers Free deployments must use platform limits rather than paid-plan runtime limits");
});

test("D1 health uses supported Worker SQL and deployment-owned size discovery", async () => {
  const health = await readFile(new URL("../lib/operations/d1-health.ts", import.meta.url), "utf8");
  assert.doesNotMatch(health, /PRAGMA\s+(?:page_count|page_size)/i);
  assert.match(health, /databaseSizeSource:\s*"wrangler_d1_info_required"/);
  assert.match(health, /estimatedBytes:\s*null/);
});

test("large advisory components use atomic JSON-backed D1 bulk inserts", async () => {
  const repository = await readFile(new URL("../lib/ingestion/d1-repository.ts", import.meta.url), "utf8");
  assert.match(repository, /FROM json_each\(\?\)/);
  assert.match(repository, /JSON\.stringify\(affectedRecords\)/);
  assert.match(repository, /JSON\.stringify\(remediationRecords\)/);
  assert.match(repository, /await this\.db\.batch\(queries\)/, "bulk inserts must remain in the advisory transaction");
  assert.doesNotMatch(repository, /queries\.push\(this\.db\.prepare\("INSERT INTO affected_products/, "affected products must not create one RPC statement per assertion");
});

test("advisory revision history permits a material A to B to A reversion", async () => {
  const schema = await readFile(new URL("../db/schema.ts", import.meta.url), "utf8");
  const migration = await readFile(new URL("../migrations/0003_allow_advisory_state_reversions.sql", import.meta.url), "utf8");
  const repository = await readFile(new URL("../lib/ingestion/d1-repository.ts", import.meta.url), "utf8");

  assert.match(schema, /index\("idx_advisory_revisions_advisory_hash"\)/);
  assert.doesNotMatch(schema, /uniqueIndex\("idx_advisory_revisions_advisory_hash"\)/);
  assert.match(migration, /DROP INDEX IF EXISTS `idx_advisory_revisions_advisory_hash`/);
  assert.match(migration, /CREATE INDEX `idx_advisory_revisions_advisory_hash`/);
  assert.doesNotMatch(migration, /CREATE UNIQUE INDEX/);
  assert.match(repository, /previous\?\.contentHash === hashes\.contentHash/, "consecutive identical source states must still be idempotent");
});

test("operations monitoring captures D1 capacity before enforcing the health gate", async () => {
  const workflow = await readFile(new URL("../.github/workflows/operations-monitor.yml", import.meta.url), "utf8");
  const capture = workflow.indexOf("Capture authenticated operational health");
  const capacity = workflow.indexOf("Capture D1 capacity");
  const publish = workflow.indexOf("Publish or resolve production alert");
  const enforce = workflow.indexOf("Enforce production health gate");
  assert.ok(capture >= 0 && capacity > capture && publish > capacity && enforce > publish);
  assert.match(workflow, /databaseWarningBytes:400000000/);
  assert.match(workflow, /dashboardCoreLatencyMs < 1000 and \.databaseBytes < \.databaseWarningBytes/);
});

test("retired deployment checkpoints are closed without touching operational backfill", async () => {
  const migration = await readFile(new URL("../migrations/0008_close_deployment_ingestion_checkpoints.sql", import.meta.url), "utf8");
  assert.match(migration, /status = 'pending'/);
  assert.match(migration, /continuation_token = NULL/);
  assert.match(migration, /gate1:microsoft:%/);
  assert.match(migration, /deploy:release-note:%/);
  assert.doesNotMatch(migration, /DELETE FROM ingestion_checkpoints/i);
  assert.doesNotMatch(migration, /backfill:/i);
});

test("a newly named deterministic replay reopens the canonical completed range", async () => {
  const stored = { id: "prior-replay", source_id: "microsoft-msrc-csaf", mode: "replay", coverage_start: "2026-08-11T00:00:00.000Z", coverage_end: "2026-08-11T23:59:59.999Z", window_start: "2026-08-11T00:00:00.000Z", window_end: "2026-08-11T23:59:59.999Z", continuation_token: null, status: "complete" };
  const writes = [];
  const db = {
    prepare(sql) {
      return { bind(...values) { return {
        async first() {
          if (/WHERE id=\?/.test(sql)) return values[0] === stored.id ? stored : null;
          if (/WHERE source_id=\?/.test(sql)) return stored;
          return null;
        },
        async run() { writes.push({ sql, values }); return {}; },
      }; } };
    },
  };
  const replay = await loadOrCreateCheckpoint(db, "microsoft-msrc-csaf", { checkpointId: "deploy-replay", mode: "replay", since: stored.coverage_start, until: stored.coverage_end }, new Date("2026-08-26T12:00:00Z"));
  assert.equal(replay.id, "prior-replay");
  assert.equal(replay.status, "pending");
  assert.equal(checkpointBatchKey(replay), "prior-replay:2026-08-11T00:00:00.000Z:start");
  assert.equal(checkpointBatchKey(replay, "deploy-replay"), "prior-replay:generation:deploy-replay:2026-08-11T00:00:00.000Z:start");
  assert.equal(checkpointBatchKey(replay, "deploy-replay"), checkpointBatchKey(replay, "deploy-replay"), "the same replay generation remains idempotent when resumed");
  assert.match(writes[0].sql, /ON CONFLICT DO NOTHING/);
  assert.match(writes.at(-1).sql, /status='pending'.*completed_at=NULL/);
});

test("CVE detail exposes component-level advisory revision comparison with provenance", async () => {
  const query = await readFile(new URL("../lib/api/cve-query.ts", import.meta.url), "utf8");
  const detail = await readFile(new URL("../app/cve/[id]/CveDetailClient.tsx", import.meta.url), "utf8");
  assert.match(query, /LAG\(ar\.content_hash\)/);
  assert.match(query, /LAG\(ar\.affected_products_hash\)/);
  assert.match(query, /LAG\(ar\.remediation_hash\)/);
  assert.match(detail, /Advisory Revision Comparison/);
  assert.match(detail, /Affected products/);
  assert.match(detail, /Remediation/);
});

test("CVE detail groups identical remediation assertions while preserving product scope", () => {
  const base = { advisory_id: "cisco:advisory", source_id: "cisco-psirt-csaf", observed_at: "2026-08-27T00:00:00Z", vendor: "Cisco", kind: "patch", patch_available: 1, fixed_version: null, action: "Install the vendor update.", reboot_required: null, superseded: null, source_url: "https://software.cisco.com", published_at: null, updated_at: "2026-08-27T00:00:00Z" };
  const grouped = normalizeRemediationRows([{ ...base, product: "Release 1.0" }, { ...base, product: "Release 1.1" }, { ...base, product: "Release 1.0" }, { ...base, product: "Release 2.0", action: "Apply the workaround." }]);
  assert.equal(grouped.length, 2);
  assert.deepEqual(grouped[0].products, ["Release 1.0", "Release 1.1"]);
  assert.deepEqual(grouped[1].products, ["Release 2.0"]);
  assert.equal(grouped[0].patchAvailable, true);
});

test("Patch Tuesday totals retain Microsoft release-note provenance separately from linked CVEs", async () => {
  const migration = await readFile(new URL("../migrations/0004_release_event_reported_totals.sql", import.meta.url), "utf8");
  const query = await readFile(new URL("../lib/api/dashboard-query.ts", import.meta.url), "utf8");
  const dashboard = await readFile(new URL("../app/DashboardClient.tsx", import.meta.url), "utf8");
  assert.match(migration, /reported_cve_count/);
  assert.match(query, /const reported = event\.reported_cve_count == null \? null/);
  assert.match(query, /totalBasis: reported == null \? "linked_advisories" : "vendor_reported"/);
  assert.match(query, /reconciliationStatus/);
  assert.match(dashboard, /Microsoft-reported CVEs/);
  assert.match(dashboard, /Successfully linked in D1/);
  assert.match(dashboard, /Linked CVEs drive severity, threat, and product metrics/);
});

test("Patch Tuesday membership excludes Microsoft VEX records and preserves release-note provenance", async () => {
  const microsoft = await readFile(new URL("../lib/ingestion/adapters/microsoft.ts", import.meta.url), "utf8");
  const repository = await readFile(new URL("../lib/ingestion/d1-repository.ts", import.meta.url), "utf8");
  const query = await readFile(new URL("../lib/api/dashboard-query.ts", import.meta.url), "utf8");
  const migration = await readFile(new URL("../migrations/0007_patch_tuesday_authoritative_membership.sql", import.meta.url), "utf8");
  assert.match(microsoft, /mayAssociateRelease.*documentType === "advisory"/s);
  assert.match(repository, /source_url=CASE WHEN excluded\.reported_cve_count IS NOT NULL/);
  assert.match(query, /vendor_advisory_id LIKE 'advisory:%'[\s\S]*vendor_advisory_id LIKE 'release-membership:%'/);
  assert.match(migration, /vendor_advisory_id` LIKE 'vex:%'/);
  assert.match(migration, /vendor_advisory_id` LIKE 'release-note:%'/);
  assert.match(migration, /UPDATE `sources`[\s\S]*'mozilla-mfsa-yaml'[\s\S]*THEN 1 ELSE 0 END/);
  const deployment = await readFile(new URL("../.github/workflows/cloudflare.yml", import.meta.url), "utf8");
  assert.doesNotMatch(deployment, /Refresh latest Microsoft release-note assertions|Validate one bounded Microsoft delta batch|checkpointId/, "production deployment must not create partial ingestion checkpoints");
  assert.match(deployment, /reconciliationStatus != "overlinked"/);
  assert.match(deployment, /productFamilyBasis == "vendor_reported"/);
});

test("production implementation no longer claims a 24-month scope", async () => {
  const files = ["../README.md", "../app/DashboardClient.tsx", "../lib/api/dashboard-query.ts", "../docs/github-pages-cloudflare.md"];
  for (const file of files) assert.doesNotMatch(await readFile(new URL(file, import.meta.url), "utf8"), /24[- ]month|24 months|-24 months/i, file);
});

test("gate documentation uses outcome-based release framing", async () => {
  const gate = await readFile(new URL("../docs/production-readiness.md", import.meta.url), "utf8");
  assert.doesNotMatch(gate, /mark PR #1 ready|PR #1 may be marked ready/i);
  assert.match(gate, /PASS requires evidence/);
  assert.match(gate, /FAIL.*until PR #5 is reviewed/s);
});
