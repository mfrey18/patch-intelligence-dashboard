import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import "./helpers/register-typescript.mjs";

const policy = await import("../lib/ingestion/operational-policy.ts");
const { advanceCheckpoint, loadOrCreateCheckpoint, normalizeIngestionRequest } = await import("../lib/ingestion/orchestration.ts");
const { runVendorAdapter } = await import("../lib/ingestion/pipeline.ts");
const { calculatePriority } = await import("../lib/domain/priority.ts");
const { assertCveProvenance } = await import("../lib/api/provenance.ts");

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
  assert.equal(delta.windowEnd, "2026-08-21T11:59:59.999Z");
  assert.match(delta.id, /^microsoft-msrc-csaf:delta:/);

  const backfill = normalizeIngestionRequest("microsoft-msrc-csaf", { mode: "backfill" }, now);
  assert.equal(backfill.coverageStart, "2026-02-21T00:00:00.000Z");
  assert.equal(backfill.windowEnd, "2026-02-21T23:59:59.999Z");

  const patchTuesday = normalizeIngestionRequest("microsoft-msrc-csaf", { mode: "patch_tuesday", since: "2026-08-11T00:00:00.000Z", until: "2026-08-12T00:00:00.000Z" }, now);
  assert.equal(patchTuesday.windowEnd, "2026-08-11T23:59:59.999Z");

  assert.throws(() => normalizeIngestionRequest("microsoft-msrc-csaf", { mode: "replay" }, now), /requires explicit/);
  assert.throws(() => normalizeIngestionRequest("microsoft-msrc-csaf", { mode: "backfill", since: "2026-02-20T23:59:59.999Z" }, now), /outside the rolling six-month/);
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
    timeline: [], sourceLinks: [],
  };
  assert.doesNotThrow(() => assertCveProvenance(detail));
  assert.throws(() => assertCveProvenance({ ...detail, remediations: [{ ...detail.remediations[0], sourceUrl: "" }] }), /authoritative HTTPS source URL/);
  assert.throws(() => assertCveProvenance({ ...detail, priority: { ...priority, components: { ...priority.components, kev: false } } }), /Priority KEV component/);
});

test("production workflows apply migrations before Worker deployment and serialize Pages afterward", async () => {
  const worker = await readFile(new URL("../.github/workflows/cloudflare.yml", import.meta.url), "utf8");
  const pages = await readFile(new URL("../.github/workflows/pages.yml", import.meta.url), "utf8");
  const ingestion = await readFile(new URL("../.github/workflows/ingestion.yml", import.meta.url), "utf8");
  assert.ok(worker.indexOf("d1 migrations apply") < worker.indexOf("Deploy Worker and public assets"));
  assert.ok(worker.indexOf("Deploy Worker and public assets") < worker.indexOf("Smoke-test Worker"));
  assert.match(worker, /group: production-deployment/);
  assert.match(worker, /environment:\s+name: production-worker/);
  assert.match(pages, /workflow_run:/);
  assert.match(pages, /group: production-deployment/);
  assert.match(ingestion, /ENABLE_SCHEDULED_INGESTION == 'true'/);
  assert.match(ingestion, /fail-fast: false/);
  assert.doesNotMatch(ingestion, /sources:\s*\[[^\]]+,[^\]]+\]/, "each request must contain one source");
});

test("production implementation no longer claims a 24-month scope", async () => {
  const files = ["../README.md", "../app/DashboardClient.tsx", "../lib/api/dashboard-query.ts", "../docs/github-pages-cloudflare.md"];
  for (const file of files) assert.doesNotMatch(await readFile(new URL(file, import.meta.url), "utf8"), /24[- ]month|24 months|-24 months/i, file);
});
