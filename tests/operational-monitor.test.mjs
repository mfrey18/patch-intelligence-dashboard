import "./helpers/register-typescript.mjs";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const { captureOperationalMonitor, OPERATIONAL_THRESHOLDS } = await import("../lib/operations/operational-monitor.ts");

const sourceIds = ["cisa-kev", "first-epss", "microsoft-msrc-csaf", "cisco-psirt-csaf", "palo-alto-psirt-csaf", "mozilla-mfsa-yaml"];

function monitorDb(overrides = {}) {
  const state = { generated_at: "2026-08-26T11:00:00.000Z", cve_count: 7, parity_status: "passed", parity_checked_at: "2026-08-26T11:00:00.000Z", last_attempt_status: "success", last_attempt_at: "2026-08-26T11:00:00.000Z", last_attempt_error: null, ...overrides.state };
  const sources = sourceIds.map((sourceId) => ({ source_id: sourceId, last_attempt: "2026-08-26T10:00:00.000Z", last_success: "2026-08-26T10:00:00.000Z", last_failure: null, result: "success", failed: 0, failures_24h: 0, bound_hits_24h: 0, ...overrides.source }));
  return {
    prepare(sql) {
      return {
        bind() { return this; },
        async first() {
          if (/dashboard_projection_state/.test(sql)) return state;
          if (/COUNT\(\*\) count FROM cve_dashboard_facts/.test(sql)) return { count: overrides.actualCount ?? 7 };
          if (/dashboard_projection_leases/.test(sql)) return overrides.projectionLease ?? null;
          if (/MAX\(completed_at\)/.test(sql)) return { completed_at: overrides.latestSuccess ?? "2026-08-26T10:00:00.000Z" };
          return null;
        },
        async all() {
          if (/FROM sources s/.test(sql)) return { results: sources };
          if (/FROM ingestion_leases/.test(sql)) return { results: overrides.ingestionLeases ?? [] };
          return { results: [] };
        },
      };
    },
  };
}

test("operational monitor reports a fresh parity-checked system as healthy", async () => {
  const result = await captureOperationalMonitor(monitorDb(), new Date("2026-08-26T12:00:00.000Z"), async () => 200);
  assert.equal(result.status, "healthy");
  assert.equal(result.projection.actualCount, 7);
  assert.equal(result.sources.length, 6);
  assert.deepEqual(result.alerts, []);
});

test("operational monitor explains parity, lag, freshness, bounds, lease, and latency failures", async () => {
  const result = await captureOperationalMonitor(monitorDb({
    state: { generated_at: "2026-08-24T00:00:00.000Z", cve_count: 8, parity_status: "failed", last_attempt_status: "failed", last_attempt_error: "parity mismatch" },
    actualCount: 7,
    latestSuccess: "2026-08-26T11:30:00.000Z",
    source: { last_success: "2026-08-24T00:00:00.000Z", last_failure: "2026-08-26T11:00:00.000Z", result: "failed", failed: 1, failures_24h: 4, bound_hits_24h: 4 },
    ingestionLeases: [{ source_id: "microsoft-msrc-csaf", acquired_at: "2026-08-26T11:40:00.000Z", expires_at: "2026-08-26T11:50:00.000Z" }],
  }), new Date("2026-08-26T12:00:00.000Z"), async () => 1_500);
  assert.equal(result.status, "unhealthy");
  const codes = new Set(result.alerts.map((alert) => alert.code));
  for (const code of ["projection_stale", "projection_count_mismatch", "projection_parity_unverified", "projection_refresh_failed", "projection_behind_ingestion", "source_stale", "source_latest_attempt_failed", "source_repeated_failures", "source_repeated_bound_hits", "ingestion_lease_expired", "dashboard_core_slow"]) assert.ok(codes.has(code), code);
});

test("retention cleanup of an abandoned historical run does not replace a successful latest attempt", async () => {
  const result = await captureOperationalMonitor(monitorDb({
    source: { result: "success", failed: 0, last_success: "2026-08-26T11:30:00.000Z", last_failure: "2026-08-26T11:45:00.000Z", failures_24h: 1 },
  }), new Date("2026-08-26T12:00:00.000Z"), async () => 200);
  assert.equal(result.status, "healthy");
  assert.ok(!result.alerts.some((alert) => alert.code === "source_latest_attempt_failed"));
});

test("operational thresholds and daily monitoring workflow are explicit", () => {
  assert.deepEqual(OPERATIONAL_THRESHOLDS, { projectionStaleHours: 36, sourceStaleHours: 36, coreLatencyMs: 1000, repeatedBoundHits24h: 3, repeatedFailures24h: 3, leaseStuckMinutes: 8 });
  const workflow = readFileSync(new URL("../.github/workflows/operations-monitor.yml", import.meta.url), "utf8");
  assert.match(workflow, /api\/internal\/monitor/);
  assert.match(workflow, /databaseWarningBytes:400000000/);
  assert.match(workflow, /status != "unhealthy"/);
  assert.match(workflow, /issues: write/);
  assert.match(workflow, /Publish or resolve production alert/);
  for (const code of ["source_stale", "source_repeated_failures", "projection_behind_ingestion", "projection_parity_unverified", "ingestion_lease_expired", "source_repeated_bound_hits", "dashboard_core_slow"]) assert.match(readFileSync(new URL("../lib/operations/operational-monitor.ts", import.meta.url), "utf8"), new RegExp(code));
  assert.doesNotMatch(workflow, /localhost/);
});
