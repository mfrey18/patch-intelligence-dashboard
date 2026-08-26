import "./helpers/register-typescript.mjs";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const { refreshDashboardProjection } = await import("../lib/operations/dashboard-projection.ts");

test("dashboard projection is atomically published from authoritative tables", async () => {
  const prepared = [];
  const batchSizes = [];
  let leaseHolder = null;
  const metrics = { total: 7, critical: 1, high: 2, known_exploited: 1, kev: 1, zero_day: 0, patch_available: 3, p1: 1, p2: 2, microsoft: 4, cisco: 3 };
  const db = {
    prepare(sql) {
      const statement = {
        sql,
        values: [],
        bind(...values) { this.values = values; return this; },
        async first() { if (/SELECT holder FROM dashboard_projection_leases/.test(sql)) return { holder: leaseHolder }; if (/COUNT\(\*\) total/.test(sql)) return metrics; return null; },
        async run() { if (/INSERT INTO dashboard_projection_leases/.test(sql)) leaseHolder = this.values[0]; return { success: true, meta: {} }; },
      };
      prepared.push(statement);
      return statement;
    },
    async batch(statements) { batchSizes.push(statements.length); return statements.map(() => ({ success: true, meta: {} })); },
  };

  const result = await refreshDashboardProjection(db, "run-1", new Date("2026-08-26T00:00:00.000Z"));
  assert.deepEqual(batchSizes, [2, 4]);
  assert.equal(result.cveCount, 7);
  assert.equal(result.parity.status, "passed");
  assert.ok(prepared.some((statement) => /FROM cves c LEFT JOIN advisory_cves/.test(statement.sql)));
  assert.ok(prepared.some((statement) => /DELETE FROM cve_dashboard_facts$/.test(statement.sql)));
  assert.ok(prepared.some((statement) => /dashboard_projection_state/.test(statement.sql)));
});

test("migration adds the disposable facts model and query-path indexes", () => {
  const migration = readFileSync(new URL("../migrations/0005_dashboard_read_model.sql", import.meta.url), "utf8");
  assert.match(migration, /CREATE TABLE IF NOT EXISTS cve_dashboard_facts/);
  assert.match(migration, /CREATE TABLE IF NOT EXISTS dashboard_projection_state/);
  assert.match(migration, /idx_affected_products_revision_cve_product/);
  assert.match(migration, /idx_remediations_revision_cve_kind/);
  assert.match(migration, /idx_release_events_type_date/);
  const parityMigration = readFileSync(new URL("../migrations/0006_projection_parity_monitoring.sql", import.meta.url), "utf8");
  assert.match(parityMigration, /cve_dashboard_facts_staging/);
  assert.match(parityMigration, /dashboard_projection_leases/);
  assert.match(parityMigration, /parity_status/);
});

test("dashboard selects the read model with canonical fallback and a core response", () => {
  const source = readFileSync(new URL("../lib/api/dashboard-query.ts", import.meta.url), "utf8");
  assert.match(source, /buildProjectedFilteredCte/);
  assert.match(source, /FROM cve_dashboard_facts WHERE/);
  assert.match(source, /buildCanonicalFilteredCte/);
  assert.match(source, /params\.get\("include"\) === "core"/);
  assert.match(source, /canonical_fallback/);
});

test("deployment populates the projection after Worker deploy and before smoke tests", () => {
  const workflow = readFileSync(new URL("../.github/workflows/cloudflare.yml", import.meta.url), "utf8");
  const deploy = workflow.indexOf("Deploy Worker and public assets");
  const populate = workflow.indexOf("Populate dashboard read model");
  const smoke = workflow.indexOf("Smoke-test Worker and public API");
  assert.ok(deploy >= 0 && populate > deploy && smoke > populate);
  assert.match(workflow, /api\/internal\/projection/);
  assert.match(workflow, /projection_status.*404/s, "projection publication must tolerate bounded Worker propagation delay");
  assert.match(workflow, /\.parity\.status == "passed"/, "deployment must fail closed unless canonical projection parity passes");
});
