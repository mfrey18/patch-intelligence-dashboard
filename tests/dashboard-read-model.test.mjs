import "./helpers/register-typescript.mjs";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const { refreshDashboardProjection } = await import("../lib/operations/dashboard-projection.ts");

test("dashboard projection is atomically published from authoritative tables", async () => {
  const prepared = [];
  let batchSize = 0;
  const db = {
    prepare(sql) {
      const statement = {
        sql,
        values: [],
        bind(...values) { this.values = values; return this; },
        async first(column) { return column === "count" ? 7 : { count: 7 }; },
        async run() { return { success: true, meta: {} }; },
      };
      prepared.push(statement);
      return statement;
    },
    async batch(statements) { batchSize = statements.length; return statements.map(() => ({ success: true, meta: {} })); },
  };

  const result = await refreshDashboardProjection(db, "run-1", new Date("2026-08-26T00:00:00.000Z"));
  assert.equal(batchSize, 3);
  assert.equal(result.cveCount, 7);
  assert.match(prepared[0].sql, /FROM cves c LEFT JOIN advisory_cves/);
  assert.match(prepared[0].sql, /ON CONFLICT\(cve_id\) DO UPDATE/);
  assert.match(prepared[1].sql, /DELETE FROM cve_dashboard_facts/);
  assert.match(prepared[2].sql, /dashboard_projection_state/);
});

test("migration adds the disposable facts model and query-path indexes", () => {
  const migration = readFileSync(new URL("../migrations/0005_dashboard_read_model.sql", import.meta.url), "utf8");
  assert.match(migration, /CREATE TABLE IF NOT EXISTS cve_dashboard_facts/);
  assert.match(migration, /CREATE TABLE IF NOT EXISTS dashboard_projection_state/);
  assert.match(migration, /idx_affected_products_revision_cve_product/);
  assert.match(migration, /idx_remediations_revision_cve_kind/);
  assert.match(migration, /idx_release_events_type_date/);
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
});
