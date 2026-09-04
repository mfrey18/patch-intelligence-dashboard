import "./helpers/register-typescript.mjs";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const { EPSS_DAILY_RETENTION_DAYS, INTELLIGENCE_WINDOW_MONTHS } = await import("../lib/ingestion/operational-policy.ts");
const { pruneRollingRetention } = await import("../lib/operations/d1-health.ts");

test("EPSS storage keeps a dense recent window and weekly six-month history", async () => {
  const statements = [];
  const db = {
    prepare(sql) {
      const statement = {
        sql,
        values: [],
        bind(...values) { this.values = values; return this; },
        async run() { return { success: true, meta: { changes: /epss_observations/.test(sql) ? 2 : 0 } }; },
      };
      statements.push(statement);
      return statement;
    },
  };

  const result = await pruneRollingRetention(db, new Date("2026-09-02T12:00:00.000Z"));
  assert.equal(INTELLIGENCE_WINDOW_MONTHS, 6);
  assert.equal(EPSS_DAILY_RETENTION_DAYS, 42);
  assert.equal(result.cutoff, "2026-03-02");
  assert.equal(result.dailyCutoff, "2026-07-22");
  assert.equal(result.epssObservations, 4);
  const downsample = statements.find((statement) => /strftime\('%Y-%W'/.test(statement.sql));
  assert.ok(downsample);
  assert.deepEqual(downsample.values, ["2026-03-02", "2026-07-22", "2026-03-02", "2026-07-22"]);
});

test("EPSS ingestion scopes observations and suppresses identical current snapshots", () => {
  const source = readFileSync(new URL("../lib/ingestion/enrichments/epss.ts", import.meta.url), "utf8");
  assert.match(source, /COALESCE\(a\.published_at,a\.source_updated_at\)>=date\('now','-\$\{INTELLIGENCE_WINDOW_MONTHS\} months'\)/);
  assert.match(source, /latest\?\.score_date === scoreDate && latest\.source_hash === sourceHash/);
  assert.match(source, /counts\.unchanged = trackedObservations\.length/);
});

test("CISA and vendor ingestion avoid touching unchanged canonical rows", () => {
  const cisa = readFileSync(new URL("../lib/ingestion/enrichments/cisa.ts", import.meta.url), "utf8");
  const repository = readFileSync(new URL("../lib/ingestion/d1-repository.ts", import.meta.url), "utf8");
  assert.match(cisa, /if \(!previous \|\| changeTypes\.length > 0 \|\| !previous\.active \|\| !previous\.evidence_present\)/);
  assert.match(cisa, /INSERT OR IGNORE INTO cves/);
  assert.match(repository, /INSERT OR IGNORE INTO cves/);
  assert.doesNotMatch(repository, /ON CONFLICT\(id\) DO UPDATE SET updated_at=excluded\.updated_at/);
});
