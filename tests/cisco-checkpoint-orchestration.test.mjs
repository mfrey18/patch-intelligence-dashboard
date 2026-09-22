import assert from "node:assert/strict";
import test from "node:test";

import "./helpers/register-typescript.mjs";

const { loadOrCreateCheckpoint } = await import("../lib/ingestion/orchestration.ts");

function database(rows = []) {
  const state = rows.map((row) => ({ ...row }));
  const writes = [];
  return {
    state,
    writes,
    prepare(sql) {
      return {
        bind(...values) {
          return {
            async all() {
              if (/status<>'complete'/.test(sql)) {
                return { results: state.filter((row) => row.source_id === values[0] && row.mode === "delta" && row.status !== "complete" && /^daily:cisco(?::|-)/i.test(row.id)).sort((a, b) => a.created_at.localeCompare(b.created_at)), meta: { changes: 0 } };
              }
              if (/status='complete'/.test(sql)) {
                return { results: state.filter((row) => row.source_id === values[0] && row.mode === "delta" && row.status === "complete").sort((a, b) => b.coverage_end.localeCompare(a.coverage_end)), meta: { changes: 0 } };
              }
              return { results: [], meta: { changes: 0 } };
            },
            async first() {
              if (/WHERE id=\?/.test(sql)) return state.find((row) => row.id === values[0]) ?? null;
              if (/coverage_start=\?/.test(sql)) return state.find((row) => row.source_id === values[0] && row.mode === values[1] && row.coverage_start === values[2] && row.coverage_end === values[3]) ?? null;
              return null;
            },
            async run() {
              writes.push({ sql, values });
              if (/^INSERT INTO ingestion_checkpoints/.test(sql)) {
                const [id, source_id, mode, coverage_start, coverage_end, window_start, window_end, created_at, updated_at] = values;
                if (!state.some((row) => row.id === id)) state.push({ id, source_id, mode, coverage_start, coverage_end, window_start, window_end, continuation_token: null, status: "pending", created_at, updated_at });
              }
              return { results: [], meta: { changes: 1 } };
            },
          };
        },
      };
    },
  };
}

function checkpoint(id, status, created, coverageEnd = "2026-09-21T23:59:59.999Z", continuation = "offset:4") {
  return { id, source_id: "cisco-psirt-csaf", mode: "delta", coverage_start: "2026-09-18T00:00:00.000Z", coverage_end: coverageEnd, window_start: "2026-09-21T00:00:00.000Z", window_end: coverageEnd, continuation_token: continuation, status, created_at: created, updated_at: created };
}

test("scheduled Cisco resumes the oldest incomplete daily checkpoint and preserves offset", async () => {
  const db = database([
    checkpoint("daily:cisco-psirt-csaf:2026-09-20", "pending", "2026-09-20T01:00:00.000Z"),
    checkpoint("daily:cisco:today", "pending", "2026-09-21T01:00:00.000Z", "2026-09-22T23:59:59.999Z", "offset:1"),
  ]);
  const result = await loadOrCreateCheckpoint(db, "cisco-psirt-csaf", { scheduled: true, checkpointId: "daily:cisco:today" }, new Date("2026-09-22T12:00:00.000Z"));
  assert.equal(result.id, "daily:cisco-psirt-csaf:2026-09-20");
  assert.equal(result.continuation, "offset:4");
  assert.equal(db.writes.length, 0);
});

test("after scheduled completion Cisco gets a fresh overlapping range and identity", async () => {
  const db = database([checkpoint("daily:cisco:today", "complete", "2026-09-21T01:00:00.000Z")]);
  const result = await loadOrCreateCheckpoint(db, "cisco-psirt-csaf", { scheduled: true, checkpointId: "daily:cisco:today" }, new Date("2026-09-22T12:00:00.000Z"));
  assert.notEqual(result.id, "daily:cisco:today");
  assert.match(result.id, /^daily:cisco:today:/);
  assert.equal(result.coverageStart, "2026-09-18T23:59:59.999Z");
  assert.equal(result.coverageEnd, "2026-09-22T12:00:00.000Z");
  assert.equal(result.status, "pending");
});

test("manual Cisco checkpoints remain isolated from the scheduled queue", async () => {
  const db = database([checkpoint("daily:cisco:today", "pending", "2026-09-21T01:00:00.000Z")]);
  const result = await loadOrCreateCheckpoint(db, "cisco-psirt-csaf", { checkpointId: "manual:cisco-replay", mode: "delta", since: "2026-09-22T00:00:00.000Z", until: "2026-09-22T12:00:00.000Z" }, new Date("2026-09-22T12:00:00.000Z"));
  assert.equal(result.id, "manual:cisco-replay");
  assert.equal(result.coverageStart, "2026-09-22T00:00:00.000Z");
});
