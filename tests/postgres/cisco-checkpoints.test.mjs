import test from "node:test";
import assert from "node:assert/strict";
import { testDatabase } from "./database.mjs";
import { seedIngestionCatalog } from "../../lib/ingestion/postgres-repository.ts";
import { loadOrCreateCheckpoint, validateScheduledScope } from "../../lib/ingestion/orchestration.ts";

const source = "cisco-psirt-csaf";
async function insertCheckpoint(db, { id, status = "pending", createdAt, coverageStart = "2026-09-18T00:00:00.000Z", coverageEnd = "2026-09-21T23:59:59.999Z", continuation = "offset:4" }) {
  await db.prepare(`INSERT INTO ingestion_checkpoints
    (id,source_id,mode,coverage_start,coverage_end,window_start,window_end,continuation_token,status,created_at,updated_at)
    VALUES (?,?,'delta',?,?,?,?,? ,?,?,?)`).bind(id, source, coverageStart, coverageEnd, coverageStart, coverageEnd, continuation, status, createdAt, createdAt).run();
}

test("scheduled lookup filters the daily namespace before ordering and resumes the oldest failure", async () => {
  const db = await testDatabase();
  try {
    await seedIngestionCatalog(db);
    await insertCheckpoint(db, { id: "manual:old", status: "pending", createdAt: "2026-09-01T00:00:00.000Z", coverageStart: "2026-09-01T00:00:00.000Z", coverageEnd: "2026-09-02T00:00:00.000Z" });
    await insertCheckpoint(db, { id: "daily:cisco-psirt-csaf:2026-09-20", status: "failed", createdAt: "2026-09-20T00:00:00.000Z" });
    await insertCheckpoint(db, { id: "daily:cisco:today", status: "pending", createdAt: "2026-09-21T00:00:00.000Z", coverageStart: "2026-09-19T00:00:00.000Z", coverageEnd: "2026-09-22T00:00:00.000Z", continuation: "offset:1" });
    const result = await loadOrCreateCheckpoint(db, source, { scheduled: true, checkpointId: "daily:cisco:today" }, new Date("2026-09-22T12:00:00.000Z"));
    assert.equal(result.id, "daily:cisco-psirt-csaf:2026-09-20");
    assert.equal(result.status, "failed");
    assert.equal(result.continuation, "offset:4");
  } finally { await db.close(); }
});

test("completion creates a timestamped overlap and a later same-day call creates a fresh window", async () => {
  const db = await testDatabase();
  try {
    await seedIngestionCatalog(db);
    await insertCheckpoint(db, { id: "daily:cisco:today", status: "complete", createdAt: "2026-09-21T23:59:59.999Z" });
    const now = new Date("2026-09-22T12:00:00.000Z");
    const first = await loadOrCreateCheckpoint(db, source, { scheduled: true, checkpointId: "daily:cisco:today" }, now);
    assert.match(first.id, /^daily:cisco:today:/);
    assert.equal(first.coverageStart, "2026-09-18T23:59:59.999Z");
    assert.equal(first.coverageEnd, now.toISOString());
    await db.prepare("UPDATE ingestion_checkpoints SET status='complete',completed_at=?,updated_at=? WHERE id=?").bind(now.toISOString(), now.toISOString(), first.id).run();
    const second = await loadOrCreateCheckpoint(db, source, { scheduled: true, checkpointId: "daily:cisco:today" }, new Date(now.getTime() + 60_000));
    assert.notEqual(second.id, first.id);
    assert.equal(second.status, "pending");
  } finally { await db.close(); }
});

test("manual and replay requests remain outside the scheduled Cisco namespace", async () => {
  const db = await testDatabase();
  try {
    await seedIngestionCatalog(db);
    await insertCheckpoint(db, { id: "daily:cisco:today", status: "pending", createdAt: "2026-09-21T00:00:00.000Z" });
    const manual = await loadOrCreateCheckpoint(db, source, { mode: "delta", checkpointId: "manual:cisco", since: "2026-09-22T00:00:00.000Z", until: "2026-09-22T12:00:00.000Z" }, new Date("2026-09-22T12:00:00.000Z"));
    assert.equal(manual.id, "manual:cisco");
    assert.throws(() => validateScheduledScope(source, { scheduled: true, mode: "replay", checkpointId: "daily:cisco:today" }, "replay"), /only supported/);
    assert.doesNotThrow(() => validateScheduledScope(source, { mode: "replay", checkpointId: "manual:cisco" }, "replay"));
  } finally { await db.close(); }
});

test("rolling-window start stays inside six-month scope", async () => {
  const db = await testDatabase();
  try {
    await seedIngestionCatalog(db);
    await insertCheckpoint(db, { id: "daily:cisco:old", status: "complete", createdAt: "2026-03-01T00:00:00.000Z", coverageEnd: "2026-03-01T00:00:00.000Z" });
    const result = await loadOrCreateCheckpoint(db, source, { scheduled: true }, new Date("2026-09-22T12:00:00.000Z"));
    assert.equal(result.coverageStart, "2026-03-22T00:00:00.000Z");
    assert.ok(Date.parse(result.coverageStart) <= Date.parse(result.coverageEnd));
  } finally { await db.close(); }
});
