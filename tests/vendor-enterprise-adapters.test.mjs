import assert from "node:assert/strict";
import test from "node:test";

import "./helpers/register-typescript.mjs";
import { makeAtlassianRaw, makeConfiguredCsaf, makeOracleCsaf } from "./fixtures/vendor-enterprise-payloads.mjs";

const { createAppleAdapter, normalizeAppleCsaf } = await import("../lib/ingestion/adapters/apple.ts");
const { normalizeAtlassianVulnerability } = await import("../lib/ingestion/adapters/atlassian.ts");
const { normalizeOracleCsaf, oracleCpuCandidates, oracleCsafCandidates } = await import("../lib/ingestion/adapters/oracle.ts");
const { createSapAdapter, normalizeSapCsaf } = await import("../lib/ingestion/adapters/sap.ts");

const sanitize = (value) => typeof value === "string" ? value.trim().replace(/\s+/g, " ") : undefined;
const policy = { timeoutMs: 100, maxResponseBytes: 100_000, retries: 0, retryBaseMs: 1 };

test("Atlassian uses explicit version statuses without implying patch or exploitation", () => {
  const advisory = normalizeAtlassianVulnerability(makeAtlassianRaw(), sanitize);

  assert.equal(advisory.cvssScore, 8.1);
  assert.equal(advisory.cves[0].normalizedSeverity, "high");
  assert.equal(advisory.exploitationStatus, "unknown");
  assert.equal(advisory.zeroDayStatus, "unknown");
  assert.deepEqual(advisory.exploitEvidence, []);
  assert.deepEqual(advisory.affectedProducts.map(({ status, affectedVersion, fixedVersion }) => ({ status, affectedVersion, fixedVersion })), [
    { status: "affected", affectedVersion: "9.0.0", fixedVersion: undefined },
    { status: "fixed", affectedVersion: undefined, fixedVersion: "9.0.1" },
  ]);
  assert.equal(advisory.remediations[0].kind, "fixed_version");
  assert.equal(advisory.remediations[0].fixedVersion, "9.0.1");
  assert.equal(advisory.remediations[0].patchAvailable, undefined);
});

test("Atlassian normalization is deterministic and rejects malformed CVE IDs", () => {
  const raw = makeAtlassianRaw();
  assert.deepEqual(normalizeAtlassianVulnerability(raw, sanitize), normalizeAtlassianVulnerability(structuredClone(raw), sanitize));
  raw.body.cve.cve_id = "ATLASSIAN-123";
  assert.throws(() => normalizeAtlassianVulnerability(raw, sanitize), /valid CVE ID/);
});

test("Oracle CSAF preserves explicit vendor fixes and quarterly release events", () => {
  const advisory = normalizeOracleCsaf(makeOracleCsaf(), sanitize);

  assert.equal(advisory.vendor, "oracle");
  assert.equal(advisory.exploitationStatus, "unknown");
  assert.equal(advisory.zeroDayStatus, "unknown");
  assert.equal(advisory.remediations[0].kind, "patch");
  assert.equal(advisory.remediations[0].patchAvailable, true);
  assert.equal(advisory.remediations[0].fixedVersion, undefined);
  assert.equal(advisory.releaseEvent.eventType, "quarterly_cpu");
  assert.equal(advisory.releaseEvent.eventDate, "2026-07-21");
});

test("Oracle quarterly discovery generates only deterministic official CSAF JSON candidates", () => {
  const refs = oracleCpuCandidates(new Date("2025-01-01T00:00:00Z"), new Date("2025-12-31T23:59:59Z"));
  assert.deepEqual(refs.map((ref) => ref.id), ["cpujan2025", "cpuapr2025", "cpujul2025", "cpuoct2025"]);
  assert.ok(refs.every((ref) => /^https:\/\/www\.oracle\.com\/a\/tech\/docs\/security-alerts\/cpu(?:jan|apr|jul|oct)2025csaf\.json$/.test(ref.url)));
});

test("Oracle discovery includes official CSPU CSAF publications beginning in May 2026", () => {
  const refs = oracleCsafCandidates(new Date("2026-05-01T00:00:00Z"), new Date("2026-08-31T23:59:59Z"));
  assert.deepEqual(refs.map((ref) => ref.id).sort(), ["cpujul2026", "cspuaug2026", "cspujun2026", "cspumay2026"]);
  assert.ok(refs.every((ref) => /^https:\/\/www\.oracle\.com\/a\/tech\/docs\/security-alerts\/(?:cpu|cspu)[a-z]{3}2026csaf\.json$/.test(ref.url)));
  assert.equal(oracleCsafCandidates(new Date("2025-05-01T00:00:00Z"), new Date("2025-06-30T23:59:59Z")).some((ref) => ref.id.startsWith("cspu")), false);
});

test("Oracle CSPU normalization creates a distinct reusable release event", () => {
  const raw = makeOracleCsaf();
  raw.ref.id = "cspuaug2026";
  const advisory = normalizeOracleCsaf(raw, sanitize);
  assert.equal(advisory.releaseEvent.eventType, "critical_security_patch_update");
  assert.match(advisory.releaseEvent.label, /Critical Security Patch Update/);
});

test("Apple and SAP default adapters fail closed until authoritative feeds are configured", async () => {
  await assert.rejects(() => createAppleAdapter().discover({ fetch, policy }), /verified public machine-readable/);
  await assert.rejects(() => createSapAdapter().discover({ fetch, policy }), /SAP for Me entitlement/);
  assert.throws(() => createAppleAdapter({ csafUrls: ["https://example.com/advisory.json"] }), /not an approved/);
  assert.throws(() => createSapAdapter({ csafUrls: ["http://support.sap.com/advisory.json"] }), /not an approved/);
});

test("configured Apple and SAP CSAF normalizers do not infer risk assertions", () => {
  const apple = normalizeAppleCsaf(makeConfiguredCsaf("apple"), sanitize);
  const sap = normalizeSapCsaf(makeConfiguredCsaf("sap"), sanitize);
  for (const advisory of [apple, sap]) {
    assert.equal(advisory.cves[0].normalizedSeverity, "critical");
    assert.equal(advisory.exploitationStatus, "unknown");
    assert.equal(advisory.zeroDayStatus, "unknown");
    assert.deepEqual(advisory.exploitEvidence, []);
    assert.deepEqual(advisory.remediations, []);
  }
});
