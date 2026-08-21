import assert from "node:assert/strict";
import test from "node:test";

import "./helpers/register-typescript.mjs";
import { cloneAdvisory, makeAdvisory } from "./fixtures/normalized-advisory.mjs";

const { PRIORITY_THRESHOLDS, calculatePriority } = await import(
  "../lib/domain/priority.ts"
);
const { diffAdvisory } = await import("../lib/ingestion/diff.ts");
const { hashAdvisory, sha256, stableSerialize } = await import(
  "../lib/ingestion/hash.ts"
);
const { ingestionBatchOutcome } = await import("../lib/ingestion/pipeline.ts");

test("ingestion batches expose partial vendor results at the outer API boundary", () => {
  assert.deepEqual(ingestionBatchOutcome([{ status: "success" }, { status: "unchanged" }]), {
    status: "success",
    httpStatus: 200,
  });
  assert.deepEqual(ingestionBatchOutcome([{ status: "success" }, { status: "partial" }]), {
    status: "partial",
    httpStatus: 207,
  });
  assert.deepEqual(ingestionBatchOutcome([{ status: "failed" }]), {
    status: "partial",
    httpStatus: 207,
  });
});

test("priority is explainable and keeps KEV and known exploitation independently visible", () => {
  const result = calculatePriority({
    kev: true,
    exploitationStatus: "known_exploited",
    severity: "critical",
    cvss: 9.8,
    epssPercentile: 0.97,
  });

  assert.deepEqual(result, {
    level: "P1",
    reasons: [
      "Known exploited",
      "CISA KEV",
      "Critical severity",
      "CVSS 9.8",
      "EPSS 97th percentile",
    ],
    components: { kev: true, exploitationStatus: "known_exploited", severity: "critical", cvss: 9.8, epssPercentile: 0.97 },
  });

  assert.equal(
    calculatePriority({
      kev: false,
      exploitationStatus: "known_exploited",
      severity: "low",
    }).level,
    "P1",
  );
  assert.equal(
    calculatePriority({
      kev: true,
      exploitationStatus: "not_known_exploited",
      severity: "low",
    }).level,
    "P1",
  );
});

test("priority thresholds are centralized and inclusive at their boundaries", () => {
  assert.deepEqual(PRIORITY_THRESHOLDS, {
    criticalHighEpssPercentile: 0.7,
    highVeryHighEpssPercentile: 0.9,
  });

  const priorityFor = (severity, epssPercentile) =>
    calculatePriority({
      kev: false,
      exploitationStatus: "not_known_exploited",
      severity,
      epssPercentile,
    }).level;

  assert.equal(priorityFor("critical", 0.7), "P2");
  assert.equal(priorityFor("critical", 0.699), "P3");
  assert.equal(priorityFor("high", 0.9), "P2");
  assert.equal(priorityFor("high", 0.899), "P3");
  assert.equal(priorityFor("medium", 1), "P3");
});

test("routine priority still provides a human-readable reason", () => {
  assert.deepEqual(
    calculatePriority({
      kev: false,
      exploitationStatus: "unknown",
      severity: "unknown",
    }),
    { level: "P3", reasons: ["Routine vendor advisory"], components: { kev: false, exploitationStatus: "unknown", severity: "unknown", cvss: null, epssPercentile: null } },
  );
});

test("stable serialization and SHA-256 ignore object key insertion order", async () => {
  const first = {
    z: 3,
    nested: { second: 2, first: 1 },
    a: 1,
    omitted: undefined,
  };
  const second = {
    a: 1,
    nested: { first: 1, second: 2 },
    z: 3,
  };

  assert.equal(stableSerialize(first), stableSerialize(second));
  assert.equal(await sha256(first), await sha256(second));
});

test("advisory hashes are independent of normalized collection order", async () => {
  const advisory = makeAdvisory();
  advisory.cves.push({
    ...advisory.cves[0],
    cveId: "CVE-2026-0999",
    description: "A second vulnerability.",
  });
  advisory.affectedProducts.push({
    cveId: "CVE-2026-0999",
    sourceProductId: "windows-11-24h2",
    name: "Windows 11",
    family: "Windows",
    affectedVersion: "24H2",
    status: "affected",
  });
  advisory.remediations.push({
    cveId: "CVE-2026-0999",
    kind: "mitigation",
    action: "Disable the affected service until the update can be installed.",
    sourceUrl: advisory.sourceUrl,
  });
  advisory.exploitEvidence.push({
    cveId: "CVE-2026-0999",
    type: "public_disclosure",
    status: "confirmed",
    evidenceDate: "2026-08-11",
    evidenceUrl: advisory.sourceUrl,
  });

  const reordered = cloneAdvisory(advisory);
  reordered.cves.reverse();
  reordered.affectedProducts.reverse();
  reordered.remediations.reverse();
  reordered.exploitEvidence.reverse();

  assert.deepEqual(await hashAdvisory(reordered), await hashAdvisory(advisory));
});

test("component hashes isolate affected-product and remediation changes", async () => {
  const original = makeAdvisory();
  const remediationChanged = cloneAdvisory(original);
  remediationChanged.remediations[0].action = "Install the revised security update.";

  const before = await hashAdvisory(original);
  const after = await hashAdvisory(remediationChanged);

  assert.notEqual(after.contentHash, before.contentHash);
  assert.notEqual(after.remediationHash, before.remediationHash);
  assert.equal(after.affectedProductsHash, before.affectedProductsHash);
});

test("first observation reports a new advisory and aggregated new-CVE change", () => {
  const advisory = makeAdvisory({
    cves: [
      makeAdvisory().cves[0],
      { ...makeAdvisory().cves[0], cveId: "CVE-2026-1001" },
    ],
  });

  assert.deepEqual(diffAdvisory(null, advisory), ["NEW_ADVISORY", "NEW_CVE"]);
});

test("idempotent replay of an unchanged advisory produces no changes", () => {
  const previous = makeAdvisory();
  const replay = cloneAdvisory(previous);

  assert.deepEqual(diffAdvisory(previous, replay), []);
});

test("severity, CVSS, and source revision changes are classified", () => {
  const previous = makeAdvisory();
  const current = cloneAdvisory(previous);
  current.vendorSeverity = "Important";
  current.cvssScore = 8.8;
  current.cves[0].vendorSeverity = "Important";
  current.cves[0].normalizedSeverity = "high";
  current.cves[0].cvssScore = 8.8;
  current.cves[0].cvssVector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H";
  current.sourceUpdatedAt = "2026-08-12T17:00:00.000Z";

  assert.deepEqual(diffAdvisory(previous, current), [
    "ADVISORY_REVISED",
    "SEVERITY_CHANGED",
    "CVSS_CHANGED",
    "SOURCE_MODIFIED",
  ]);
});

test("new CVEs and exploitation evidence produce meaningful revision types", () => {
  const previous = makeAdvisory();
  const current = cloneAdvisory(previous);
  current.cves.push({
    ...current.cves[0],
    cveId: "CVE-2026-1001",
    description: "A newly associated vulnerability.",
  });
  current.exploitationStatus = "known_exploited";
  current.exploitEvidence.push({
    cveId: "CVE-2026-1000",
    type: "known_exploitation",
    status: "confirmed",
    evidenceDate: "2026-08-12",
    evidenceUrl: current.sourceUrl,
    summary: "Microsoft observed exploitation in the wild.",
  });

  assert.deepEqual(diffAdvisory(previous, current), [
    "ADVISORY_REVISED",
    "NEW_CVE",
    "EXPLOITATION_STATUS_CHANGED",
  ]);
});

test("affected-product additions and removals are both surfaced", () => {
  const previous = makeAdvisory();
  const current = cloneAdvisory(previous);
  current.affectedProducts = [
    {
      cveId: "CVE-2026-1000",
      sourceProductId: "windows-11-24h2",
      name: "Windows 11",
      family: "Windows",
      affectedVersion: "24H2",
      status: "affected",
    },
  ];

  assert.deepEqual(diffAdvisory(previous, current), [
    "ADVISORY_REVISED",
    "AFFECTED_PRODUCT_ADDED",
    "AFFECTED_PRODUCT_REMOVED",
  ]);
});

test("fixed-version, remediation, mitigation, and workaround changes are classified", () => {
  const previous = makeAdvisory();
  const current = cloneAdvisory(previous);
  current.remediations[0].fixedVersion = "26100.5000";
  current.remediations[0].action = "Install the re-released August 2026 security update.";
  current.remediations.push(
    {
      cveId: "CVE-2026-1000",
      kind: "mitigation",
      action: "Disable the affected service.",
      sourceUrl: current.sourceUrl,
    },
    {
      cveId: "CVE-2026-1000",
      kind: "workaround",
      action: "Block the affected protocol at the network boundary.",
      sourceUrl: current.sourceUrl,
    },
  );

  assert.deepEqual(diffAdvisory(previous, current), [
    "ADVISORY_REVISED",
    "FIXED_VERSION_CHANGED",
    "REMEDIATION_CHANGED",
    "MITIGATION_ADDED",
    "WORKAROUND_ADDED",
  ]);
});

test("authoritative zero-day status changes are classified independently", () => {
  const previous = makeAdvisory();
  const current = cloneAdvisory(previous);
  current.zeroDayStatus = "confirmed";
  current.exploitEvidence.push({ cveId: "CVE-2026-1000", type: "zero_day", status: "confirmed", evidenceDate: "2026-08-21", evidenceUrl: current.sourceUrl, summary: "Vendor confirmed exploitation before public fix availability." });
  const changes = diffAdvisory(previous, current);
  assert.ok(changes.includes("ZERO_DAY_STATUS_CHANGED"));
  assert.ok(changes.includes("ADVISORY_REVISED"));
});
