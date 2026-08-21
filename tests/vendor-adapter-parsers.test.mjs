import assert from "node:assert/strict";
import test from "node:test";

import "./helpers/register-typescript.mjs";
import {
  EPSS_CURRENT_CSV,
  makeCisaKevSnapshot,
  makeCiscoCsaf,
  makeMicrosoftCvrf,
  textStream,
} from "./fixtures/vendor-payloads.mjs";

const { normalizeMicrosoftCvrf } = await import(
  "../lib/ingestion/adapters/microsoft.ts"
);
const { normalizeCiscoCsaf } = await import(
  "../lib/ingestion/adapters/cisco.ts"
);
const { parseCisaKevSnapshot } = await import(
  "../lib/ingestion/enrichments/cisa.ts"
);
const { streamEpssCsv } = await import(
  "../lib/ingestion/enrichments/epss.ts"
);

const observedAt = "2026-08-20T12:10:00.000Z";
const sanitize = (value) =>
  typeof value === "string" ? value.trim().replace(/\s+/g, " ") : undefined;

test("Microsoft does not infer exploitation, zero-day, or remediation from severity", () => {
  const [advisory] = normalizeMicrosoftCvrf(
    makeMicrosoftCvrf(),
    observedAt,
    sanitize,
  );

  assert.equal(advisory.cves[0].normalizedSeverity, "critical");
  assert.equal(advisory.cvssScore, 9.8);
  assert.equal(advisory.exploitationStatus, "unknown");
  assert.equal(advisory.zeroDayStatus, "unknown");
  assert.deepEqual(advisory.exploitEvidence, []);
  assert.deepEqual(advisory.remediations, []);
  assert.equal(advisory.affectedProducts[0].status, "affected");
});

test("Microsoft emits exploitation and remediation only from explicit vendor fields", () => {
  const raw = makeMicrosoftCvrf();
  const vulnerability = raw.body.vulnerabilities[0];
  vulnerability.threats = [{ category: "exploit_status", details: "Exploited: Yes; Publicly Disclosed: Yes; Microsoft explicitly identifies this issue as a zero-day vulnerability." }];
  vulnerability.remediations = [
    {
      category: "vendor_fix",
      details: "Install the security update. A restart is required.",
      product_ids: ["prod-1"],
      url: raw.resolvedUrl,
      date: "2026-08-12T17:00:00Z",
    },
    {
      category: "mitigation",
      details: "Disable the affected service until the update is installed.",
      product_ids: ["prod-1"],
      url: raw.resolvedUrl,
    },
  ];

  const [advisory] = normalizeMicrosoftCvrf(raw, observedAt, sanitize);
  const patch = advisory.remediations.find((item) => item.kind === "patch");
  const mitigation = advisory.remediations.find(
    (item) => item.kind === "mitigation",
  );

  assert.equal(advisory.exploitationStatus, "known_exploited");
  assert.equal(advisory.zeroDayStatus, "confirmed");
  assert.deepEqual(
    advisory.exploitEvidence.map((item) => item.type),
    ["known_exploitation", "public_disclosure", "zero_day"],
  );
  assert.equal(patch?.patchAvailable, true);
  assert.equal(patch?.rebootRequired, true);
  assert.equal(patch?.productName, "Windows Server 2025");
  assert.equal(mitigation?.patchAvailable, undefined);
});

test("Microsoft normalization is idempotent and skips malformed CVE entries", () => {
  const raw = makeMicrosoftCvrf();
  raw.body.vulnerabilities.push({
    cve: "not-a-cve",
    title: "Malformed vulnerability record",
  });

  const first = normalizeMicrosoftCvrf(raw, observedAt, sanitize);
  const second = normalizeMicrosoftCvrf(
    structuredClone(raw),
    observedAt,
    sanitize,
  );

  assert.deepEqual(second, first);
  assert.equal(first.length, 1);
  assert.equal(first[0].cves[0].cveId, "CVE-2026-1000");
});

test("Cisco does not infer exploitation, zero-day, or remediation from impact and CVSS", () => {
  const advisory = normalizeCiscoCsaf(makeCiscoCsaf(), observedAt, sanitize);

  assert.equal(advisory.cves[0].normalizedSeverity, "critical");
  assert.equal(advisory.cvssScore, 9.8);
  assert.equal(advisory.exploitationStatus, "unknown");
  assert.equal(advisory.zeroDayStatus, "unknown");
  assert.deepEqual(advisory.exploitEvidence, []);
  assert.deepEqual(advisory.remediations, []);
});

test("Cisco requires explicit threat and remediation categories for vendor assertions", () => {
  const raw = makeCiscoCsaf();
  const vulnerability = raw.body.vulnerabilities[0];
  vulnerability.threats.push({
    category: "exploit_status",
    details:
      "Cisco is aware that this vulnerability is actively exploited as a zero-day.",
    date: "2026-08-19T16:00:00Z",
    url: raw.resolvedUrl,
  });
  vulnerability.remediations = [
    {
      category: "vendor_fix",
      details: "Upgrade to the fixed release. A reboot is required.",
      fixed_release: "2.0.1",
      product_ids: ["CSAFPID-1"],
      url: raw.resolvedUrl,
      date: "2026-08-19T16:00:00Z",
    },
    {
      category: "workaround",
      details: "Disable external access to the affected interface.",
      product_ids: ["CSAFPID-1"],
      url: raw.resolvedUrl,
    },
  ];

  const advisory = normalizeCiscoCsaf(raw, observedAt, sanitize);
  const patch = advisory.remediations.find((item) => item.kind === "patch");
  const workaround = advisory.remediations.find(
    (item) => item.kind === "workaround",
  );

  assert.equal(advisory.exploitationStatus, "known_exploited");
  assert.equal(advisory.zeroDayStatus, "confirmed");
  assert.deepEqual(
    advisory.exploitEvidence.map((item) => item.type),
    ["known_exploitation", "zero_day"],
  );
  assert.equal(patch?.patchAvailable, true);
  assert.equal(patch?.fixedVersion, "2.0.1");
  assert.equal(patch?.rebootRequired, true);
  assert.equal(workaround?.patchAvailable, undefined);
});

test("Cisco normalization is idempotent and deduplicates repeated CVE assertions", () => {
  const raw = makeCiscoCsaf();
  raw.body.vulnerabilities.push(
    structuredClone(raw.body.vulnerabilities[0]),
  );

  const first = normalizeCiscoCsaf(raw, observedAt, sanitize);
  const second = normalizeCiscoCsaf(
    structuredClone(raw),
    observedAt,
    sanitize,
  );

  assert.deepEqual(second, first);
  assert.equal(first.cves.length, 1);
  assert.equal(first.cves[0].cveId, "CVE-2026-2000");
});

test("CISA KEV keeps required action, patch state, and zero-day state separate", () => {
  const payload = makeCisaKevSnapshot();
  const snapshot = parseCisaKevSnapshot(payload, "https://www.cisa.gov/kev.json");
  const entry = snapshot.entries[0];

  assert.equal(entry.requiredAction, payload.vulnerabilities[0].requiredAction);
  assert.equal(Object.hasOwn(entry, "patchAvailable"), false);
  assert.equal(Object.hasOwn(entry, "remediation"), false);
  assert.equal(Object.hasOwn(entry, "zeroDay"), false);
  assert.equal(Object.hasOwn(entry, "zeroDayStatus"), false);
  assert.equal(entry.cveId, "CVE-2026-3000");
  assert.equal(snapshot.sourceUrl, "https://www.cisa.gov/kev.json");
});

test("CISA KEV parsing is idempotent and canonicalizes release timestamps", () => {
  const payload = makeCisaKevSnapshot({
    dateReleased: "2026-08-20T08:00:00-04:00",
  });

  const first = parseCisaKevSnapshot(payload);
  const second = parseCisaKevSnapshot(structuredClone(payload));

  assert.deepEqual(second, first);
  assert.equal(first.dateReleased, "2026-08-20T12:00:00.000Z");
});

test("CISA KEV rejects duplicate and malformed snapshot fixtures", () => {
  const duplicate = makeCisaKevSnapshot();
  duplicate.vulnerabilities.push(
    structuredClone(duplicate.vulnerabilities[0]),
  );
  duplicate.count = 2;

  assert.throws(
    () => parseCisaKevSnapshot(duplicate),
    /duplicate CVE-2026-3000/,
  );
  assert.throws(
    () =>
      parseCisaKevSnapshot(
        makeCisaKevSnapshot({
          vulnerabilities: [
            {
              ...makeCisaKevSnapshot().vulnerabilities[0],
              cveID: "CVE-invalid",
            },
          ],
        }),
      ),
    /invalid CVE ID/,
  );
  assert.throws(
    () => parseCisaKevSnapshot(makeCisaKevSnapshot({ count: 2 })),
    /count does not match/,
  );
});

test("EPSS bulk parsing preserves the dataset date and current model metadata", async () => {
  const rows = [];
  const result = await streamEpssCsv(
    textStream(EPSS_CURRENT_CSV, 17),
    (row) => rows.push(row),
  );

  assert.deepEqual(result, {
    metadata: {
      modelVersion: "v2025.03.14",
      scoreDate: "2026-08-19T00:00:00.000Z",
    },
    rowCount: 2,
  });
  assert.deepEqual(rows, [
    { cveId: "CVE-2026-1000", score: 0.01234, percentile: 0.54321 },
    { cveId: "CVE-2026-2000", score: 0.87654, percentile: 0.98765 },
  ]);
});

test("EPSS historical parsing uses an explicit expected date without overwriting row values", async () => {
  const csv = [
    "cve,epss,percentile",
    "CVE-2026-1000,0.00042,0.12345",
  ].join("\n");
  const rows = [];
  const result = await streamEpssCsv(
    textStream(csv, 5),
    (row) => rows.push(row),
    "2026-08-18",
  );

  assert.equal(result.metadata.scoreDate, "2026-08-18T00:00:00.000Z");
  assert.equal(result.metadata.modelVersion, undefined);
  assert.deepEqual(rows, [
    { cveId: "CVE-2026-1000", score: 0.00042, percentile: 0.12345 },
  ]);
});

test("EPSS parsing is idempotent and rejects duplicates or malformed values", async () => {
  const parse = async (csv) => {
    const rows = [];
    const result = await streamEpssCsv(
      textStream(csv, 11),
      (row) => rows.push(row),
    );
    return { result, rows };
  };

  assert.deepEqual(await parse(EPSS_CURRENT_CSV), await parse(EPSS_CURRENT_CSV));

  const metadata = "#score_date:2026-08-19";
  await assert.rejects(
    () =>
      parse(
        [
          metadata,
          "cve,epss,percentile",
          "CVE-2026-1000,0.1,0.2",
          "cve-2026-1000,0.2,0.3",
        ].join("\n"),
      ),
    /duplicate CVE-2026-1000/,
  );
  await assert.rejects(
    () =>
      parse(
        [
          metadata,
          "cve,epss,percentile",
          "CVE-2026-1000,1.1,0.2",
        ].join("\n"),
      ),
    /values are out of range/,
  );
  await assert.rejects(
    () => parse([metadata, "cve,score,percentile"].join("\n")),
    /header is invalid/,
  );
});
