import assert from "node:assert/strict";
import test from "node:test";

import "./helpers/register-typescript.mjs";
import { makeMozillaRaw, MOZILLA_MFSA_YAML } from "./fixtures/mozilla-mfsa-payload.mjs";

const { mozillaAdapter, normalizeMozillaMfsa, parseMozillaMfsaYaml } = await import("../lib/ingestion/adapters/mozilla.ts");

const sanitize = (value) => typeof value === "string" ? value.trim().replace(/\s+/g, " ") : undefined;

test("Mozilla parses the official MFSA YAML structure conservatively", () => {
  const parsed = parseMozillaMfsaYaml(MOZILLA_MFSA_YAML);

  assert.equal(parsed.announcedAt, "2026-08-04T00:00:00.000Z");
  assert.deepEqual(parsed.fixedIn, ["Firefox 153.0.3", "Firefox for Android 153.0.3"]);
  assert.equal(parsed.cves[0].cveId, "CVE-2026-18809");
  assert.equal(parsed.cves[0].impact, "high");
  assert.match(parsed.cves[0].description, /actively exploited/);
});

test("Mozilla emits explicit fixed versions without inferring patch or exploitation state", () => {
  const advisory = normalizeMozillaMfsa(makeMozillaRaw(), sanitize);

  assert.equal(advisory.vendor, "mozilla");
  assert.equal(advisory.vendorAdvisoryId, "mfsa2026-73");
  assert.equal(advisory.exploitationStatus, "unknown");
  assert.equal(advisory.zeroDayStatus, "unknown");
  assert.deepEqual(advisory.exploitEvidence, []);
  assert.equal(advisory.cves.length, 2);
  assert.equal(advisory.cves[1].normalizedSeverity, "medium");
  assert.equal(advisory.affectedProducts[0].status, "fixed");
  assert.equal(advisory.affectedProducts[0].fixedVersion, "153.0.3");
  assert.equal(advisory.remediations[0].kind, "fixed_version");
  assert.equal(advisory.remediations[0].fixedVersion, "153.0.3");
  assert.equal(advisory.remediations[0].patchAvailable, undefined);
  assert.equal(advisory.sourceUrl, "https://www.mozilla.org/security/advisories/mfsa2026-73/");
});

test("Mozilla normalization is idempotent and rejects incomplete YAML", () => {
  const first = normalizeMozillaMfsa(makeMozillaRaw(), sanitize);
  const second = normalizeMozillaMfsa(makeMozillaRaw(`${MOZILLA_MFSA_YAML}`), sanitize);

  assert.deepEqual(second, first);
  assert.throws(() => parseMozillaMfsaYaml("title: Missing data"), /announced date/);
  assert.throws(() => parseMozillaMfsaYaml(MOZILLA_MFSA_YAML.replace(/fixed_in:[\s\S]*?title:/, "fixed_in:\ntitle:")), /fixed_in releases/);
});

test("Mozilla discovers YAML files from its official repository only", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input) => {
    const url = String(input);
    if (url.startsWith("https://api.github.com/repos/mozilla/foundation-security-advisories/commits?")) {
      const parsed = new URL(url);
      assert.equal(parsed.searchParams.get("path"), "announce");
      assert.equal(parsed.searchParams.get("since"), "2026-08-18T00:00:00.000Z");
      assert.equal(parsed.searchParams.get("until"), "2026-08-20T00:00:00.000Z");
      return new Response(JSON.stringify([{
        sha: "0123456789abcdef0123456789abcdef01234567",
        url: "https://api.github.com/repos/mozilla/foundation-security-advisories/commits/0123456789abcdef0123456789abcdef01234567",
        commit: { committer: { date: "2026-08-19T12:34:56Z" } },
      }]), { headers: { "content-type": "application/json" } });
    }
    assert.equal(url, "https://api.github.com/repos/mozilla/foundation-security-advisories/commits/0123456789abcdef0123456789abcdef01234567");
    return new Response(JSON.stringify({ files: [
      { filename: "announce/2026/mfsa2026-73.yml", status: "modified" },
      { filename: "announce/2026/notes.txt", status: "modified" },
      { filename: "announce/2026/mfsa2026-72.yml", status: "removed" },
    ] }), { headers: { "content-type": "application/json" } });
  };
  try {
    const refs = await mozillaAdapter.discover({
      fetch: globalThis.fetch,
      since: "2026-08-18T00:00:00.000Z",
      until: "2026-08-20T00:00:00.000Z",
      policy: { timeoutMs: 1_000, maxResponseBytes: 100_000, retries: 0, retryBaseMs: 1 },
    });
    assert.deepEqual(refs, [{
      id: "mfsa2026-73",
      url: "https://raw.githubusercontent.com/mozilla/foundation-security-advisories/0123456789abcdef0123456789abcdef01234567/announce/2026/mfsa2026-73.yml",
      sourceUpdatedAt: "2026-08-19T12:34:56.000Z",
      metadata: {
        repositoryPath: "announce/2026/mfsa2026-73.yml",
        repositorySha: "0123456789abcdef0123456789abcdef01234567",
        publicationUrl: "https://www.mozilla.org/security/advisories/mfsa2026-73/",
      },
    }]);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
