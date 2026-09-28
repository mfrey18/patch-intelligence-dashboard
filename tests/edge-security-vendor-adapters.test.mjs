import assert from "node:assert/strict";
import test from "node:test";

import "./helpers/register-typescript.mjs";
import { EDGE_VENDOR_CSAF, FORTINET_RSS, IVANTI_RSS, PALO_ALTO_RSS, csafRaw } from "./fixtures/edge-security-vendor-payloads.mjs";

const { createAdobeAdapter, normalizeAdobeCsaf } = await import("../lib/ingestion/adapters/adobe.ts");
const { createFortinetAdapter, normalizeFortinetCsaf, parseFortinetIndex } = await import("../lib/ingestion/adapters/fortinet.ts");
const { normalizeIvantiRssItem } = await import("../lib/ingestion/adapters/ivanti.ts");
const { paloAltoAdapter, normalizePaloAltoCsaf } = await import("../lib/ingestion/adapters/palo-alto.ts");
const { parseVendorFeed } = await import("../lib/ingestion/adapters/rss.ts");

const policy = { timeoutMs: 1_000, maxResponseBytes: 100_000, retries: 0, retryBaseMs: 1 };
const sanitize = (value) => typeof value === "string" ? value.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim() || undefined : undefined;
const observedAt = "2026-08-20T12:10:00.000Z";
const fortinetIndex = `<html><body><div id="fwb_id_1">Published: Sep 1, 2026</div><script>document.getElementById('fwb_id_1').addEventListener('click', function(event) {location.href = '/psirt/FG-IR-26-167'});</script><a aria-label="Next" href="/psirt?page=2">Next</a></body></html>`;

test("vendor RSS parser handles CDATA, entities, and source dates", () => {
  const [fortinet] = parseVendorFeed(FORTINET_RSS);
  const [ivanti] = parseVendorFeed(IVANTI_RSS);

  assert.match(fortinet.description, /Revised on 2026-08-19/);
  assert.match(ivanti.description, /no evidence of CVE-2026-4200/);
  assert.equal(ivanti.publishedAt, "2026-08-12T16:00:00.000Z");
});

test("Palo Alto discovers official RSS entries and resolves the verified CSAF endpoint", async () => {
  await withFetch(async (url) => {
    assert.equal(String(url), "https://security.paloaltonetworks.com/rss.xml");
    return new Response(PALO_ALTO_RSS, { headers: { "content-type": "application/xml" } });
  }, async () => {
    const refs = await paloAltoAdapter.discover({ fetch, policy });
    assert.deepEqual(refs, [{
      id: "CVE-2026-4100",
      url: "https://security.paloaltonetworks.com/csaf/CVE-2026-4100",
      sourceUpdatedAt: "2026-08-12T16:00:00.000Z",
      metadata: { publicationUrl: "https://security.paloaltonetworks.com/CVE-2026-4100", feedTitle: "CVE-2026-4100 Edge Appliance issue (Severity: CRITICAL)" },
    }]);
  });
});

test("Palo Alto CSAF keeps fixed versions and exploitation assertions explicit", () => {
  const [advisory] = normalizePaloAltoCsaf(csafRaw("CVE-2026-4100"), observedAt, sanitize);
  assert.equal(advisory.vendor, "palo-alto");
  assert.equal(advisory.exploitationStatus, "not_known_exploited");
  assert.equal(advisory.zeroDayStatus, "unknown");
  assert.equal(advisory.remediations[0].patchAvailable, true);
  assert.equal(advisory.remediations[0].fixedVersion, "9.2.1");
});

test("Fortinet public HTML discovery follows the official PSIRT index", async () => {
  const terminal = fortinetIndex.replaceAll('aria-label="Next"', 'aria-label="Terminal"');
  const seen = [];
  await withFetch(async (url) => { seen.push(String(url)); return new Response(seen.length === 1 ? fortinetIndex : terminal, { headers: { "content-type": "text/html" } }); }, async () => {
    const refs = await createFortinetAdapter().discover({ fetch, policy: { ...policy, maxResponseBytes: 2_000_000 }, since: "2026-09-01T00:00:00Z" });
    assert.equal(refs[0].id, "FG-IR-26-167");
    assert.match(refs[0].url, /fortiguard\.fortinet\.com\/psirt\/FG-IR-26-167/);
    assert.equal(seen.length, 2);
    assert.match(seen[1], /[?&]page=2(?:&|$)/);
  });
  await assert.rejects(() => createFortinetAdapter({ csafUrlTemplate: "https://example.invalid/{id}.json" }).discover({ fetch, policy }), /official Fortinet host/);
});

test("Fortinet pagination rejects malformed next links instead of treating them as terminal", () => {
  const malformed = `<html><a aria-label="Next" href="https://example.invalid/psirt?page=2">next</a></html>`;
  assert.throws(() => parseFortinetIndex(malformed, "https://fortiguard.fortinet.com/psirt"), /malformed next-page link/);
});

test("Fortinet uses RSS only for discovery and shared CSAF for assertions", async () => {
  const adapter = createFortinetAdapter({ csafUrlTemplate: "https://filestore.fortinet.com/fortiguard/csaf/{id}.json" });
  await withFetch(async () => new Response(FORTINET_RSS, { headers: { "content-type": "application/xml" } }), async () => {
    const [ref] = await adapter.discover({ fetch, policy });
    assert.equal(ref.id, "FG-IR-26-999");
    assert.equal(ref.url, "https://filestore.fortinet.com/fortiguard/csaf/FG-IR-26-999.json");
    assert.equal(ref.sourceUpdatedAt, "2026-08-19T00:00:00.000Z");
  });
  const [advisory] = normalizeFortinetCsaf(csafRaw("FG-IR-26-999"), observedAt, sanitize);
  assert.equal(advisory.vendor, "fortinet");
  assert.equal(advisory.cves[0].cvssScore, 9.1);
});

test("Ivanti RSS records authoritative negative exploitation without implying a patch", () => {
  const [item] = parseVendorFeed(IVANTI_RSS);
  const advisory = normalizeIvantiRssItem({ ref: { id: "august-2026-security-update", url: item.link }, contentType: "application/rss+xml", body: item, fetchedAt: observedAt, resolvedUrl: item.link }, observedAt, sanitize);
  assert.equal(advisory.exploitationStatus, "not_known_exploited");
  assert.equal(advisory.cves[0].cveId, "CVE-2026-4200");
  assert.deepEqual(advisory.remediations, []);
  assert.equal(advisory.zeroDayStatus, "unknown");
});

test("Ivanti RSS emits patch and zero-day state only when explicitly stated", () => {
  const body = {
    id: "fixture",
    title: "Emergency Ivanti security update for CVE-2026-4201",
    link: "https://www.ivanti.com/blog/emergency-security-update",
    description: "Ivanti is aware that CVE-2026-4201 is actively exploited as a zero-day. A patch is available now; apply the security update.",
    publishedAt: "2026-08-20T12:00:00.000Z",
  };
  const advisory = normalizeIvantiRssItem({ ref: { id: "emergency-security-update", url: body.link }, contentType: "application/rss+xml", body, fetchedAt: observedAt, resolvedUrl: body.link }, observedAt, sanitize);
  assert.equal(advisory.exploitationStatus, "known_exploited");
  assert.equal(advisory.zeroDayStatus, "confirmed");
  assert.equal(advisory.remediations[0].patchAvailable, true);
  assert.deepEqual(advisory.exploitEvidence.map((item) => item.type), ["known_exploitation", "zero_day"]);
});

test("Ivanti generic patch-program copy cannot create remediation without an asserted CVE", () => {
  const body = {
    id: "monthly-update",
    title: "Monthly Security Update",
    link: "https://www.ivanti.com/blog/monthly-security-update",
    description: "Ivanti releases standard security patches every month. See the linked notices for remediation details.",
    publishedAt: "2026-08-20T12:00:00.000Z",
  };
  const advisory = normalizeIvantiRssItem({ ref: { id: body.id, url: body.link }, contentType: "application/rss+xml", body, fetchedAt: observedAt, resolvedUrl: body.link }, observedAt, sanitize);
  assert.deepEqual(advisory.cves, []);
  assert.deepEqual(advisory.remediations, []);
});

test("Adobe defaults to official HTML and fails closed when the index is blocked", async () => {
  await assert.rejects(() => createAdobeAdapter().discover({ fetch: async () => new Response("blocked", { status: 403 }), policy }), /HTTP 403/);
  await assert.rejects(() => createAdobeAdapter({ indexUrl: "https://example.invalid/index.json" }).discover({ fetch, policy }), /official Adobe host/);
  const adapter = createAdobeAdapter({ indexUrl: "https://security.adobe.com/private/csaf-index.json" });
  await withFetch(async () => new Response(JSON.stringify({ advisories: [{ id: "APSB26-99", csaf_url: "https://security.adobe.com/csaf/APSB26-99.json", updated_at: "2026-08-19T12:00:00Z" }] }), { headers: { "content-type": "application/json" } }), async () => {
    const [ref] = await adapter.discover({ fetch, policy });
    assert.equal(ref.id, "APSB26-99");
    assert.equal(ref.url, "https://security.adobe.com/csaf/APSB26-99.json");
  });
  const [advisory] = normalizeAdobeCsaf(csafRaw("APSB26-99", structuredClone(EDGE_VENDOR_CSAF)), observedAt, sanitize);
  assert.equal(advisory.vendor, "adobe");
});

async function withFetch(stub, run) {
  const original = globalThis.fetch;
  globalThis.fetch = stub;
  try { return await run(); } finally { globalThis.fetch = original; }
}
