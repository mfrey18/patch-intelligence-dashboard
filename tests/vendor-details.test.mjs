import assert from "node:assert/strict";
import test from "node:test";

import "./helpers/register-typescript.mjs";

const { parseBroadcomDetail, createBroadcomAdapter } = await import("../lib/ingestion/adapters/broadcom.ts");
const { parseFortinetHtml, parseFortinetIndex, normalizeFortinetHtml, createFortinetAdapter } = await import("../lib/ingestion/adapters/fortinet.ts");
const { parseIvantiDetail, normalizeIvantiHtml } = await import("../lib/ingestion/adapters/ivanti.ts");
const { parseSapDetail, normalizeSapHtml } = await import("../lib/ingestion/adapters/sap.ts");
const { parseCitrixDetail, normalizeCitrixHtml, createCitrixAdapter } = await import("../lib/ingestion/adapters/citrix.ts");

const sanitize = (value) => typeof value === "string" ? value.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim() || undefined : undefined;

const fortinetIndex = `<html><body><div class="row" id="fwb_id_1">Published: Sep 1, 2026</div><script>document.getElementById('fwb_id_1').addEventListener('click', function(event) {location.href = '/psirt/FG-IR-26-167'});</script><a aria-label="Next" href="/psirt?page=2">Next</a></body></html>`;
const fortinetDetail = `<html><head><meta property="og:url" content="https://fortiguard.fortinet.com/psirt/FG-IR-26-167"><meta property="og:title" content="FG-IR-26-167 FortiOS issue"></head><body><h1 class="title">FG-IR-26-167 FortiOS issue</h1><div class="content">CVE-2026-84387</div><table><tbody><tr><td>Published Date</td><td>2026-09-01</td></tr><tr><td>Severity</td><td>High</td></tr></tbody></table><table><thead><tr><th>Product</th><th>Affected</th><th>Solution</th></tr></thead><tbody><tr><td>FortiOS</td><td>7.4.0</td><td>Upgrade to 7.4.4</td></tr><tr><td>FortiProxy</td><td>7.2.0</td><td>Upgrade to 7.2.9</td></tr><tr><td>FortiAnalyzer</td><td>6.4.0</td><td>Upgrade to 6.4.12</td></tr></tbody></table></body></html>`;
const citrixDetail = `<html><head><script type="application/ld+json">{"@type":"Article","headline":"NetScaler security bulletin CTX696604","name":"NetScaler ADC","datePublished":"2026-07-01T00:00:00Z","dateModified":"2026-07-20T00:00:00Z"}</script></head><body><main><h1>NetScaler security bulletin CTX696604</h1><p>CVE-2026-8451 CVE-2026-8452 CVE-2026-8453 CVE-2026-8454 CVE-2026-8455 CVE-2026-8456</p><p>NetScaler ADC 14.1 BEFORE 14.1-72.61; 13.1 BEFORE 13.1-63.18.</p><p>14.1-72.61 and later; 13.1-63.18 and later; 13.1.37.272 and later.</p><p>Added the line: "The coordinated disclosure revision was also resolved."</p><table><thead><tr><th>CVE ID</th><th>Description</th><th>Preconditions</th><th>CVSS</th></tr></thead><tbody><tr><td>CVE-2026-8451</td><td>Authentication issue</td><td>Requires management access</td><td>Base Score: 8.8</td></tr><tr><td>CVE-2026-8452</td><td>Input validation issue</td><td>Requires management access</td><td>7.2</td></tr><tr><td>CVE-2026-8453</td><td>Issue</td><td>Requires management access</td><td>7.2</td></tr><tr><td>CVE-2026-8454</td><td>Issue</td><td>Requires management access</td><td>7.2</td></tr><tr><td>CVE-2026-8455</td><td>Issue</td><td>Requires management access</td><td>7.2</td></tr><tr><td>CVE-2026-8456</td><td>Issue</td><td>Requires management access</td><td>7.2</td></tr></tbody></table></main></body></html>`;
const citrixSitemap1 = `<urlset><url><loc>https://support.citrix.com/external/article/CTX696604/netscaler-adc-and-netscaler-gateway-security-bulletin.html</loc></url><url><loc>https://support.citrix.com/external/article/CTX41756/generic-kb.html</loc></url></urlset>`;
const citrixSitemap2 = `<urlset><url><loc>https://support.citrix.com/external/article/CTX700001/netscaler-security-bulletin.html</loc></url></urlset>`;

test("Fortinet parser follows the document's location targets without executing JavaScript", async () => {
  const page = parseFortinetIndex(fortinetIndex, "https://fortiguard.fortinet.com/psirt", "2026-08-31T00:00:00Z");
  assert.equal(page.refs[0].id, "FG-IR-26-167");
  assert.match(page.refs[0].url, /fortiguard\.fortinet\.com\/psirt\/FG-IR-26-167/);
  assert.match(page.nextUrl, /[?&]page=2(?:&|$)/);
  const parsed = parseFortinetHtml(fortinetDetail, page.refs[0].url);
  assert.equal(parsed.cves[0], "CVE-2026-84387");
  assert.equal(parsed.affectedProducts.length, 3);
  assert.equal(parsed.remediations[0].fixedVersion, "7.4.4");
  assert.equal(normalizeFortinetHtml(fortinetDetail, page.refs[0].url, sanitize).vendorAdvisoryId, "FG-IR-26-167");
});

test("Fortinet public HTML adapter is complete-index and configured CSAF stays subset", () => {
  assert.equal(createFortinetAdapter().historicalCoverage, "complete_index");
  assert.equal(createFortinetAdapter({ csafUrlTemplate: "https://filestore.fortinet.com/fortiguard/csaf/{id}.json" }).historicalCoverage, "configured_subset");
});

test("Broadcom detail associations remain row scoped", () => {
  const html = `<html><head><meta property="og:title" content="VCDSA advisory"><meta property="article:published_time" content="2026-09-01T00:00:00Z"></head><body><h1>VCDSA advisory</h1><table><thead><tr><th>Product</th><th>Affected</th><th>Fixed</th></tr></thead><tbody><tr><td>VMware ESXi</td><td>8.0</td><td>8.0 U3</td></tr></tbody></table><p>CVE-2026-1234</p></body></html>`;
  const parsed = parseBroadcomDetail(html, "https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/1");
  assert.deepEqual(parsed.cves, ["CVE-2026-1234"]);
  assert.equal(parsed.affectedProducts[0].cveId, undefined);
  assert.equal(parsed.remediations[0].productName, "VMware ESXi");
  assert.equal(createBroadcomAdapter({ fetchDetails: true }).historicalCoverage, "complete_index");
});

test("Broadcom parses response matrices whose header is rendered as table cells", () => {
  const html = `<html><h1>VCDSA advisory</h1><table><tbody><tr><td>VMware Product</td><td>Version</td><td>CVE</td><td>Fixed Version</td></tr><tr><td>VMware Fusion</td><td>25H2</td><td>CVE-2026-1234</td><td>26H1u1</td></tr></tbody></table></html>`;
  const parsed = parseBroadcomDetail(html, "https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/1");
  assert.equal(parsed.affectedProducts[0].name, "VMware Fusion");
  assert.equal(parsed.affectedProducts[0].fixedVersion, "26H1u1");
  assert.equal(parsed.remediations[0].fixedVersion, "26H1u1");
});

test("Broadcom and Fortinet do not turn negative or migration rows into fixes", () => {
  const broadcom = parseBroadcomDetail(`<html><h1>VCDSA advisory</h1><table><thead><tr><th>Product</th><th>Affected</th><th>Fixed</th></tr></thead><tbody><tr><td>Unaffected product</td><td>Not affected</td><td>N/A</td></tr><tr><td>Migrated product</td><td>8.0</td><td>Migrate to another branch</td></tr></tbody></table></html>`, "https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/1");
  assert.equal(broadcom.affectedProducts[0].status, "unaffected");
  assert.equal(broadcom.affectedProducts[1].status, "affected");
  assert.equal(broadcom.affectedProducts[1].fixedVersion, undefined);
  assert.deepEqual(broadcom.remediations, []);
  const fortinet = parseFortinetHtml(`<html><head><meta property="og:title" content="FG-IR-26-167"></head><body><h1>FG-IR-26-167</h1><table><thead><tr><th>Product</th><th>Affected</th><th>Solution</th></tr></thead><tbody><tr><td>Unaffected product</td><td>Not affected</td><td>N/A</td></tr><tr><td>Migrated product</td><td>5.0</td><td>Migrate to current release</td></tr></tbody></table></body></html>`, "https://fortiguard.fortinet.com/psirt/FG-IR-26-167");
  assert.equal(fortinet.affectedProducts[0].status, "unaffected");
  assert.equal(fortinet.affectedProducts[1].status, "affected");
  assert.equal(fortinet.affectedProducts[1].fixedVersion, undefined);
  assert.deepEqual(fortinet.remediations, []);
});

test("Ivanti detail parser accepts only official support links and explicit fixed rows", () => {
  const html = `<html><head><meta property="og:title" content="Ivanti Sentry advisory"><meta property="article:published_time" content="2026-09-01T00:00:00Z"></head><body><h1>Ivanti Sentry advisory</h1><p>CVE-2026-1234 has no evidence of exploitation.</p><table><thead><tr><th>Product</th><th>Affected version</th><th>Fixed version</th></tr></thead><tbody><tr><td>Sentry</td><td>10.0</td><td>10.1</td></tr></tbody></table></body></html>`;
  const parsed = parseIvantiDetail(html, "https://forums.ivanti.com/s/article/Ivanti-Sentry-CVE-2026-1234");
  assert.equal(parsed.vendorAdvisoryId, "Ivanti-Sentry-CVE-2026-1234");
  assert.deepEqual(parsed.cves, ["CVE-2026-1234"]);
  assert.equal(parsed.affectedProducts.length, 1);
  assert.equal(normalizeIvantiHtml(html, parsed.sourceUrl, sanitize).exploitationStatus, "unknown");
  assert.throws(() => parseIvantiDetail(html, "https://example.com/advisory"), /not official/);
});

test("SAP public index adapter does not treat its monthly landing page as an advisory", async () => {
  const html = `<html><head><title>January Security Notes</title></head><body><h1>Security Notes</h1><a href="https://me.sap.com/notes/1234567/E">SAP Note 1234567</a></body></html>`;
  const parsed = parseSapDetail(`<html><head><meta property="og:title" content="SAP Security Note 1234567"><meta property="article:published_time" content="2026-01-13T00:00:00Z"></head><body><h1>SAP Security Note 1234567 for CVE-2026-1234</h1><table><thead><tr><th>Product</th><th>Affected</th><th>Correction</th></tr></thead><tbody><tr><td>SAP NetWeaver</td><td>7.5</td><td>Apply correction</td></tr></tbody></table></body></html>`, "https://me.sap.com/notes/1234567/E");
  assert.equal(parsed.vendorAdvisoryId, "SAP-1234567");
  assert.deepEqual(parsed.cves, ["CVE-2026-1234"]);
  assert.equal(normalizeSapHtml(`<html><h1>SAP Security Note 1234567</h1></html>`, "https://me.sap.com/notes/1234567/E", sanitize).vendor, "sap");
  assert.match(html, /Security Notes/);
});

test("Citrix parser uses JSON-LD article identity and does not invent CVE mappings", async () => {
  const html = citrixDetail;
  const parsed = parseCitrixDetail(html, "https://support.citrix.com/external/article/696604");
  assert.equal(parsed.vendorAdvisoryId, "CTX696604");
  assert.equal(parsed.cves.length, 6);
  assert.equal(parsed.affectedProducts[0].cveId, undefined);
  assert.equal(parsed.preconditions.length, 6);
  assert.equal(parsed.revisions.length, 1);
  assert.equal(parsed.cveDetails["CVE-2026-8451"].cvssScore, 8.8);
  assert.equal(parsed.remediations.length, 3);
  assert.equal(parsed.remediations[0].fixedVersion, "14.1-72.61");
  assert.equal(normalizeCitrixHtml(html, parsed.sourceUrl, sanitize).vendor, "citrix");
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response("<sitemapindex></sitemapindex>", { headers: { "content-type": "application/xml" } });
  try { await assert.rejects(() => createCitrixAdapter().discover({ fetch, policy: { timeoutMs: 100, maxResponseBytes: 100_000, retries: 0, retryBaseMs: 1 } }), /sitemap did not expose/); } finally { globalThis.fetch = originalFetch; }
});

test("Citrix default discovery traverses the official sitemap chain and filters security bulletin slugs", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input) => {
    const url = String(input);
    if (url.endsWith("/sitemap.xml")) return new Response(`<sitemapindex><sitemap><loc>https://support.citrix.com/sitemap_1.xml</loc></sitemap><sitemap><loc>https://support.citrix.com/sitemap_2.xml</loc></sitemap></sitemapindex>`, { headers: { "content-type": "application/xml" } });
    if (url.endsWith("/sitemap_1.xml")) return new Response(citrixSitemap1, { headers: { "content-type": "application/xml" } });
    if (url.endsWith("/sitemap_2.xml")) return new Response(citrixSitemap2, { headers: { "content-type": "application/xml" } });
    throw new Error(`unexpected URL ${url}`);
  };
  try {
    const refs = await createCitrixAdapter().discover({ fetch, policy: { timeoutMs: 100, maxResponseBytes: 2_000_000, retries: 0, retryBaseMs: 1 } });
    assert.ok(refs.some((ref) => ref.id === "CTX696604"));
    assert.ok(refs.every((ref) => /\/external\/article\/CTX\d+\//.test(ref.url)));
    assert.equal(refs.some((ref) => ref.id === "CTX41756"), false);
  } finally { globalThis.fetch = originalFetch; }
});
