import assert from "node:assert/strict";
import test from "node:test";

import "./helpers/register-typescript.mjs";

const { createAdobeAdapter } = await import("../lib/ingestion/adapters/adobe.ts");
const { createAppleAdapter } = await import("../lib/ingestion/adapters/apple.ts");
const { createChromeAdapter } = await import("../lib/ingestion/adapters/chrome.ts");
const { normalizeAdobeHtml } = await import("../lib/ingestion/adapters/adobe.ts");
const { normalizeAppleHtml } = await import("../lib/ingestion/adapters/apple.ts");
const { normalizeChromeHtml } = await import("../lib/ingestion/adapters/chrome.ts");

const policy = { timeoutMs: 1_000, maxResponseBytes: 100_000, retries: 0, retryBaseMs: 1 };
const sanitize = (value) => typeof value === "string" ? value.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim() || undefined : undefined;
const observedAt = "2026-09-22T00:00:00.000Z";
const context = (fetch) => ({ fetch, policy });

function response(body) { return new Response(body, { headers: { "content-type": "text/html" } }); }

test("Adobe HTML discovers stable APSB IDs and preserves explicit CVE/fix assertions", async () => {
  const index = `<main><a href="/security/products/acrobat/apsb26-63.html">APSB26-63 Security update 2026-09-20</a></main>`;
  const detail = `<main><h1>APSB26-63 Acrobat</h1><time datetime="2026-09-20T00:00:00Z"></time><p>CVE-2026-0001 Severity: Important.</p><table><thead><tr><th>CVE</th><th>Solution</th></tr></thead><tbody><tr><td>CVE-2026-0001</td><td>26.001</td></tr></tbody></table></main>`;
  const sitemap = `<urlset><url><loc>https://helpx.adobe.com/security/products/acrobat/apsb26-63.html</loc><lastmod>2026-09-20</lastmod></url><url><loc>https://helpx.adobe.com/security/products/acrobat/apsb26-12.html</loc><lastmod>2026-03-01</lastmod></url></urlset>`;
  const fetcher = async (input) => String(input).endsWith("sitemap.xml") ? response(sitemap) : String(input).endsWith("security.html") ? response(index) : response(detail);
  const adapter = createAdobeAdapter();
  const [ref] = await adapter.discover(context(fetcher));
  assert.deepEqual(ref, { id: "APSB26-63", url: "https://helpx.adobe.com/security/products/acrobat/apsb26-63.html", sourceUpdatedAt: "2026-09-20T00:00:00.000Z" });
  const [advisory] = await adapter.normalize(await adapter.fetch(ref, context(fetcher)), { observedAt, sanitizeText: sanitize });
  assert.equal(advisory.vendorAdvisoryId, "APSB26-63");
  assert.equal(advisory.cves[0].cveId, "CVE-2026-0001");
  assert.equal(advisory.remediations[0].fixedVersion, "26.001");
});

test("Adobe default HTML discovery fails closed when the official sitemap is malformed", async () => {
  const adapter = createAdobeAdapter();
  await assert.rejects(() => adapter.discover(context(async () => response("<html><body>temporary error</body></html>"))), /sitemap was unavailable or malformed/);
});

test("Adobe default discovery rejects a sitemap that cannot prove the requested window", async () => {
  const sitemap = `<urlset><url><loc>https://helpx.adobe.com/security/products/acrobat/apsb26-145.html</loc><lastmod>2026-09-20</lastmod></url></urlset>`;
  await assert.rejects(() => createAdobeAdapter().discover({ fetch: async () => response(sitemap), since: "2026-03-01T00:00:00Z", until: observedAt, policy }), /historical boundary/);
});
test("Apple HTML uses the explicit support document ID and keeps unknown threat state unknown", async () => {
  const html = `<main><h1>About the security content of Apple devices</h1><time datetime="2026-09-19T00:00:00Z"></time><p>CVE-2026-0002 Severity: High.</p></main>`;
  const fetcher = async () => response(html);
  const adapter = createAppleAdapter({ indexUrl: "https://support.apple.com/en-us/100100" });
  await assert.rejects(() => adapter.discover(context(fetcher)), /no identifiable security advisories/);
});

test("Chrome HTML paginates official release links and does not infer exploitation", async () => {
  const index = `<div class="post" data-id="123"><h2 class="title"><a itemprop="url" href="/2026/09/stable-channel-update-for-desktop_123.html">Stable Channel Update for Desktop</a></h2><span itemprop="datePublished">Friday, September 18, 2026</span></div><a class="blog-pager-older-link" href="/page/2">Older Posts</a>`;
  const older = `<div class="post" data-id="124"><h2 class="title"><a itemprop="url" href="/2026/08/extended-stable-update-for-desktop_124.html">Extended Stable Update for Desktop</a></h2><span itemprop="datePublished">Tuesday, August 18, 2026</span></div>`;
  const detail = `<main><h1>Chrome security update</h1><time datetime="2026-09-18T00:00:00Z"></time><p>CVE-2026-0003 Severity: High. No evidence of active exploitation.</p></main>`;
  const fetcher = async (input) => {
    const url = String(input);
    if (url.endsWith("/")) return response(index);
    if (url.endsWith("/page/2")) return response(older);
    return response(detail);
  };
  const adapter = createChromeAdapter();
  const refs = await adapter.discover(context(fetcher));
  assert.deepEqual(refs.map((ref) => ref.id), ["CHROME-POST-123", "CHROME-POST-124"]);
  const [advisory] = await adapter.normalize(await adapter.fetch(refs[0], context(fetcher)), { observedAt, sanitizeText: sanitize });
  assert.equal(advisory.cves[0].cveId, "CVE-2026-0003");
  assert.equal(advisory.exploitationStatus, "not_known_exploited");
  assert.equal(advisory.exploitEvidence[0].status, "not_confirmed");
});

test("configured Apple CSAF remains an explicit override", async () => {
  const adapter = createAppleAdapter({ csafUrls: ["https://support.apple.com/security/advisory.json"] });
  const refs = await adapter.discover(context(async () => response("{}")));
  assert.deepEqual(refs, [{ id: "advisory", url: "https://support.apple.com/security/advisory.json" }]);
});

test("Adobe detail table shape joins product tables without CVE multiplication", () => {
  const adobeFixture = `<main><h1>Adobe Security Bulletin</h1><table><tbody><tr><td>Product</td><td>Track</td><td>Affected version</td><td>Platform</td></tr><tr><td>Adobe InDesign</td><td>Continuous</td><td>ID21.5 and earlier versions</td><td>Windows and macOS</td></tr><tr><td>Adobe InDesign</td><td>Continuous</td><td>ID20.5.4 and earlier versions</td><td>Windows and macOS</td></tr></tbody></table><table><tbody><tr><td>Product</td><td>Track</td><td>Updated version</td><td>Platform</td></tr><tr><td>Adobe InDesign</td><td>Continuous</td><td>ID21.6</td><td>Windows and macOS</td></tr><tr><td>Adobe InDesign</td><td>Continuous</td><td>ID20.5.5</td><td>Windows and macOS</td></tr></tbody></table><table><tbody><tr><td>Vulnerability Category</td><td>Severity</td><td>CVE Number</td></tr><tr><td>NULL Pointer Dereference</td><td>Important</td><td>CVE-2026-0006</td></tr><tr><td>Use After Free</td><td>Critical</td><td>CVE-2026-0007</td></tr></tbody></table></main>`;
  const advisory = normalizeAdobeHtml({
    ref: { id: "APSB26-63", url: "https://helpx.adobe.com/security/products/acrobat/apsb26-63.html", sourceUpdatedAt: "2026-06-15T00:00:00Z" },
    contentType: "text/html",
    body: adobeFixture,
    fetchedAt: observedAt,
    resolvedUrl: "https://helpx.adobe.com/security/products/acrobat/apsb26-63.html",
  }, sanitize);
  assert.equal(advisory.cves.length, 2);
  assert.deepEqual(advisory.affectedProducts.map((product) => product.fixedVersion), ["ID21.6", "ID20.5.5"]);
  assert.equal(advisory.remediations.length, 2);
  assert.ok(advisory.remediations.every((remediation) => remediation.cveId === undefined));
});

test("Apple component scope and Chrome Blogger article templates retain explicit fixes", () => {
  const apple = normalizeAppleHtml({
    ref: { id: "APPLE-149034", url: "https://support.apple.com/en-us/149034", sourceUpdatedAt: observedAt },
    contentType: "text/html",
    body: `<main><h1>About the security content of iOS 27 and iPadOS 27</h1><h2>iOS 27 and iPadOS 27</h2><h3>Kernel</h3><p>Available for: iPhone 11 and later</p><p>Impact: An app may execute arbitrary code. CVE-2026-0004</p></main>`,
    fetchedAt: observedAt,
    resolvedUrl: "https://support.apple.com/en-us/149034",
  }, sanitize);
  assert.equal(apple.cves[0].cveId, "CVE-2026-0004");
  assert.equal(apple.affectedProducts[0].fixedVersion, "iOS 27 and iPadOS 27");
  assert.equal(apple.affectedProducts[0].affectedVersion, "iPhone 11 and later");

  const chrome = normalizeChromeHtml({
    ref: { id: "CHROME-POST-1", url: "https://chromereleases.googleblog.com/2026/09/stable.html", sourceUpdatedAt: observedAt },
    contentType: "text/html",
    body: `<article class="post"><h2 class="title">Stable Channel Update for Desktop</h2><div class="post-content" itemprop="articleBody"><script type="text/template"><p>Chrome 154.0.8037.57 (Linux) 154.0.8037.57/.58 Windows/Mac contains fixes.</p><p>High CVE-2026-0005: Memory safety bug.</p></script></div></article>`,
    fetchedAt: observedAt,
    resolvedUrl: "https://chromereleases.googleblog.com/2026/09/stable.html",
  }, sanitize);
  assert.equal(chrome.cves[0].cveId, "CVE-2026-0005");
  assert.equal(chrome.affectedProducts.length, 2);
  assert.equal(chrome.remediations.length, 2);
  assert.equal(createAdobeAdapter().historicalCoverage, "complete_index");
  assert.equal(createAppleAdapter().historicalCoverage, "complete_index");
  assert.equal(createChromeAdapter().historicalCoverage, "complete_index");
  assert.equal(createAppleAdapter({ indexUrl: "https://support.apple.com/custom-index" }).historicalCoverage, undefined);
  assert.equal(createChromeAdapter({ indexUrl: "https://chromereleases.googleblog.com/custom" }).historicalCoverage, undefined);
});

test("Chrome pagination stops after a page crosses the requested retention boundary", async () => {
  const html = `<div class="post" data-id="new"><h2 class="title"><a itemprop="url" href="/2026/09/stable-channel-update-for-desktop_new.html">Stable Channel Update for Desktop</a></h2><span itemprop="datePublished">Tuesday, September 1, 2026</span></div><div class="post" data-id="old"><h2 class="title"><a itemprop="url" href="/2026/03/stable-channel-update-for-desktop_old.html">Stable Channel Update for Desktop</a></h2><span itemprop="datePublished">Sunday, March 1, 2026</span></div><a id="Blog1_blog-pager-older-link" href="/older">Older Posts</a>`;
  const adapter = createChromeAdapter({ indexUrl: "https://chromereleases.googleblog.com/custom" });
  const page = await adapter.discoverPage({ fetch: async () => response(html), since: "2026-03-28T00:00:00Z", until: observedAt, policy });
  assert.deepEqual(page.refs.map((ref) => ref.id), ["CHROME-POST-new"]);
  assert.equal(page.nextCursor, null);
});
