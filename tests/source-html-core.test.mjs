import assert from "node:assert/strict";
import test from "node:test";

import "./helpers/register-typescript.mjs";

const { absoluteOfficialUrl, explicitDate, fetchOfficialHtml, links, loadHtml, tableRows, text } = await import("../lib/ingestion/adapters/html.ts");

const policy = { timeoutMs: 1_000, maxResponseBytes: 100_000, retries: 0, retryBaseMs: 1 };

test("HTML primitives preserve links, text, dates, and table headers", () => {
  const document = loadHtml(`<!doctype html><main><h1>Security bulletin</h1><time datetime="2026-09-21T12:00:00Z">September 21, 2026</time><a href="/detail/1">APSB26-63</a><table><thead><tr><th>CVE</th><th>Fixed</th></tr></thead><tbody><tr><td>CVE-2026-0001</td><td>26.1</td></tr></tbody></table></main>`);
  assert.equal(text(document, "h1"), "Security bulletin");
  assert.deepEqual(links(document), [{ href: "/detail/1", text: "APSB26-63" }]);
  assert.deepEqual(tableRows(document), [{ headers: ["CVE", "Fixed"], cells: ["CVE-2026-0001", "26.1"] }]);
  assert.equal(explicitDate("September 21, 2026"), "2026-09-21T00:00:00.000Z");
  assert.equal(explicitDate("Published 2026-09-21"), "2026-09-21T00:00:00.000Z");
  assert.equal(absoluteOfficialUrl("https://adobe.com/security/index.html", "/detail/1", ["adobe.com"]), "https://adobe.com/detail/1");
  assert.equal(absoluteOfficialUrl("https://adobe.com/security/index.html", "https://example.invalid/detail", ["adobe.com"]), undefined);
});
test("fetchOfficialHtml enforces the official host and returns response metadata", async () => {
  const result = await fetchOfficialHtml("https://support.apple.com/security", {
    fetch: async () => new Response("<h1>Security</h1>", { headers: { "content-type": "text/html", etag: "v1" } }),
    policy,
  }, ["apple.com"]);
  assert.equal(result.html, "<h1>Security</h1>");
  assert.equal(result.url, "https://support.apple.com/security");
  assert.equal(result.etag, "v1");
  await assert.rejects(() => fetchOfficialHtml("https://example.invalid/security", { fetch, policy }, ["apple.com"]), /allowlisted/);
});

test("fetchOfficialHtml validates every manual redirect hop", async () => {
  let calls = 0;
  const result = await fetchOfficialHtml("https://support.apple.com/security", {
    fetch: async () => {
      calls += 1;
      return calls === 1
        ? new Response(null, { status: 302, headers: { location: "/security/latest" } })
        : new Response("<h1>Security</h1>");
    },
    policy,
  }, ["apple.com"]);
  assert.equal(calls, 2);
  assert.equal(result.url, "https://support.apple.com/security/latest");

  await assert.rejects(() => fetchOfficialHtml("https://support.apple.com/security", {
    fetch: async () => new Response(null, { status: 302, headers: { location: "https://example.invalid/away" } }),
    policy,
  }, ["apple.com"]), /allowlisted host/);
});
