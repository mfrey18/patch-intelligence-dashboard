import assert from "node:assert/strict";
import test from "node:test";

const workerUrl = new URL("../dist/server/index.js", import.meta.url);
workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}`);
const { default: worker } = await import(workerUrl.href);

const context = { waitUntil() {}, passThroughOnException() {} };
const environment = { ASSETS: { fetch: async () => new Response("Not found", { status: 404 }) } };

test("server-renders the vulnerability intelligence dashboard without fabricated records", async () => {
  const response = await worker.fetch(new Request("http://localhost/", { headers: { accept: "text/html" } }), environment, context);
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);
  assert.equal(response.headers.get("x-frame-options"), "DENY");
  const html = await response.text();
  assert.match(html, /<title>Vulnerability Intelligence<\/title>/i);
  assert.match(html, /Vulnerability Intelligence Dashboard/);
  assert.match(html, /Total Vulnerabilities/);
  assert.match(html, /Since last refresh/);
  assert.match(html, /Coverage &amp; Freshness/);
  assert.doesNotMatch(html, /What needs attention now|Operational triage|Priority queue|>PI</);
  assert.doesNotMatch(html, /CVE-2026-\d{4,}/);
});

test("public API fallback is read-only and internal ingestion is never cacheable", async () => {
  const dashboard = await worker.fetch(new Request("http://localhost/api/dashboard"), environment, context);
  assert.equal(dashboard.status, 200);
  assert.match(dashboard.headers.get("cache-control") ?? "", /public/);
  const body = await dashboard.json();
  assert.equal(body.demo, true);
  assert.equal(body.metrics.total, 0);

  const ingest = await worker.fetch(new Request("http://localhost/api/internal/ingest", { method: "POST", body: "{}", headers: { "content-type": "application/json" } }), environment, context);
  assert.equal(ingest.status, 503);
  assert.equal(ingest.headers.get("cache-control"), "no-store");
});

test("new intelligence routes render safe bounded states", async () => {
  const invalidVendor = await worker.fetch(new Request("http://localhost/vendor/not-allowlisted", { headers: { accept: "text/html" } }), environment, context);
  assert.equal(invalidVendor.status, 200);
  assert.match(await invalidVendor.text(), /Vendor not found/);

  const emptyComparison = await worker.fetch(new Request("http://localhost/compare", { headers: { accept: "text/html" } }), environment, context);
  assert.equal(emptyComparison.status, 200);
  assert.match(await emptyComparison.text(), /Choose two or three CVEs/);
});
