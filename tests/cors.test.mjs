import assert from "node:assert/strict";
import test from "node:test";

import "./helpers/register-typescript.mjs";
const { addPublicCorsHeaders, allowedOrigins, publicCorsPreflight } = await import("../lib/api/cors.ts");

const configured = "https://owner.github.io,http://localhost:4173,https://invalid.example/path,ftp://files.example";

test("CORS accepts only configured exact dashboard origins", () => {
  assert.deepEqual([...allowedOrigins(configured)], ["https://owner.github.io", "http://localhost:4173"]);
  const allowedHeaders = new Headers();
  assert.equal(addPublicCorsHeaders(allowedHeaders, new Request("https://api.example/api/dashboard", { headers: { origin: "https://owner.github.io" } }), configured), true);
  assert.equal(allowedHeaders.get("access-control-allow-origin"), "https://owner.github.io");
  assert.match(allowedHeaders.get("vary") ?? "", /Origin/);

  const deniedHeaders = new Headers();
  assert.equal(addPublicCorsHeaders(deniedHeaders, new Request("https://api.example/api/dashboard", { headers: { origin: "https://attacker.example" } }), configured), false);
  assert.equal(deniedHeaders.get("access-control-allow-origin"), null);
});

test("CORS preflight permits read-only API methods and rejects unknown origins", () => {
  const allowed = publicCorsPreflight(new Request("https://api.example/api/cves/CVE-2026-1234", { method: "OPTIONS", headers: { origin: "https://owner.github.io" } }), configured);
  assert.equal(allowed.status, 204);
  assert.equal(allowed.headers.get("access-control-allow-origin"), "https://owner.github.io");
  assert.equal(allowed.headers.get("access-control-allow-methods"), "GET, OPTIONS");

  const denied = publicCorsPreflight(new Request("https://api.example/api/dashboard", { method: "OPTIONS", headers: { origin: "https://attacker.example" } }), configured);
  assert.equal(denied.status, 403);
  assert.equal(denied.headers.get("access-control-allow-origin"), null);
});
