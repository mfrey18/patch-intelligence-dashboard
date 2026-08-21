import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const html = await readFile(new URL("../dist-pages/index.html", import.meta.url), "utf8");

test("GitHub Pages artifact uses the configured base path and API origin", () => {
  const apiOrigin = process.env.VITE_API_BASE_URL;
  const basePath = process.env.PAGES_BASE_PATH || "/";
  assert.ok(apiOrigin, "VITE_API_BASE_URL must be present while checking the artifact");
  assert.match(html, new RegExp(`connect-src 'self' ${escapeRegExp(apiOrigin)}`));
  assert.match(html, new RegExp(`(?:src|href)="${escapeRegExp(basePath)}assets/`));
  assert.doesNotMatch(html, /%VITE_[A-Z0-9_]+%/);
});

test("GitHub Pages artifact contains only static client assets", () => {
  assert.match(html, /<div id="root"><\/div>/);
  assert.doesNotMatch(html, /INGEST_SECRET|CISCO_CLIENT_SECRET|CLOUDFLARE_API_TOKEN/);
});

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
