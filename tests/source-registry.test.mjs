import assert from "node:assert/strict";
import test from "node:test";

import "./helpers/register-typescript.mjs";

const { SOURCE_CATALOG, SOURCE_IDS } = await import("../lib/ingestion/source-catalog.ts");
const { createVendorAdapter, defaultSourceIds } = await import("../lib/ingestion/source-registry.ts");

test("source catalog has unique centralized IDs and resolves every vendor adapter", () => {
  assert.equal(SOURCE_IDS.size, SOURCE_CATALOG.length);
  for (const source of SOURCE_CATALOG.filter((entry) => entry.vendorId)) {
    assert.equal(createVendorAdapter(source.id, {})?.sourceId, source.id);
  }
  assert.equal(createVendorAdapter("cisa-kev", {}), null);
  assert.equal(createVendorAdapter("first-epss", {}), null);
});

test("default ingestion excludes credential-dependent sources until configured", () => {
  const defaults = defaultSourceIds({});
  assert.ok(defaults.includes("microsoft-msrc-csaf"));
  assert.ok(defaults.includes("cisa-kev"));
  assert.ok(defaults.includes("first-epss"));
  assert.ok(!defaults.includes("cisco-psirt-csaf"));
  assert.ok(!defaults.includes("adobe-psirt-csaf"));
  assert.ok(!defaults.includes("fortinet-psirt-csaf"));
  assert.ok(!defaults.includes("apple-configured-csaf"));
  assert.ok(!defaults.includes("sap-configured-csaf"));

  const configured = defaultSourceIds({
    CISCO_CLIENT_ID: "id",
    CISCO_CLIENT_SECRET: "secret",
    ADOBE_SECURITY_INDEX_URL: "https://adobe.com/security/index.json",
    FORTINET_CSAF_URL_TEMPLATE: "https://fortinet.com/security/{id}.json",
    APPLE_CSAF_URLS: '["https://support.apple.com/security/advisory.json"]',
    SAP_CSAF_URLS: "https://support.sap.com/security/advisory.json",
  });
  assert.equal(configured.length, SOURCE_CATALOG.length);
});
