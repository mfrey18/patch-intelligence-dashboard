export function makeRaw({ id, url, body }) {
  return {
    ref: { id, url },
    contentType: "application/json",
    body,
    fetchedAt: "2026-08-20T12:00:00.000Z",
    resolvedUrl: url,
  };
}

export function makeAtlassianRaw(overrides = {}) {
  const cveId = "CVE-2026-4100";
  return makeRaw({
    id: cveId,
    url: `https://api.atlassian.com/vuln-transparency/v1/cves?cve_ids=${cveId}`,
    body: {
      cve: {
        cve_id: cveId,
        cve_summary: "A vulnerability in an Atlassian Data Center product",
        cve_details: "An authenticated user can trigger an authorization failure in an affected product.",
        cve_vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
        cve_publish_date: "2026-08-18T00:00:00.000+0000",
        cve_severity: 8.1,
        advisory_url: "https://www.atlassian.com/trust/security/advisories/example",
        affected_products: ["Confluence Data Center"],
      },
      productStatuses: [
        { product: "Confluence Data Center", version: "9.0.0", status: "AFFECTED" },
        { product: "Confluence Data Center", version: "9.0.1", status: "FIXED" },
      ],
      ...overrides,
    },
  });
}

export function makeOracleCsaf() {
  const url = "https://www.oracle.com/a/tech/docs/security-alerts/cpujul2026csaf.json";
  return makeRaw({
    id: "cpujul2026",
    url,
    body: {
      document: {
        title: "Oracle Critical Patch Update Advisory - July 2026",
        tracking: {
          id: "CPUJul2026csaf",
          initial_release_date: "2026-07-21T13:00:00-07:00",
          current_release_date: "2026-07-30T13:00:00-07:00",
        },
        notes: [{ text: "Oracle Critical Patch Update machine-readable advisory." }],
      },
      product_tree: {
        branches: [{
          name: "Oracle Example Product",
          product: { product_id: "P-1V-4.2", name: "Oracle Example Product Version 4.2" },
        }],
      },
      vulnerabilities: [{
        cve: "CVE-2026-4200",
        notes: [{ text: "A vulnerability affects an explicitly listed Oracle product version." }],
        scores: [{ cvss_v3: { baseScore: 9.1, baseSeverity: "CRITICAL", vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" } }],
        product_status: { known_affected: ["P-1V-4.2"] },
        threats: [{ category: "impact", details: "A successful attack can have a serious impact." }],
        remediations: [{ category: "vendor_fix", details: "Oracle customers with valid support contracts", product_ids: ["P-1V-4.2"], url }],
      }],
    },
  });
}

export function makeConfiguredCsaf(vendor) {
  const url = `https://security.${vendor}.com/advisories/example.json`;
  return makeRaw({
    id: `${vendor}-example`,
    url,
    body: {
      document: {
        title: `${vendor} configured CSAF fixture`,
        tracking: { id: `${vendor}-example`, initial_release_date: "2026-08-12T12:00:00Z", current_release_date: "2026-08-12T12:00:00Z" },
      },
      product_tree: { branches: [{ product: { product_id: "product-1", name: `${vendor} Product 1` } }] },
      vulnerabilities: [{
        cve: vendor === "apple" ? "CVE-2026-4300" : "CVE-2026-4400",
        scores: [{ cvss_v3: { baseScore: 9.8, baseSeverity: "CRITICAL" } }],
        product_status: { known_affected: ["product-1"] },
      }],
    },
  });
}
