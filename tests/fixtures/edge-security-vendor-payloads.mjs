export const EDGE_VENDOR_CSAF = {
  document: {
    title: "Synthetic vendor security advisory",
    tracking: {
      id: "SYNTH-2026-001",
      initial_release_date: "2026-08-12T16:00:00Z",
      current_release_date: "2026-08-19T16:00:00Z",
    },
    notes: [{ category: "summary", text: "A synthetic fixture used only to verify CSAF normalization behavior." }],
  },
  product_tree: {
    branches: [{ name: "Edge Appliance", product: { product_id: "prod-1", name: "Edge Appliance 9" } }],
  },
  vulnerabilities: [{
    cve: "CVE-2026-4100",
    notes: [{ category: "description", text: "A synthetic vulnerability description long enough to be selected by the normalizer." }],
    product_status: { known_affected: ["prod-1"] },
    scores: [{ cvss_v3: { baseScore: 9.1, baseSeverity: "CRITICAL", vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" } }],
    threats: [{ category: "exploit_status", details: "No known exploitation has been observed.", date: "2026-08-19T16:00:00Z" }],
    remediations: [{ category: "vendor_fix", details: "Install release 9.2.1.", fixed_release: "9.2.1", product_ids: ["prod-1"], date: "2026-08-19T16:00:00Z" }],
  }],
};

export function csafRaw(vendorId, body = structuredClone(EDGE_VENDOR_CSAF)) {
  return {
    ref: { id: vendorId, url: `https://security.example.invalid/csaf/${vendorId}` },
    contentType: "application/json",
    body,
    fetchedAt: "2026-08-20T12:00:00.000Z",
    resolvedUrl: `https://security.example.invalid/csaf/${vendorId}`,
  };
}

export const PALO_ALTO_RSS = `<?xml version="1.0"?><rss version="2.0"><channel>
  <item><title>CVE-2026-4100 Edge Appliance issue (Severity: CRITICAL)</title><pubDate>2026-08-12T16:00:00.000Z</pubDate><link>https://security.paloaltonetworks.com/CVE-2026-4100</link><guid>https://security.paloaltonetworks.com/CVE-2026-4100</guid></item>
  <item><title>Untrusted link</title><link>https://example.invalid/CVE-2026-9999</link><guid>bad</guid></item>
</channel></rss>`;

export const FORTINET_RSS = `<?xml version="1.0"?><rss version="2.0"><channel>
  <item><title>Synthetic Fortinet fixture</title><link>https://fortiguard.fortinet.com/psirt/FG-IR-26-999</link><description><![CDATA[<p>CVSSv3 Score: 9.1</p><p><em>Revised on 2026-08-19 00:00:00</em></p>]]></description><guid>https://fortiguard.fortinet.com/psirt/FG-IR-26-999</guid><pubDate>Wed, 12 Aug 2026 00:00:00 -0700</pubDate></item>
</channel></rss>`;

export const IVANTI_RSS = `<?xml version="1.0"?><rss version="2.0"><channel>
  <item><guid isPermaLink="false">fixture-guid</guid><link>https://www.ivanti.com/blog/august-2026-security-update</link><title>August 2026 Security Update</title><description>&lt;p&gt;Ivanti has no evidence of CVE-2026-4200 being exploited in the wild.&lt;/p&gt;</description><pubDate>Wed, 12 Aug 2026 10:00:00 -0600</pubDate></item>
</channel></rss>`;
