export function makeRawAdvisory({
  refId,
  url,
  body,
  sourceUpdatedAt,
  metadata,
}) {
  return {
    ref: {
      id: refId,
      url,
      sourceUpdatedAt,
      metadata,
    },
    contentType: "application/json",
    body,
    fetchedAt: "2026-08-20T12:05:00.000Z",
    resolvedUrl: url,
  };
}

export function makeMicrosoftCvrf(overrides = {}) {
  const url = "https://api.msrc.microsoft.com/csaf/advisories/2026/msrc_cve-2026-1000.json";
  const body = {
    document: {
      title: "Remote code execution vulnerability",
      tracking: {
        id: "CVE-2026-1000",
        initial_release_date: "2026-08-11T17:00:00Z",
        current_release_date: "2026-08-12T17:00:00Z",
        version: "1.0.1",
      },
      aggregate_severity: { text: "Critical" },
      notes: [{ text: "Microsoft security advisory for an affected product." }],
    },
    product_tree: {
      branches: [{ name: "Windows Server", product: { product_id: "prod-1", name: "Windows Server 2025" } }],
    },
    vulnerabilities: [
      {
        cve: "CVE-2026-1000",
        notes: [{ text: "An unauthenticated attacker could execute code on an affected system." }],
        scores: [{ products: ["prod-1"], cvss_v3: { baseScore: 9.8, baseSeverity: "CRITICAL", vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" } }],
        product_status: { known_affected: ["prod-1"] },
        threats: [],
      },
    ],
    ...overrides,
  };

  return makeRawAdvisory({
    refId: "advisories:2026/msrc_cve-2026-1000",
    url,
    sourceUpdatedAt: "2026-08-12T17:00:00.000Z",
    metadata: {
      documentType: "advisory",
    },
    body,
  });
}

export function makeCiscoCsaf(overrides = {}) {
  const url = "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-example/csaf/cisco-sa-example.json";
  const body = {
    document: {
      title: "Cisco Example Product Vulnerability",
      tracking: {
        id: "cisco-sa-example",
        initial_release_date: "2026-08-18T16:00:00Z",
        current_release_date: "2026-08-19T16:00:00Z",
      },
      notes: [
        {
          text: "This advisory describes a vulnerability in an affected Cisco product.",
        },
      ],
    },
    product_tree: {
      branches: [
        {
          name: "Cisco Example Appliance",
          product: {
            product_id: "CSAFPID-1",
            name: "Cisco Example Appliance 1.0",
          },
        },
      ],
    },
    vulnerabilities: [
      {
        cve: "CVE-2026-2000",
        notes: [
          {
            text: "An unauthenticated attacker could execute commands on an affected appliance.",
          },
        ],
        scores: [
          {
            products: ["CSAFPID-1"],
            cvss_v3: {
              baseScore: 9.8,
              baseSeverity: "CRITICAL",
              vectorString:
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            },
          },
        ],
        product_status: { known_affected: ["CSAFPID-1"] },
        threats: [
          {
            category: "impact",
            details:
              "Remote exploitation could have a serious impact, but Cisco has not stated that exploitation was observed.",
          },
        ],
      },
    ],
    ...overrides,
  };

  return makeRawAdvisory({
    refId: "cisco-sa-example",
    url,
    sourceUpdatedAt: "2026-08-19T16:00:00.000Z",
    body,
  });
}

export function makeCisaKevSnapshot(overrides = {}) {
  return {
    title: "CISA Catalog of Known Exploited Vulnerabilities",
    catalogVersion: "2026.08.20",
    dateReleased: "2026-08-20T12:00:00.000Z",
    count: 1,
    vulnerabilities: [
      {
        cveID: "CVE-2026-3000",
        vendorProject: "Example Vendor",
        product: "Example Gateway",
        vulnerabilityName: "Example Gateway Command Injection Vulnerability",
        dateAdded: "2026-08-20",
        shortDescription:
          "The gateway contains a command injection vulnerability.",
        requiredAction:
          "Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.",
        dueDate: "2026-09-10",
        knownRansomwareCampaignUse: "Unknown",
        notes: "Follow CISA guidance.",
        cwes: ["CWE-78"],
      },
    ],
    ...overrides,
  };
}

export const EPSS_CURRENT_CSV = [
  "#model_version:v2025.03.14,score_date:2026-08-19T00:00:00.000Z",
  "cve,epss,percentile",
  "CVE-2026-1000,0.01234,0.54321",
  "CVE-2026-2000,0.87654,0.98765",
  "",
].join("\n");

export function textStream(value, chunkSize = value.length) {
  const bytes = new TextEncoder().encode(value);
  return new ReadableStream({
    start(controller) {
      for (let offset = 0; offset < bytes.length; offset += chunkSize) {
        controller.enqueue(bytes.slice(offset, offset + chunkSize));
      }
      controller.close();
    },
  });
}
