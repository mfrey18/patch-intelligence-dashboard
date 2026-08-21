export function makeAdvisory(overrides = {}) {
  return {
    vendor: "microsoft",
    sourceId: "msrc-csaf",
    vendorAdvisoryId: "MSRC-2026-08",
    title: "August 2026 security update",
    summary: "Security updates are available for a supported product.",
    sourceUrl: "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-1000",
    publishedAt: "2026-08-11T17:00:00.000Z",
    sourceUpdatedAt: "2026-08-11T17:00:00.000Z",
    vendorSeverity: "Critical",
    cvssScore: 9.8,
    exploitationStatus: "not_known_exploited",
    zeroDayStatus: "not_confirmed",
    cves: [
      {
        cveId: "CVE-2026-1000",
        description: "A remote code execution vulnerability.",
        cwe: "CWE-787",
        vendorSeverity: "Critical",
        normalizedSeverity: "critical",
        cvssScore: 9.8,
        cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        publishedAt: "2026-08-11T17:00:00.000Z",
        modifiedAt: "2026-08-11T17:00:00.000Z",
      },
    ],
    affectedProducts: [
      {
        cveId: "CVE-2026-1000",
        sourceProductId: "windows-server-2025",
        name: "Windows Server 2025",
        family: "Windows",
        affectedVersion: "24H2",
        fixedVersion: "26100.4946",
        status: "affected",
      },
    ],
    remediations: [
      {
        cveId: "CVE-2026-1000",
        productName: "Windows Server 2025",
        kind: "fixed_version",
        patchAvailable: true,
        fixedVersion: "26100.4946",
        action: "Install the August 2026 security update.",
        rebootRequired: true,
        sourceUrl: "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-1000",
        publishedAt: "2026-08-11T17:00:00.000Z",
      },
    ],
    exploitEvidence: [],
    releaseEvent: {
      id: "microsoft-patch-tuesday-2026-08",
      eventType: "patch_tuesday",
      eventDate: "2026-08-11",
      label: "Microsoft Patch Tuesday — August 2026",
      sourceUrl: "https://msrc.microsoft.com/update-guide/",
    },
    ...overrides,
  };
}

export function cloneAdvisory(advisory) {
  return structuredClone(advisory);
}
