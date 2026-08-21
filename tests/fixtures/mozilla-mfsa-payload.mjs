export const MOZILLA_MFSA_YAML = `## mfsa2026-73.yml
announced: August 04, 2026
impact: high
fixed_in:
- Firefox 153.0.3
- Firefox for Android 153.0.3
title: 'Security Vulnerabilities fixed in Firefox 153.0.3'
description: |
  Mozilla published fixed releases for the affected products.
advisories:
  CVE-2026-18809:
    title: Information disclosure in Firefox
    impact: high
    description: |
      A reporter stated that the issue was actively exploited. This prose alone
      is not authoritative exploitation-status metadata.
    reporter: The Mozilla Fuzzing Team
    bugs:
      - url: 2055683
  CVE-2026-18810:
    title: A lower-impact browser issue
    impact: moderate
    reporter: Example Reporter
    bugs:
      - url: 2055684
`;

export function makeMozillaRaw(body = MOZILLA_MFSA_YAML) {
  return {
    ref: {
      id: "mfsa2026-73",
      url: "https://raw.githubusercontent.com/mozilla/foundation-security-advisories/main/announce/2026/mfsa2026-73.yml",
      metadata: {
        repositoryPath: "announce/2026/mfsa2026-73.yml",
        repositorySha: "fixture-sha",
        publicationUrl: "https://www.mozilla.org/security/advisories/mfsa2026-73/",
      },
    },
    contentType: "text/yaml",
    body,
    fetchedAt: "2026-08-20T12:00:00.000Z",
    resolvedUrl: "https://raw.githubusercontent.com/mozilla/foundation-security-advisories/main/announce/2026/mfsa2026-73.yml",
  };
}
