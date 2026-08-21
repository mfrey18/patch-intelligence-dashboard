import type { VendorId } from "../domain/types";

export interface SourceCatalogEntry {
  id: string;
  vendorId: VendorId | null;
  name: string;
  kind: "vendor_advisory" | "kev_snapshot" | "epss_snapshot";
  discoveryUrl: string;
  requiresConfiguration?: boolean;
}

/** Central source identity/provenance catalog shared by D1 seeding and dispatch. */
export const SOURCE_CATALOG = [
  { id: "microsoft-msrc-csaf", vendorId: "microsoft", name: "Microsoft MSRC CSAF", kind: "vendor_advisory", discoveryUrl: "https://api.msrc.microsoft.com/csaf/advisories/changes.csv" },
  { id: "cisco-psirt-csaf", vendorId: "cisco", name: "Cisco PSIRT OpenVuln + CSAF", kind: "vendor_advisory", discoveryUrl: "https://apix.cisco.com/security/advisories/v2/all/lastpublished", requiresConfiguration: true },
  { id: "adobe-psirt-csaf", vendorId: "adobe", name: "Adobe PSIRT configured CSAF", kind: "vendor_advisory", discoveryUrl: "https://helpx.adobe.com/security.html", requiresConfiguration: true },
  { id: "fortinet-psirt-csaf", vendorId: "fortinet", name: "Fortinet PSIRT RSS + configured CSAF", kind: "vendor_advisory", discoveryUrl: "https://filestore.fortinet.com/fortiguard/rss/ir.xml", requiresConfiguration: true },
  { id: "palo-alto-psirt-csaf", vendorId: "palo-alto", name: "Palo Alto Networks PSIRT CSAF", kind: "vendor_advisory", discoveryUrl: "https://security.paloaltonetworks.com/rss.xml" },
  { id: "ivanti-security-advisory-rss", vendorId: "ivanti", name: "Ivanti Security Advisory RSS", kind: "vendor_advisory", discoveryUrl: "https://www.ivanti.com/blog/topics/security-advisory/rss" },
  { id: "mozilla-mfsa-yaml", vendorId: "mozilla", name: "Mozilla Foundation Security Advisories", kind: "vendor_advisory", discoveryUrl: "https://api.github.com/repos/mozilla/foundation-security-advisories/contents/announce" },
  { id: "oracle-cpu-csaf", vendorId: "oracle", name: "Oracle Critical Patch Update CSAF", kind: "vendor_advisory", discoveryUrl: "https://www.oracle.com/a/tech/docs/security-alerts/" },
  { id: "atlassian-vulnerability-api", vendorId: "atlassian", name: "Atlassian Vulnerability API", kind: "vendor_advisory", discoveryUrl: "https://api.atlassian.com/vuln-transparency/v1/cves" },
  { id: "apple-configured-csaf", vendorId: "apple", name: "Apple configured CSAF", kind: "vendor_advisory", discoveryUrl: "https://support.apple.com/100100", requiresConfiguration: true },
  { id: "sap-configured-csaf", vendorId: "sap", name: "SAP entitled configured CSAF", kind: "vendor_advisory", discoveryUrl: "https://support.sap.com/en/my-support/knowledge-base/security-notes-news.html", requiresConfiguration: true },
  { id: "cisa-kev", vendorId: null, name: "CISA Known Exploited Vulnerabilities", kind: "kev_snapshot", discoveryUrl: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" },
  { id: "first-epss", vendorId: null, name: "FIRST EPSS bulk dataset", kind: "epss_snapshot", discoveryUrl: "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz" },
] as const satisfies readonly SourceCatalogEntry[];

export const SOURCE_IDS = new Set<string>(SOURCE_CATALOG.map((source) => source.id));
