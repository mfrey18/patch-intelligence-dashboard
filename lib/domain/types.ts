export const VENDOR_IDS = [
  "microsoft", "cisco", "adobe", "fortinet", "palo-alto", "ivanti", "vmware-broadcom", "citrix", "chrome", "mozilla", "apple", "oracle", "atlassian", "sap",
] as const;

export type VendorId = (typeof VENDOR_IDS)[number];
export type NormalizedSeverity = "critical" | "high" | "medium" | "low" | "unknown";
export type ExploitationStatus = "known_exploited" | "not_known_exploited" | "unknown";
export type ZeroDayStatus = "confirmed" | "not_confirmed" | "unknown";
export type RemediationKind = "patch" | "fixed_version" | "mitigation" | "workaround" | "vendor_action";
export type PriorityLevel = "P1" | "P2" | "P3";

export const CHANGE_TYPES = [
  "NEW_ADVISORY", "NEW_CVE", "ADVISORY_REVISED", "SEVERITY_CHANGED", "CVSS_CHANGED", "EXPLOITATION_STATUS_CHANGED", "ZERO_DAY_STATUS_CHANGED", "KEV_ADDED", "KEV_REMOVED", "KEV_DEADLINE_CHANGED", "KEV_ENTRY_MODIFIED", "AFFECTED_PRODUCT_ADDED", "AFFECTED_PRODUCT_REMOVED", "FIXED_VERSION_CHANGED", "REMEDIATION_CHANGED", "MITIGATION_ADDED", "WORKAROUND_ADDED", "SOURCE_MODIFIED",
] as const;

export type ChangeType = (typeof CHANGE_TYPES)[number];

export interface NormalizedCveAssertion {
  cveId: string;
  description?: string;
  cwe?: string;
  vendorSeverity?: string;
  normalizedSeverity: NormalizedSeverity;
  cvssScore?: number;
  cvssVector?: string;
  publishedAt?: string;
  modifiedAt?: string;
}

export interface NormalizedAffectedProduct {
  cveId?: string;
  sourceProductId?: string;
  name: string;
  family?: string;
  affectedVersion?: string;
  fixedVersion?: string;
  status: "affected" | "fixed" | "unaffected" | "unknown";
}

export interface NormalizedRemediation {
  cveId?: string;
  productName?: string;
  kind: RemediationKind;
  patchAvailable?: boolean;
  fixedVersion?: string;
  action?: string;
  rebootRequired?: boolean;
  superseded?: boolean;
  sourceUrl: string;
  publishedAt?: string;
  updatedAt?: string;
}

export interface NormalizedExploitEvidence {
  cveId: string;
  type: "known_exploitation" | "zero_day" | "public_disclosure";
  status: "confirmed" | "not_confirmed" | "unknown";
  evidenceDate?: string;
  evidenceUrl: string;
  summary?: string;
}

export interface NormalizedReleaseEvent {
  id: string;
  eventType: "patch_tuesday" | "security_release" | "quarterly_cpu" | "critical_security_patch_update" | "vendor_release";
  eventDate: string;
  label: string;
  sourceUrl?: string;
  reportedCveCount?: number;
  reportedAt?: string;
  /** Vendor-reported affected-CVE counts by product family. Counts may overlap. */
  reportedProductFamilies?: Array<{ label: string; value: number }>;
}

export interface NormalizedAdvisory {
  vendor: VendorId;
  sourceId: string;
  vendorAdvisoryId: string;
  title: string;
  summary?: string;
  sourceUrl: string;
  publishedAt?: string;
  sourceUpdatedAt?: string;
  vendorSeverity?: string;
  cvssScore?: number;
  exploitationStatus: ExploitationStatus;
  zeroDayStatus: ZeroDayStatus;
  cves: NormalizedCveAssertion[];
  affectedProducts: NormalizedAffectedProduct[];
  remediations: NormalizedRemediation[];
  exploitEvidence: NormalizedExploitEvidence[];
  releaseEvent?: NormalizedReleaseEvent;
}

export interface AdvisoryHashes {
  contentHash: string;
  affectedProductsHash: string;
  remediationHash: string;
}

export interface AdvisorySnapshot extends AdvisoryHashes {
  advisory: NormalizedAdvisory;
}

export interface PriorityResult {
  level: PriorityLevel;
  reasons: string[];
  components: {
    kev: boolean;
    exploitationStatus: ExploitationStatus;
    severity: NormalizedSeverity;
    cvss: number | null;
    epssPercentile: number | null;
  };
}

export interface DashboardVulnerabilityRow {
  cveId: string;
  title: string;
  vendor: string;
  product: string | null;
  severity: NormalizedSeverity;
  cvss: number | null;
  epss: number | null;
  epssPercentile: number | null;
  kev: boolean;
  knownExploited: boolean;
  zeroDay: boolean;
  patchAvailable: boolean | null;
  mitigationAvailable: boolean;
  workaroundAvailable: boolean;
  publishedAt: string | null;
  modifiedAt: string | null;
  priority: PriorityResult;
}
