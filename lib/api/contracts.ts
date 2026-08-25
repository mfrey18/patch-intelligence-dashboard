import type { DashboardVulnerabilityRow, PriorityResult } from "../domain/types";

export interface DashboardMetrics { total: number; critical: number; high: number; knownExploited: number; kev: number; zeroDay: number; patchAvailable: number; }
export interface ChangeMetrics { since: string | null; newCves: number; newCritical: number; newlyKnownExploited: number; newKev: number; revisedAdvisories: number; newRemediation: number; }
export interface SourceHealth { sourceId: string; name: string; lastAttempt: string | null; lastSuccess: string | null; lastFailure: string | null; durationMs: number | null; result: string | null; mode: string | null; freshness: "fresh" | "stale" | "never"; discovered: number; inserted: number; changed: number; unchanged: number; failed: number; boundHit: boolean; errorSummary: string | null; lease: { active: boolean; expiresAt: string | null }; checkpoint: { id: string; status: string; windowStart: string; windowEnd: string } | null; }
export interface VulnerabilityActivityBucket { bucket: string; label: string; critical: number; high: number; medium: number; low: number; }
export interface ThreatSignalBucket { bucket: string; label: string; knownExploited: number; kev: number; zeroDay: number; highEpss: number; }
export interface EpssMover { cveId: string; vendor: string; product: string | null; previousScoreDate: string; scoreDate: string; previousScore: number; score: number; previousPercentile: number; percentile: number; scoreDelta: number; percentileDelta: number; modelVersion: string | null; }
export interface EmergingVulnerability { vulnerability: DashboardVulnerabilityRow; reasons: string[]; latestChangeAt: string | null; }
export interface VendorThreatMetric { label: string; total: number; knownExploited: number; kev: number; zeroDay: number; highEpss: number; }
export interface CweAnalytics { knownCoverage: number; total: number; series: Array<{ label: string; value: number; critical: number; exploited: number }>; }
export interface DashboardResponse {
  generatedAt: string;
  metrics: DashboardMetrics;
  changes: ChangeMetrics;
  priorityDistribution: Record<"P1" | "P2" | "P3", number>;
  severitySeries: Array<{ label: string; value: number }>;
  vendorSeries: Array<{ label: string; value: number }>;
  productSeries: Array<{ label: string; value: number }>;
  vulnerabilityActivity: VulnerabilityActivityBucket[];
  threatSignalActivity: ThreatSignalBucket[];
  epssMovers: EpssMover[];
  emergingVulnerabilities: EmergingVulnerability[];
  vendorThreatSeries: VendorThreatMetric[];
  changeCategoryCounts: Record<"threat" | "assessment" | "advisory" | "remediation", number>;
  cweAnalytics: CweAnalytics;
  rows: DashboardVulnerabilityRow[];
  recentChanges: Array<{ cveId: string | null; advisoryId: string | null; changeType: string; summary: string; observedAt: string }>;
  nextCursor: string | null;
  sourceHealth: SourceHealth[];
  latestReleaseEvent: { id: string; label: string; eventDate: string; total: number; linkedTotal: number; totalBasis: "vendor_reported" | "linked_advisories"; totalSourceUrl: string | null; reportedAt: string | null; critical: number; high: number; knownExploited: number; zeroDay: number; kev: number; productFamilies: Array<{ label: string; value: number }>; comparison: { label: string; eventDate: string; totalDelta: number; linkedTotal: number; criticalDelta: number; highDelta: number; knownExploitedDelta: number; zeroDayDelta: number; kevDelta: number } | null } | null;
  demo?: boolean;
}

export interface CveDetailResponse {
  canonical: { cveId: string; description: string | null; cwe: string | null; cvss: number | null; cvssVector: string | null; publishedAt: string | null; modifiedAt: string | null; sourceUrl: string | null };
  priority: PriorityResult;
  advisories: Array<{ id: string; sourceId: string; observedAt: string; vendor: string; vendorAdvisoryId: string; title: string; sourceUrl: string; vendorSeverity: string | null; normalizedSeverity: string; vendorCvss: number | null; vendorCvssVector: string | null; publishedAt: string | null; modifiedAt: string | null }>;
  affectedProducts: Array<{ advisoryId: string; sourceId: string; vendor: string; product: string; affectedVersion: string | null; fixedVersion: string | null; status: string; sourceProductId: string | null; sourceUrl: string; observedAt: string }>;
  remediations: Array<{ advisoryId: string; sourceId: string; observedAt: string; vendor: string; kind: string; patchAvailable: boolean | null; fixedVersion: string | null; action: string | null; rebootRequired: boolean | null; superseded: boolean | null; sourceUrl: string; publishedAt: string | null; updatedAt: string | null }>;
  exploitation: { knownExploited: boolean; zeroDay: boolean; evidence: Array<{ type: string; status: string; date: string | null; url: string; summary: string | null; source: string; sourceId: string; observedAt: string }> };
  kev: { active: boolean; dateAdded: string; dueDate: string | null; requiredAction: string | null; sourceUrl: string; sourceId: "cisa-kev"; observedAt: string } | null;
  epss: { current: { scoreDate: string; score: number; percentile: number; modelVersion: string | null; sourceId: "first-epss"; sourceUrl: string; observedAt: string } | null; history: Array<{ scoreDate: string; score: number; percentile: number; modelVersion: string | null; sourceId: "first-epss"; sourceUrl: string; observedAt: string }> };
  timeline: Array<{ observedAt: string; changeType: string; summary: string; sourceRunId: string }>;
  sourceLinks: Array<{ label: string; url: string }>;
}
