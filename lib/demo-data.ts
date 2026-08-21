import type { DashboardResponse } from "./api/contracts";

/** Honest empty state used before the first successful ingestion. */
export const demoDashboard: DashboardResponse = {
  generatedAt: new Date().toISOString(),
  demo: true,
  metrics: { total: 0, critical: 0, high: 0, knownExploited: 0, kev: 0, zeroDay: 0, patchAvailable: 0 },
  changes: { since: null, newCves: 0, newCritical: 0, newlyKnownExploited: 0, newKev: 0, revisedAdvisories: 0, newRemediation: 0 },
  priorityDistribution: { P1: 0, P2: 0, P3: 0 },
  severitySeries: [{ label: "Critical", value: 0 }, { label: "High", value: 0 }, { label: "Medium", value: 0 }, { label: "Low", value: 0 }],
  vendorSeries: [],
  productSeries: [],
  vulnerabilityActivity: [],
  threatSignalActivity: [],
  epssMovers: [],
  emergingVulnerabilities: [],
  vendorThreatSeries: [],
  changeCategoryCounts: { threat: 0, assessment: 0, advisory: 0, remediation: 0 },
  cweAnalytics: { knownCoverage: 0, total: 0, series: [] },
  rows: [],
  recentChanges: [],
  nextCursor: null,
  sourceHealth: [
    ...["microsoft-msrc-csaf", "cisco-psirt-csaf", "cisa-kev", "first-epss"].map((sourceId, index) => ({ sourceId, name: ["Microsoft MSRC CSAF", "Cisco PSIRT CSAF", "CISA KEV", "FIRST EPSS"][index], lastAttempt: null, lastSuccess: null, lastFailure: null, durationMs: null, result: null, mode: null, freshness: "never" as const, discovered: 0, inserted: 0, changed: 0, unchanged: 0, failed: 0, boundHit: false, errorSummary: null, lease: { active: false, expiresAt: null }, checkpoint: null })),
  ],
  latestReleaseEvent: null,
};
