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
  rows: [],
  recentChanges: [],
  nextCursor: null,
  sourceHealth: [
    { sourceId: "microsoft-msrc-csaf", name: "Microsoft MSRC CSAF", lastAttempt: null, lastSuccess: null, durationMs: null, result: null, discovered: 0, inserted: 0, changed: 0, unchanged: 0, failed: 0, errorSummary: null },
    { sourceId: "cisco-psirt-csaf", name: "Cisco PSIRT CSAF", lastAttempt: null, lastSuccess: null, durationMs: null, result: null, discovered: 0, inserted: 0, changed: 0, unchanged: 0, failed: 0, errorSummary: null },
    { sourceId: "cisa-kev", name: "CISA KEV", lastAttempt: null, lastSuccess: null, durationMs: null, result: null, discovered: 0, inserted: 0, changed: 0, unchanged: 0, failed: 0, errorSummary: null },
    { sourceId: "first-epss", name: "FIRST EPSS", lastAttempt: null, lastSuccess: null, durationMs: null, result: null, discovered: 0, inserted: 0, changed: 0, unchanged: 0, failed: 0, errorSummary: null },
  ],
  latestReleaseEvent: null,
};
