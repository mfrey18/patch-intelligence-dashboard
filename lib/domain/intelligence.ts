import { PRIORITY_THRESHOLDS } from "./priority";
import type { ChangeType, NormalizedSeverity } from "./types";

/** Predictive enrichment threshold used by analytics; it never implies exploitation. */
export const HIGH_EPSS_PERCENTILE = PRIORITY_THRESHOLDS.highVeryHighEpssPercentile;
export const EPSS_MOVER_LOOKBACK_DAYS = 7;
export const EPSS_MOVER_DATE_TOLERANCE_DAYS = 1;
export const MIN_EPSS_PERCENTILE_DELTA = 0.05;
export const EMERGING_CHANGE_WINDOW_DAYS = 14;

export type IntelligenceChangeCategory = "threat" | "assessment" | "advisory" | "remediation";

const THREAT_CHANGES = new Set<string>(["EXPLOITATION_STATUS_CHANGED", "ZERO_DAY_STATUS_CHANGED", "KEV_ADDED", "KEV_REMOVED", "KEV_DEADLINE_CHANGED", "KEV_ENTRY_MODIFIED"]);
const ASSESSMENT_CHANGES = new Set<string>(["SEVERITY_CHANGED", "CVSS_CHANGED"]);
const REMEDIATION_CHANGES = new Set<string>(["FIXED_VERSION_CHANGED", "REMEDIATION_CHANGED", "MITIGATION_ADDED", "WORKAROUND_ADDED"]);

export function intelligenceChangeCategory(changeType: string): IntelligenceChangeCategory {
  if (THREAT_CHANGES.has(changeType)) return "threat";
  if (ASSESSMENT_CHANGES.has(changeType)) return "assessment";
  if (REMEDIATION_CHANGES.has(changeType)) return "remediation";
  return "advisory";
}

export interface EmergingReasonInput {
  knownExploited: boolean;
  kev: boolean;
  zeroDay: boolean;
  severity: NormalizedSeverity;
  epssPercentile: number | null;
  epssPercentileDelta?: number | null;
  recentChangeTypes: string[];
}

export function emergingReasons(input: EmergingReasonInput): string[] {
  const changes = new Set(input.recentChangeTypes);
  const reasons: string[] = [];
  if (input.knownExploited && changes.has("EXPLOITATION_STATUS_CHANGED")) reasons.push("New authoritative exploitation evidence");
  if (input.kev && changes.has("KEV_ADDED")) reasons.push("New CISA KEV entry");
  if (input.zeroDay && changes.has("ZERO_DAY_STATUS_CHANGED")) reasons.push("New authoritative zero-day evidence");
  if (changes.has("SEVERITY_CHANGED")) reasons.push("Material severity assessment changed");
  if (input.severity === "critical" && (input.epssPercentile ?? 0) >= HIGH_EPSS_PERCENTILE) reasons.push(`Critical with EPSS at or above the ${Math.round(HIGH_EPSS_PERCENTILE * 100)}th percentile`);
  if (input.severity === "high" && (input.epssPercentile ?? 0) >= PRIORITY_THRESHOLDS.highVeryHighEpssPercentile) reasons.push(`High severity with EPSS at or above the ${Math.round(PRIORITY_THRESHOLDS.highVeryHighEpssPercentile * 100)}th percentile`);
  if ((input.epssPercentileDelta ?? 0) >= MIN_EPSS_PERCENTILE_DELTA) reasons.push(`EPSS percentile increased ${Math.round((input.epssPercentileDelta ?? 0) * 100)} points`);
  return [...new Set(reasons)];
}

export function isMaterialEmergingChange(changeType: string): changeType is ChangeType {
  return THREAT_CHANGES.has(changeType) || ASSESSMENT_CHANGES.has(changeType);
}
