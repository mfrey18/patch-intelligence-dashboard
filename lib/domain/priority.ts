import type { ExploitationStatus, NormalizedSeverity, PriorityResult } from "./types";

export const PRIORITY_THRESHOLDS = Object.freeze({
  criticalHighEpssPercentile: 0.70,
  highVeryHighEpssPercentile: 0.90,
});

export interface PriorityInput {
  kev: boolean;
  exploitationStatus: ExploitationStatus;
  severity: NormalizedSeverity;
  cvss?: number | null;
  epssPercentile?: number | null;
}

export function calculatePriority(input: PriorityInput): PriorityResult {
  const reasons: string[] = [];
  if (input.exploitationStatus === "known_exploited") reasons.push("Known exploited");
  if (input.kev) reasons.push("CISA KEV");

  let level: PriorityResult["level"] = "P3";
  if (input.kev || input.exploitationStatus === "known_exploited") {
    level = "P1";
  } else if (
    (input.severity === "critical" && (input.epssPercentile ?? 0) >= PRIORITY_THRESHOLDS.criticalHighEpssPercentile) ||
    (input.severity === "high" && (input.epssPercentile ?? 0) >= PRIORITY_THRESHOLDS.highVeryHighEpssPercentile)
  ) {
    level = "P2";
  }

  if (input.severity !== "unknown") reasons.push(`${capitalize(input.severity)} severity`);
  if (input.cvss != null) reasons.push(`CVSS ${input.cvss.toFixed(1)}`);
  if (input.epssPercentile != null) reasons.push(`EPSS ${ordinalPercentile(input.epssPercentile)}`);
  if (reasons.length === 0) reasons.push("Routine vendor advisory");
  return {
    level,
    reasons,
    components: {
      kev: input.kev,
      exploitationStatus: input.exploitationStatus,
      severity: input.severity,
      cvss: input.cvss ?? null,
      epssPercentile: input.epssPercentile ?? null,
    },
  };
}

function capitalize(value: string): string { return `${value[0]?.toUpperCase() ?? ""}${value.slice(1)}`; }

function ordinalPercentile(fraction: number): string {
  const value = Math.max(0, Math.min(100, Math.round(fraction * 100)));
  const suffix = value % 10 === 1 && value % 100 !== 11 ? "st" : value % 10 === 2 && value % 100 !== 12 ? "nd" : value % 10 === 3 && value % 100 !== 13 ? "rd" : "th";
  return `${value}${suffix} percentile`;
}
