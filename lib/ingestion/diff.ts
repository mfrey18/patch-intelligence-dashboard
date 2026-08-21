import type { ChangeType, NormalizedAdvisory } from "../domain/types";
import { stableSerialize } from "./hash";

export function diffAdvisory(previous: NormalizedAdvisory | null, current: NormalizedAdvisory): ChangeType[] {
  if (!previous) return (["NEW_ADVISORY", ...current.cves.map(() => "NEW_CVE" as const)] as ChangeType[]).filter(unique);
  const changes: ChangeType[] = [];
  const previousCves = new Set(previous.cves.map((item) => item.cveId));
  if (current.cves.some((item) => !previousCves.has(item.cveId))) changes.push("NEW_CVE");
  if (previous.vendorSeverity !== current.vendorSeverity || perCveFieldChanged(previous, current, "vendorSeverity")) changes.push("SEVERITY_CHANGED");
  if (previous.cvssScore !== current.cvssScore || perCveFieldChanged(previous, current, "cvssScore") || perCveFieldChanged(previous, current, "cvssVector")) changes.push("CVSS_CHANGED");
  if (previous.exploitationStatus !== current.exploitationStatus || stableSerialize(previous.exploitEvidence) !== stableSerialize(current.exploitEvidence)) changes.push("EXPLOITATION_STATUS_CHANGED");

  const previousProducts = keyed(previous.affectedProducts, productKey);
  const currentProducts = keyed(current.affectedProducts, productKey);
  if ([...currentProducts.keys()].some((key) => !previousProducts.has(key))) changes.push("AFFECTED_PRODUCT_ADDED");
  if ([...previousProducts.keys()].some((key) => !currentProducts.has(key))) changes.push("AFFECTED_PRODUCT_REMOVED");

  if (fixedVersions(previous) !== fixedVersions(current)) changes.push("FIXED_VERSION_CHANGED");
  if (stableSerialize(previous.remediations) !== stableSerialize(current.remediations)) changes.push("REMEDIATION_CHANGED");
  if (!hasKind(previous, "mitigation") && hasKind(current, "mitigation")) changes.push("MITIGATION_ADDED");
  if (!hasKind(previous, "workaround") && hasKind(current, "workaround")) changes.push("WORKAROUND_ADDED");
  if (previous.sourceUpdatedAt !== current.sourceUpdatedAt) changes.push("SOURCE_MODIFIED");
  if (changes.length > 0) changes.unshift("ADVISORY_REVISED");
  return changes.filter(unique);
}

function perCveFieldChanged(previous: NormalizedAdvisory, current: NormalizedAdvisory, field: "vendorSeverity" | "cvssScore" | "cvssVector"): boolean {
  const oldValues = new Map(previous.cves.map((item) => [item.cveId, item[field]]));
  return current.cves.some((item) => oldValues.has(item.cveId) && oldValues.get(item.cveId) !== item[field]);
}
function productKey(value: NormalizedAdvisory["affectedProducts"][number]): string { return [value.cveId, value.sourceProductId, value.name, value.affectedVersion, value.status].join("|"); }
function keyed<T>(values: T[], key: (value: T) => string): Map<string, T> { return new Map(values.map((value) => [key(value), value])); }
function fixedVersions(value: NormalizedAdvisory): string { return stableSerialize(value.remediations.map((item) => item.fixedVersion).filter(Boolean).sort()); }
function hasKind(value: NormalizedAdvisory, kind: "mitigation" | "workaround"): boolean { return value.remediations.some((item) => item.kind === kind); }
function unique<T>(value: T, index: number, all: T[]): boolean { return all.indexOf(value) === index; }
