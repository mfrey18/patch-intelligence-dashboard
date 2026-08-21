import type { NormalizedSeverity } from "../../domain/types";

export function record(value: unknown): Record<string, unknown> { return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {}; }
export function list(value: unknown): unknown[] { return Array.isArray(value) ? value : value == null ? [] : [value]; }
export function stringValue(value: unknown): string | undefined {
  if (typeof value === "string") return value;
  const object = record(value);
  return typeof object.Value === "string" ? object.Value : typeof object.value === "string" ? object.value : undefined;
}
export function numberValue(value: unknown): number | undefined { const parsed = typeof value === "number" ? value : Number(value); return Number.isFinite(parsed) ? parsed : undefined; }
export function path(value: unknown, ...keys: string[]): unknown { let current = value; for (const key of keys) current = record(current)[key]; return current; }
export function firstString(...values: unknown[]): string | undefined { for (const value of values) { const string = stringValue(value); if (string) return string; } return undefined; }
export function iso(value: unknown): string | undefined { const text = stringValue(value); if (!text) return undefined; const date = new Date(text); return Number.isNaN(date.getTime()) ? undefined : date.toISOString(); }
export function normalizeSeverity(value: unknown, cvss?: number): NormalizedSeverity {
  const severity = (stringValue(value) ?? "").toLowerCase();
  if (severity.includes("critical")) return "critical";
  if (severity.includes("important") || severity.includes("high")) return "high";
  if (severity.includes("moderate") || severity.includes("medium")) return "medium";
  if (severity.includes("low")) return "low";
  if (cvss != null) return cvss >= 9 ? "critical" : cvss >= 7 ? "high" : cvss >= 4 ? "medium" : "low";
  return "unknown";
}
export function validCve(value: unknown): string | undefined { const cve = stringValue(value)?.toUpperCase(); return cve && /^CVE-\d{4}-\d{4,}$/.test(cve) ? cve : undefined; }
export function uniqueBy<T>(values: T[], key: (item: T) => string): T[] { return [...new Map(values.map((value) => [key(value), value])).values()]; }
