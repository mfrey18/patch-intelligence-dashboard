import type { NormalizedAdvisory } from "../../domain/types";
import type { AdvisoryRef, RawAdvisory, VendorAdapter } from "../contracts";
import { defaultDiscoveryStart } from "../operational-policy";
import { fetchWithPolicy, readJsonLimited, readTextLimited } from "../safety";
import { normalizeCsaf } from "./csaf";

const CSAF_ROOT = "https://api.msrc.microsoft.com/csaf";
const SUG_ROOT = "https://api.msrc.microsoft.com/sug/v2.0/en-US";
const DIRECTORIES = ["advisories", "vex"] as const;

export const microsoftAdapter: VendorAdapter = {
  vendor: "microsoft",
  sourceId: "microsoft-msrc-csaf",
  async discover(ctx) {
    const since = defaultDiscoveryStart(ctx.since);
    const until = ctx.until ? new Date(ctx.until) : null;
    const refs: AdvisoryRef[] = releaseNoteRefs(since, until ?? new Date());
    for (const directory of DIRECTORIES) {
      const response = await fetchWithPolicy(`${CSAF_ROOT}/${directory}/changes.csv`, { ...ctx.policy, maxResponseBytes: Math.min(ctx.policy.maxResponseBytes, 6_000_000) });
      const csv = await readTextLimited(response, 6_000_000);
      for (const rawLine of csv.split(/\r?\n/)) {
        if (!rawLine.trim()) continue;
        const match = /^"(\d{4}\/[^"/]+\.json)","([^"]+)"$/.exec(rawLine.trim());
        if (!match) throw new Error(`Microsoft CSAF changes index contains an invalid row: ${rawLine.slice(0, 120)}`);
        const [, relativePath, rawModified] = match;
        const modified = new Date(rawModified);
        if (Number.isNaN(modified.getTime())) throw new Error(`Microsoft CSAF changes index has an invalid timestamp for ${relativePath}`);
        if (modified < since || (until && modified > until)) continue;
        refs.push({ id: `${directory}:${relativePath.slice(0, -5)}`, url: `${CSAF_ROOT}/${directory}/${relativePath}`, sourceUpdatedAt: modified.toISOString(), metadata: { documentType: directory === "vex" ? "vex" : "advisory" } });
      }
    }
    return refs;
  },
  async fetch(ref, ctx) {
    const response = await fetchWithPolicy(ref.url, ctx.policy);
    return { ref, contentType: response.headers.get("content-type") ?? "application/json", body: await readJsonLimited(response, ctx.policy.maxResponseBytes), fetchedAt: new Date().toISOString(), resolvedUrl: response.url, etag: response.headers.get("etag") ?? undefined, lastModified: response.headers.get("last-modified") ?? undefined };
  },
  async normalize(raw, ctx) {
    if (raw.ref.metadata?.documentType === "release-note") return normalizeMicrosoftReleaseNote(raw, ctx.sanitizeText);
    if (raw.ref.metadata?.documentType === "release-membership") return normalizeMicrosoftReleaseMembership(raw, ctx.sanitizeText);
    return normalizeMicrosoftCsaf(raw, ctx.observedAt, ctx.sanitizeText);
  },
};

export function normalizeMicrosoftReleaseNote(raw: RawAdvisory, sanitize: (value: unknown) => string | undefined): NormalizedAdvisory[] {
  const body = raw.body && typeof raw.body === "object" ? raw.body as Record<string, unknown> : {};
  const releaseNumber = typeof body.releaseNumber === "string" ? body.releaseNumber : raw.ref.metadata?.releaseNumber;
  const releaseDate = typeof body.releaseDate === "string" ? new Date(body.releaseDate) : null;
  const title = sanitize(body.title) ?? `${releaseNumber ?? "Microsoft"} Security Updates`;
  const description = typeof body.description === "string" ? body.description : "";
  const countMatch = /This release consists of\s+(?:the following\s+)?([0-9,]+)\s+Microsoft CVEs/i.exec(description);
  const reportedCveCount = countMatch ? Number(countMatch[1].replaceAll(",", "")) : Number.NaN;
  if (!releaseNumber || !/^\d{4}-[A-Z][a-z]{2}$/.test(releaseNumber)) throw new Error("Microsoft release note is missing a valid release number");
  if (!releaseDate || Number.isNaN(releaseDate.getTime())) throw new Error(`Microsoft release note ${releaseNumber} is missing a valid release date`);
  if (!Number.isSafeInteger(reportedCveCount) || reportedCveCount < 0) throw new Error(`Microsoft release note ${releaseNumber} is missing its authoritative Microsoft CVE count`);
  const publishedAt = releaseDate.toISOString();
  const eventDate = publishedAt.slice(0, 10);
  const sourceUrl = `https://msrc.microsoft.com/update-guide/releaseNote/${releaseNumber}`;
  const reportedProductFamilies = parseReportedProductFamilies(description);
  return [{
    vendor: "microsoft", sourceId: "microsoft-msrc-csaf", vendorAdvisoryId: `release-note:${releaseNumber}`,
    title, summary: `${reportedCveCount} Microsoft CVEs reported for ${title}.`, sourceUrl, publishedAt,
    sourceUpdatedAt: publishedAt, exploitationStatus: "unknown", zeroDayStatus: "unknown",
    cves: [], affectedProducts: [], remediations: [], exploitEvidence: [],
    releaseEvent: { id: `microsoft-patch-tuesday-${eventDate.slice(0, 7)}`, eventType: "patch_tuesday", eventDate, label: `${new Intl.DateTimeFormat("en", { month: "long", year: "numeric", timeZone: "UTC" }).format(releaseDate)} Patch Tuesday`, sourceUrl, reportedCveCount, reportedAt: publishedAt, reportedProductFamilies },
  }];
}

export function normalizeMicrosoftCsaf(raw: RawAdvisory, _observedAt: string, sanitize: (value: unknown) => string | undefined): NormalizedAdvisory[] {
  // Microsoft VEX documents cover republished ecosystem/Linux vulnerabilities
  // and are not the authoritative membership list for the monthly Microsoft
  // Patch Tuesday total. Only MSRC advisory documents may join that event.
  const mayAssociateRelease = raw.ref.metadata?.documentType === "advisory";
  return normalizeCsaf(raw, sanitize, {
    vendor: "microsoft",
    sourceId: "microsoft-msrc-csaf",
    splitByCve: true,
    advisoryIdPrefix: raw.ref.metadata?.documentType ?? "advisory",
    releaseEvent: (publishedAt, sourceUrl) => mayAssociateRelease && isSecondTuesday(publishedAt) ? { id: `microsoft-patch-tuesday-${publishedAt.slice(0, 7)}`, eventType: "patch_tuesday", eventDate: publishedAt.slice(0, 10), label: `${new Intl.DateTimeFormat("en", { month: "long", year: "numeric", timeZone: "UTC" }).format(new Date(publishedAt))} Patch Tuesday`, sourceUrl } : undefined,
  });
}

// Backward-compatible parser export while downstream callers migrate to CSAF naming.
export const normalizeMicrosoftCvrf = normalizeMicrosoftCsaf;

function isSecondTuesday(value: string): boolean {
  const date = new Date(value);
  return date.getUTCDay() === 2 && date.getUTCDate() >= 8 && date.getUTCDate() <= 14;
}

export function normalizeMicrosoftReleaseMembership(raw: RawAdvisory, sanitize: (value: unknown) => string | undefined): NormalizedAdvisory[] {
  const releaseNumber = raw.ref.metadata?.releaseNumber;
  const eventDate = raw.ref.metadata?.eventDate;
  const body = raw.body && typeof raw.body === "object" ? raw.body as Record<string, unknown> : {};
  if (!releaseNumber || !/^\d{4}-[A-Z][a-z]{2}$/.test(releaseNumber)) throw new Error("Microsoft release membership is missing a valid release number");
  if (!eventDate || Number.isNaN(new Date(`${eventDate}T23:59:59.999Z`).getTime())) throw new Error(`Microsoft release membership ${releaseNumber} is missing a valid event date`);
  if (!Array.isArray(body.value)) throw new Error(`Microsoft release membership ${releaseNumber} is missing its vulnerability collection`);
  const eventCutoff = new Date(`${eventDate}T23:59:59.999Z`).getTime();
  const cves = uniqueBy(body.value.flatMap((entry) => {
    if (!entry || typeof entry !== "object") return [];
    const item = entry as Record<string, unknown>;
    const cveId = typeof item.cveNumber === "string" ? item.cveNumber.toUpperCase() : "";
    const publishedAt = typeof item.releaseDate === "string" ? new Date(item.releaseDate) : null;
    if (!/^CVE-\d{4}-\d{4,}$/.test(cveId) || item.releaseNumber !== releaseNumber || item.issuingCna !== "Microsoft" || !publishedAt || Number.isNaN(publishedAt.getTime()) || publishedAt.getTime() > eventCutoff) return [];
    return [{ cveId, description: sanitize(item.description), normalizedSeverity: "unknown" as const, publishedAt: publishedAt.toISOString() }];
  }), (item) => item.cveId);
  if (!cves.length) throw new Error(`Microsoft release membership ${releaseNumber} contains no authoritative Microsoft CVEs through ${eventDate}`);
  const sourceUrl = `https://msrc.microsoft.com/update-guide/releaseNote/${releaseNumber}`;
  const publishedAt = `${eventDate}T00:00:00.000Z`;
  return [{
    vendor: "microsoft", sourceId: "microsoft-msrc-csaf", vendorAdvisoryId: `release-membership:${releaseNumber}`,
    title: `${releaseNumber} authoritative Microsoft CVE membership`, summary: `${cves.length} Microsoft-issued CVEs linked to ${releaseNumber} through ${eventDate}.`, sourceUrl,
    publishedAt, sourceUpdatedAt: publishedAt, exploitationStatus: "unknown", zeroDayStatus: "unknown",
    cves, affectedProducts: [], remediations: [], exploitEvidence: [],
    releaseEvent: { id: `microsoft-patch-tuesday-${eventDate.slice(0, 7)}`, eventType: "patch_tuesday", eventDate, label: `${new Intl.DateTimeFormat("en", { month: "long", year: "numeric", timeZone: "UTC" }).format(new Date(publishedAt))} Patch Tuesday`, sourceUrl },
  }];
}

function parseReportedProductFamilies(description: string): Array<{ label: string; value: number }> {
  const releaseHeading = /This release consists of[\s\S]*?<\/h2>/i.exec(description);
  if (!releaseHeading) return [];
  const table = /<table[^>]*>([\s\S]*?)<\/table>/i.exec(description.slice(releaseHeading.index + releaseHeading[0].length))?.[1];
  if (!table) return [];
  const values: Array<{ label: string; value: number }> = [];
  for (const row of table.matchAll(/<tr[^>]*>([\s\S]*?)<\/tr>/gi)) {
    const cells = [...row[1].matchAll(/<td[^>]*>([\s\S]*?)<\/td>/gi)].map((cell) => stripHtml(cell[1]));
    const value = Number(cells[2]?.replaceAll(",", ""));
    if (cells[0] && Number.isSafeInteger(value) && value >= 0) values.push({ label: cells[0], value });
  }
  return values;
}

function stripHtml(value: string): string {
  return value.replace(/<[^>]+>/g, " ").replaceAll("&amp;", "&").replaceAll("&nbsp;", " ").replace(/\s+/g, " ").trim();
}

function releaseNoteRefs(since: Date, until: Date): AdvisoryRef[] {
  const refs: AdvisoryRef[] = [];
  for (let cursor = new Date(Date.UTC(since.getUTCFullYear(), since.getUTCMonth(), 1)); cursor <= until; cursor = new Date(Date.UTC(cursor.getUTCFullYear(), cursor.getUTCMonth() + 1, 1))) {
    const firstDay = cursor.getUTCDay();
    const eventDay = 1 + ((2 - firstDay + 7) % 7) + 7;
    const event = new Date(Date.UTC(cursor.getUTCFullYear(), cursor.getUTCMonth(), eventDay));
    if (event < new Date(Date.UTC(since.getUTCFullYear(), since.getUTCMonth(), since.getUTCDate())) || event > until) continue;
    const releaseNumber = `${event.getUTCFullYear()}-${new Intl.DateTimeFormat("en", { month: "short", timeZone: "UTC" }).format(event)}`;
    const eventDate = event.toISOString().slice(0, 10);
    refs.push({ id: `release-note:${releaseNumber}`, url: `${SUG_ROOT}/releaseNote/${releaseNumber}`, sourceUpdatedAt: event.toISOString(), metadata: { documentType: "release-note", releaseNumber } });
    const filter = encodeURIComponent(`releaseNumber eq '${releaseNumber}' and issuingCna eq 'Microsoft'`);
    refs.push({ id: `release-membership:${releaseNumber}`, url: `${SUG_ROOT}/vulnerability?$filter=${filter}&$top=1000`, sourceUpdatedAt: event.toISOString(), metadata: { documentType: "release-membership", releaseNumber, eventDate } });
  }
  return refs;
}

function uniqueBy<T>(values: T[], key: (value: T) => string): T[] {
  const seen = new Set<string>();
  return values.filter((value) => { const id = key(value); if (seen.has(id)) return false; seen.add(id); return true; });
}
