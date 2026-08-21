import type { NormalizedAdvisory, NormalizedAffectedProduct, NormalizedRemediation } from "../../domain/types";
import type { AdvisoryRef, RawAdvisory, VendorAdapter } from "../contracts";
import { defaultDiscoveryStart } from "../operational-policy";
import { fetchWithPolicy, readJsonLimited, readTextLimited } from "../safety";
import { iso, normalizeSeverity, uniqueBy, validCve } from "./utils";

const REPOSITORY_ROOT = "https://api.github.com/repos/mozilla/foundation-security-advisories/contents/announce";
const RAW_HOST = "raw.githubusercontent.com";

interface GithubContentEntry {
  name?: unknown;
  path?: unknown;
  sha?: unknown;
  download_url?: unknown;
  type?: unknown;
}

interface ParsedMozillaCve {
  cveId: string;
  title?: string;
  impact?: string;
  description?: string;
}

export interface ParsedMozillaMfsa {
  announcedAt: string;
  impact?: string;
  fixedIn: string[];
  title: string;
  description?: string;
  cves: ParsedMozillaCve[];
}

export const mozillaAdapter: VendorAdapter = {
  vendor: "mozilla",
  sourceId: "mozilla-mfsa-yaml",
  async discover(ctx) {
    const start = validDate(ctx.since) ?? defaultDiscoveryStart();
    const end = validDate(ctx.until) ?? new Date();
    const refs = new Map<string, AdvisoryRef>();

    for (let year = start.getUTCFullYear(); year <= end.getUTCFullYear(); year += 1) {
      const response = await fetchWithPolicy(`${REPOSITORY_ROOT}/${year}`, ctx.policy, {
        headers: { accept: "application/vnd.github+json", "user-agent": "Patch-Intelligence-Dashboard" },
      }, [404]);
      if (response.status === 404) continue;
      const payload = await readJsonLimited(response, ctx.policy.maxResponseBytes);
      if (!Array.isArray(payload)) throw new Error(`Mozilla advisory index for ${year} is not an array`);

      for (const value of payload as GithubContentEntry[]) {
        if (value.type !== "file" || typeof value.name !== "string" || typeof value.download_url !== "string") continue;
        const match = /^(mfsa\d{4}-\d+)\.ya?ml$/i.exec(value.name);
        if (!match) continue;
        const url = new URL(value.download_url);
        if (url.protocol !== "https:" || url.hostname !== RAW_HOST) continue;
        const id = match[1].toLowerCase();
        refs.set(id, {
          id,
          url: url.toString(),
          metadata: {
            repositoryPath: typeof value.path === "string" ? value.path : `announce/${year}/${value.name}`,
            repositorySha: typeof value.sha === "string" ? value.sha : "",
            publicationUrl: `https://www.mozilla.org/security/advisories/${id}/`,
          },
        });
      }
    }

    return [...refs.values()].sort((left, right) => left.id.localeCompare(right.id));
  },
  async fetch(ref, ctx) {
    const url = new URL(ref.url);
    if (url.protocol !== "https:" || url.hostname !== RAW_HOST) throw new Error("Mozilla advisory URL is outside the official repository host");
    const response = await fetchWithPolicy(url.toString(), ctx.policy, { headers: { accept: "text/yaml, text/plain" } });
    return {
      ref,
      contentType: response.headers.get("content-type") ?? "text/yaml",
      body: await readTextLimited(response, ctx.policy.maxResponseBytes),
      fetchedAt: new Date().toISOString(),
      resolvedUrl: response.url,
      etag: response.headers.get("etag") ?? undefined,
      lastModified: response.headers.get("last-modified") ?? undefined,
    };
  },
  async normalize(raw, ctx) {
    return [normalizeMozillaMfsa(raw, ctx.sanitizeText)];
  },
};

export function normalizeMozillaMfsa(raw: RawAdvisory, sanitize: (value: unknown) => string | undefined): NormalizedAdvisory {
  if (typeof raw.body !== "string") throw new Error("Mozilla MFSA payload must be YAML text");
  const parsed = parseMozillaMfsaYaml(raw.body);
  const sourceUrl = raw.ref.metadata?.publicationUrl ?? `https://www.mozilla.org/security/advisories/${raw.ref.id.toLowerCase()}/`;
  const releases = parsed.fixedIn.map(parseFixedRelease);
  const cves = parsed.cves.map((item) => ({
    cveId: item.cveId,
    description: sanitize(item.description ?? item.title),
    vendorSeverity: item.impact,
    normalizedSeverity: normalizeSeverity(item.impact),
    publishedAt: parsed.announcedAt,
    modifiedAt: iso(raw.lastModified ?? raw.ref.sourceUpdatedAt),
  }));
  const affectedProducts: NormalizedAffectedProduct[] = [];
  const remediations: NormalizedRemediation[] = [];

  for (const cve of cves) {
    for (const release of releases) {
      affectedProducts.push({
        cveId: cve.cveId,
        sourceProductId: release.raw,
        name: release.product,
        fixedVersion: release.version,
        status: "fixed",
      });
      remediations.push({
        cveId: cve.cveId,
        productName: release.product,
        kind: "fixed_version",
        fixedVersion: release.version,
        action: `Update to ${release.raw}`,
        sourceUrl,
        publishedAt: parsed.announcedAt,
        updatedAt: iso(raw.lastModified ?? raw.ref.sourceUpdatedAt),
      });
    }
  }

  const highest = [...cves].sort((left, right) => severityRank(right.normalizedSeverity) - severityRank(left.normalizedSeverity))[0];
  return {
    vendor: "mozilla",
    sourceId: "mozilla-mfsa-yaml",
    vendorAdvisoryId: raw.ref.id.toLowerCase(),
    title: sanitize(parsed.title) ?? raw.ref.id,
    summary: sanitize(parsed.description),
    sourceUrl,
    publishedAt: parsed.announcedAt,
    sourceUpdatedAt: iso(raw.lastModified ?? raw.ref.sourceUpdatedAt),
    vendorSeverity: parsed.impact ?? highest?.vendorSeverity,
    exploitationStatus: "unknown",
    zeroDayStatus: "unknown",
    cves,
    affectedProducts: uniqueBy(affectedProducts, (item) => `${item.cveId}|${item.sourceProductId}|${item.status}`),
    remediations: uniqueBy(remediations, (item) => `${item.cveId}|${item.productName}|${item.fixedVersion}`),
    exploitEvidence: [],
    releaseEvent: {
      id: `mozilla-security-release-${parsed.announcedAt.slice(0, 10)}`,
      eventType: "security_release",
      eventDate: parsed.announcedAt.slice(0, 10),
      label: `Mozilla security release — ${parsed.announcedAt.slice(0, 10)}`,
      sourceUrl,
    },
  };
}

/**
 * Parses the deliberately small, documented MFSA YAML shape. Unknown fields are
 * ignored and unsupported/missing required structures fail closed instead of
 * silently inventing advisory semantics.
 */
export function parseMozillaMfsaYaml(source: string): ParsedMozillaMfsa {
  const lines = source.replace(/^\uFEFF/, "").replace(/\r\n?/g, "\n").split("\n");
  let announcedAt: string | undefined;
  let impact: string | undefined;
  let title: string | undefined;
  let description: string | undefined;
  const fixedIn: string[] = [];
  const cves: ParsedMozillaCve[] = [];
  let inAdvisories = false;
  let current: ParsedMozillaCve | undefined;

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (!inAdvisories) {
      const field = /^(announced|impact|title|description|fixed_in):(?:\s*(.*))?$/.exec(line);
      if (field) {
        const [, key, rawValue = ""] = field;
        if (key === "announced") announcedAt = parseAnnouncementDate(parseScalar(rawValue));
        else if (key === "impact") impact = parseScalar(rawValue).toLowerCase();
        else if (key === "title") title = parseScalar(rawValue);
        else if (key === "description") {
          const block = readBlock(lines, index, 2, rawValue);
          description = block.value;
          index = block.endIndex;
        } else if (key === "fixed_in") {
          const inline = parseInlineList(rawValue);
          fixedIn.push(...inline);
          while (/^-\s+/.test(lines[index + 1] ?? "")) {
            index += 1;
            fixedIn.push(parseScalar(lines[index].replace(/^-\s+/, "")));
          }
        }
        continue;
      }
      if (/^advisories:\s*$/.test(line)) inAdvisories = true;
      continue;
    }

    const cveMatch = /^ {2}(CVE-\d{4}-\d{4,}):\s*$/i.exec(line);
    if (cveMatch) {
      const cveId = validCve(cveMatch[1]);
      if (!cveId) throw new Error(`Mozilla MFSA contains invalid CVE ID ${cveMatch[1]}`);
      current = { cveId };
      cves.push(current);
      continue;
    }
    if (!current) continue;
    const property = /^ {4}(title|impact|description):(?:\s*(.*))?$/.exec(line);
    if (!property) continue;
    const [, key, rawValue = ""] = property;
    if (key === "title") current.title = parseScalar(rawValue);
    else if (key === "impact") current.impact = parseScalar(rawValue).toLowerCase();
    else {
      const block = readBlock(lines, index, 6, rawValue);
      current.description = block.value;
      index = block.endIndex;
    }
  }

  if (!announcedAt) throw new Error("Mozilla MFSA is missing a valid announced date");
  if (!title) throw new Error("Mozilla MFSA is missing a title");
  if (fixedIn.length === 0) throw new Error("Mozilla MFSA is missing fixed_in releases");
  if (cves.length === 0) throw new Error("Mozilla MFSA does not contain any CVE advisories");
  return { announcedAt, impact, fixedIn: uniqueBy(fixedIn.filter(Boolean), (value) => value), title, description, cves: uniqueBy(cves, (value) => value.cveId) };
}

function readBlock(lines: string[], index: number, indentation: number, marker: string): { value?: string; endIndex: number } {
  if (!/^[|>][-+]?\s*$/.test(marker)) return { value: parseScalar(marker) || undefined, endIndex: index };
  const values: string[] = [];
  let cursor = index + 1;
  for (; cursor < lines.length; cursor += 1) {
    const line = lines[cursor];
    if (!line.trim()) { values.push(""); continue; }
    const leading = /^\s*/.exec(line)?.[0].length ?? 0;
    if (leading < indentation) break;
    values.push(line.slice(indentation));
  }
  const separator = marker.startsWith(">") ? " " : "\n";
  return { value: values.join(separator).replace(/\s+$/, "") || undefined, endIndex: cursor - 1 };
}

function parseScalar(value: string): string {
  const trimmed = value.trim();
  if (trimmed.startsWith("'") && trimmed.endsWith("'")) return trimmed.slice(1, -1).replace(/''/g, "'");
  if (trimmed.startsWith('"') && trimmed.endsWith('"')) {
    try { return JSON.parse(trimmed) as string; } catch { throw new Error("Mozilla MFSA contains an invalid quoted scalar"); }
  }
  return trimmed.replace(/\s+#.*$/, "");
}

function parseInlineList(value: string): string[] {
  const trimmed = value.trim();
  if (!trimmed) return [];
  if (!trimmed.startsWith("[") || !trimmed.endsWith("]")) throw new Error("Mozilla MFSA fixed_in must be a YAML list");
  return trimmed.slice(1, -1).split(",").map(parseScalar).filter(Boolean);
}

function parseAnnouncementDate(value: string): string | undefined {
  const isoMatch = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
  if (isoMatch) return makeUtcDate(Number(isoMatch[1]), Number(isoMatch[2]), Number(isoMatch[3]));
  const match = /^([A-Za-z]+)\s+(\d{1,2}),\s+(\d{4})$/.exec(value);
  if (!match) return undefined;
  const month = ["january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december"].indexOf(match[1].toLowerCase()) + 1;
  return month ? makeUtcDate(Number(match[3]), month, Number(match[2])) : undefined;
}

function makeUtcDate(year: number, month: number, day: number): string | undefined {
  const date = new Date(Date.UTC(year, month - 1, day));
  if (date.getUTCFullYear() !== year || date.getUTCMonth() !== month - 1 || date.getUTCDate() !== day) return undefined;
  return date.toISOString();
}

function parseFixedRelease(raw: string): { raw: string; product: string; version?: string } {
  const match = /^(.*?)\s+((?:\d+[A-Za-z0-9]*)(?:[.-][A-Za-z0-9]+)*)$/.exec(raw.trim());
  return match ? { raw: raw.trim(), product: match[1].trim(), version: match[2] } : { raw: raw.trim(), product: raw.trim() };
}

function severityRank(value: string): number {
  return value === "critical" ? 4 : value === "high" ? 3 : value === "medium" ? 2 : value === "low" ? 1 : 0;
}

function validDate(value?: string): Date | undefined {
  if (!value) return undefined;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? undefined : date;
}
