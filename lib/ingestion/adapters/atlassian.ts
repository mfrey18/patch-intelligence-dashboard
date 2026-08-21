import type { NormalizedAdvisory, NormalizedAffectedProduct, NormalizedRemediation } from "../../domain/types";
import type { AdvisoryRef, RawAdvisory, VendorAdapter } from "../contracts";
import { fetchWithPolicy, readJsonLimited } from "../safety";
import { firstString, iso, list, normalizeSeverity, numberValue, record, stringValue, uniqueBy, validCve } from "./utils";

const ATLASSIAN_API = "https://api.atlassian.com/vuln-transparency/v1";

export const atlassianAdapter: VendorAdapter = {
  vendor: "atlassian",
  sourceId: "atlassian-vulnerability-api",
  async discover(ctx) {
    const productResponse = await fetchWithPolicy(`${ATLASSIAN_API}/products`, ctx.policy, { headers: { accept: "application/json" } });
    const productPayload = await readJsonLimited(productResponse, ctx.policy.maxResponseBytes);
    const statuses = indexProductStatuses(productPayload);
    const refs: AdvisoryRef[] = [];
    let pageId: string | undefined;
    for (let page = 0; page < 100; page += 1) {
      const url = new URL(`${ATLASSIAN_API}/cves`);
      if (pageId) url.searchParams.set("page_id", pageId);
      const response = await fetchWithPolicy(url.toString(), ctx.policy, { headers: { accept: "application/json" } });
      const payload = record(await readJsonLimited(response, ctx.policy.maxResponseBytes));
      const rows = list(payload.resources);
      for (const value of rows) {
        const row = record(value);
        const cveId = validCve(row.cve_id);
        if (!cveId || !withinRange(row.cve_publish_date, ctx.since, ctx.until)) continue;
        refs.push({
          id: cveId,
          url: `${ATLASSIAN_API}/cves?cve_ids=${encodeURIComponent(cveId)}`,
          metadata: { cve: JSON.stringify(row), productStatuses: JSON.stringify(statuses.get(cveId) ?? []) },
        });
      }
      pageId = stringValue(payload.next_page_id);
      if (!pageId) return refs;
    }
    throw new Error("Atlassian discovery exceeded the 100-page safety envelope");
  },
  async fetch(ref, ctx) {
    const cached = ref.metadata?.cve;
    if (cached) {
      return { ref, contentType: "application/json", body: { cve: JSON.parse(cached), productStatuses: JSON.parse(ref.metadata?.productStatuses ?? "[]") }, fetchedAt: new Date().toISOString(), resolvedUrl: ref.url };
    }
    const response = await fetchWithPolicy(ref.url, ctx.policy, { headers: { accept: "application/json" } });
    const payload = record(await readJsonLimited(response, ctx.policy.maxResponseBytes));
    const cve = record(list(payload.resources)[0]);
    return { ref, contentType: response.headers.get("content-type") ?? "application/json", body: { cve, productStatuses: [] }, fetchedAt: new Date().toISOString(), resolvedUrl: response.url, etag: response.headers.get("etag") ?? undefined, lastModified: response.headers.get("last-modified") ?? undefined };
  },
  async normalize(raw, ctx) {
    return [normalizeAtlassianVulnerability(raw, ctx.sanitizeText)];
  },
};

export function normalizeAtlassianVulnerability(raw: RawAdvisory, sanitize: (value: unknown) => string | undefined): NormalizedAdvisory {
  const body = record(raw.body);
  const row = record(body.cve);
  const cveId = validCve(row.cve_id);
  if (!cveId) throw new Error(`Atlassian response for ${raw.ref.id} did not include a valid CVE ID`);
  const score = numberValue(row.cve_severity);
  const title = sanitize(row.cve_summary) ?? cveId;
  const sourceUrl = officialAtlassianUrl(row.advisory_url) ?? officialAtlassianUrl(row.atl_tracking_url) ?? raw.resolvedUrl;
  const publishedAt = iso(row.cve_publish_date);
  const productStatuses = list(body.productStatuses).map(record);
  const affectedProducts: NormalizedAffectedProduct[] = productStatuses.length
    ? productStatuses.map((item) => normalizeProductStatus(cveId, item)).filter(Boolean) as NormalizedAffectedProduct[]
    : list(row.affected_products).map(stringValue).filter(Boolean).map((name) => ({ cveId, name: name as string, status: "affected" }));
  const remediations: NormalizedRemediation[] = affectedProducts.filter((item) => item.status === "fixed" && item.fixedVersion).map((item) => ({
    cveId,
    productName: item.name,
    kind: "fixed_version",
    fixedVersion: item.fixedVersion,
    action: `Upgrade to ${item.name} ${item.fixedVersion}, which Atlassian explicitly marks FIXED.`,
    sourceUrl,
    publishedAt,
  }));

  return {
    vendor: "atlassian",
    sourceId: "atlassian-vulnerability-api",
    vendorAdvisoryId: cveId,
    title,
    summary: sanitize(row.cve_details) ?? title,
    sourceUrl,
    publishedAt,
    vendorSeverity: score == null ? undefined : String(score),
    cvssScore: score,
    exploitationStatus: "unknown",
    zeroDayStatus: "unknown",
    cves: [{ cveId, description: sanitize(row.cve_details) ?? title, vendorSeverity: score == null ? undefined : String(score), normalizedSeverity: normalizeSeverity(undefined, score), cvssScore: score, cvssVector: firstString(row.cve_vector), publishedAt }],
    affectedProducts: uniqueBy(affectedProducts, (item) => `${item.name}|${item.affectedVersion}|${item.fixedVersion}|${item.status}`),
    remediations: uniqueBy(remediations, (item) => `${item.productName}|${item.fixedVersion}`),
    exploitEvidence: [],
  };
}

function indexProductStatuses(payload: unknown): Map<string, Array<Record<string, string>>> {
  const result = new Map<string, Array<Record<string, string>>>();
  for (const [product, rawProduct] of Object.entries(record(record(payload).products))) {
    for (const [version, rawAssertions] of Object.entries(record(record(rawProduct).versions))) {
      for (const rawAssertion of list(rawAssertions)) {
        for (const [rawCve, rawStatus] of Object.entries(record(rawAssertion))) {
          const cveId = validCve(rawCve);
          const status = stringValue(rawStatus);
          if (!cveId || !status) continue;
          const rows = result.get(cveId) ?? [];
          rows.push({ product, version, status });
          result.set(cveId, rows);
        }
      }
    }
  }
  return result;
}

function normalizeProductStatus(cveId: string, item: Record<string, unknown>): NormalizedAffectedProduct | undefined {
  const name = firstString(item.product);
  const version = firstString(item.version);
  const rawStatus = (firstString(item.status) ?? "").toUpperCase();
  if (!name || !version) return undefined;
  if (rawStatus === "AFFECTED") return { cveId, name, affectedVersion: version, status: "affected" };
  if (rawStatus === "FIXED") return { cveId, name, fixedVersion: version, status: "fixed" };
  if (rawStatus === "NOT_AFFECTED" || rawStatus === "UNAFFECTED") return { cveId, name, affectedVersion: version, status: "unaffected" };
  return { cveId, name, affectedVersion: version, status: "unknown" };
}

function officialAtlassianUrl(value: unknown): string | undefined {
  const raw = stringValue(value);
  if (!raw) return undefined;
  try {
    const url = new URL(raw);
    return url.protocol === "https:" && (url.hostname === "atlassian.com" || url.hostname.endsWith(".atlassian.com")) ? url.toString() : undefined;
  } catch { return undefined; }
}

function withinRange(value: unknown, since?: string, until?: string): boolean {
  const timestamp = iso(value);
  if (!timestamp) return true;
  const time = new Date(timestamp).getTime();
  return (!since || time >= new Date(since).getTime()) && (!until || time <= new Date(until).getTime());
}
