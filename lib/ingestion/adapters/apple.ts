import type { NormalizedAdvisory, NormalizedAffectedProduct, NormalizedExploitEvidence, NormalizedRemediation } from "../../domain/types";
import type { AdvisoryRef, RawAdvisory, VendorAdapter } from "../contracts";
import { normalizeCsaf } from "./csaf";
import { createConfiguredCsafAdapter } from "./configured-csaf";
import { absoluteOfficialUrl, cveIds, explicitDate, fetchOfficialHtml, inWindow, links, loadHtml, read, severityFromText } from "./html";

const DEFAULT_INDEX_URL = "https://support.apple.com/en-us/100100";
const APPLE_HOSTS = ["apple.com"];

export interface AppleAdapterOptions {
  /** Explicit Apple-hosted CSAF JSON documents remain supported as an override. */
  csafUrls?: string[];
  bearerToken?: string;
  indexUrl?: string;
}

export function createAppleAdapter(options: AppleAdapterOptions = {}): VendorAdapter {
  if (options.csafUrls?.length) return createConfiguredCsafAdapter({ vendor: "apple", sourceId: "apple-configured-csaf", urls: options.csafUrls, bearerToken: options.bearerToken, allowedHosts: APPLE_HOSTS, missingConfigurationMessage: "Apple requires an official CSAF URL" });
  return createAppleHtmlAdapter(options.indexUrl ?? DEFAULT_INDEX_URL);
}

function createAppleHtmlAdapter(indexUrl: string): VendorAdapter {
  const page = async (ctx: Parameters<VendorAdapter["discover"]>[0], cursor?: string) => {
    const fetched = await fetchOfficialHtml(cursor ?? indexUrl, ctx, APPLE_HOSTS);
    const document = loadHtml(fetched.html);
    const refs = appleRefs(document, fetched.url, ctx.since, ctx.until);
    const coverageRefs = appleRefs(document, fetched.url, undefined, ctx.until);
    if (!refs.length && !cursor) throw new Error("Apple official HTML index contains no identifiable security advisories");
    const next = links(document).find((link) => /next|older/i.test(link.text) || /(?:[?&]page=|\/page\/)/i.test(link.href));
    const nextUrl = next ? absoluteOfficialUrl(fetched.url, next.href, APPLE_HOSTS) : undefined;
    const oldest = coverageRefs.map((ref) => ref.sourceUpdatedAt).filter(Boolean).sort()[0];
    if (ctx.since && !nextUrl && (!oldest || Date.parse(oldest) > Date.parse(ctx.since))) throw new Error("Apple official index did not establish the requested historical boundary");
    return { refs, nextCursor: nextUrl && nextUrl !== fetched.url ? nextUrl : null, coverageOldest: oldest };
  };
  return {
    vendor: "apple",
    sourceId: "apple-configured-csaf",
    ...(indexUrl === DEFAULT_INDEX_URL ? { historicalCoverage: "complete_index" as const } : {}),
    async discover(ctx) {
      const refs: AdvisoryRef[] = [];
      const seen = new Set<string>();
      const seenPages = new Set<string>();
      let cursor: string | undefined;
      let pages = 0;
      let coverageOldest: string | undefined;
      do {
        if (++pages > 200) throw new Error("Apple official pagination exceeded the bounded page limit");
        if (cursor && seenPages.has(cursor)) throw new Error("Apple official pagination repeated a page cursor");
        if (cursor) seenPages.add(cursor);
        const current = await page(ctx, cursor);
        if (current.coverageOldest && (!coverageOldest || Date.parse(current.coverageOldest) < Date.parse(coverageOldest))) coverageOldest = current.coverageOldest;
        for (const ref of current.refs) if (!seen.has(ref.id)) { seen.add(ref.id); refs.push(ref); }
        cursor = current.nextCursor ?? undefined;
      } while (cursor);
      if (ctx.since && (!coverageOldest || Date.parse(coverageOldest) > Date.parse(ctx.since))) throw new Error("Apple official discovery did not establish the requested historical boundary");
      return refs;
    },
    async discoverPage(ctx, cursor) { return page(ctx, cursor); },
    async fetch(ref, ctx) {
      const fetched = await fetchOfficialHtml(ref.url, ctx, APPLE_HOSTS);
      return { ref, contentType: "text/html", body: fetched.html, fetchedAt: fetched.fetchedAt, resolvedUrl: fetched.url, etag: fetched.etag, lastModified: fetched.lastModified };
    },
    async normalize(raw, ctx) { return [normalizeAppleHtml(raw, ctx.sanitizeText)]; },
  };
}

function appleRefs(document: ReturnType<typeof loadHtml>, baseUrl: string, since?: string, until?: string): AdvisoryRef[] {
  const refs = new Map<string, AdvisoryRef>();
  // Apple labels rows by product/version (for example "iOS 26.6"), not by
  // the word security. Scope discovery to the table under the security-updates
  // heading and take the release date from the same row.
  const heading = document("h2").filter((_index, node) => /apple security updates/i.test(document(node).text())).first();
  const table = heading.length ? heading.nextAll(".table-wrapper, table").first().find("table").add(heading.nextAll("table").first()) : document("table").first();
  table.find("tr").each((_index, row) => {
    const rowNode = document(row);
    const link = rowNode.find("a[href]").first();
    const href = link.attr("href");
    if (!href) return;
    const url = absoluteOfficialUrl(baseUrl, href, APPLE_HOSTS);
    if (!url) return;
    const id = appleId(url, link.text());
    if (!id) return;
    const cells = rowNode.find("th,td").toArray().map((cell) => document(cell).text().replace(/\s+/g, " ").trim());
    const sourceUpdatedAt = explicitDate(cells.at(-1));
    if (sourceUpdatedAt && !inWindow(sourceUpdatedAt, since, until)) return;
    refs.set(id, { id, url, sourceUpdatedAt, metadata: { productRelease: cells[0] ?? "", availableFor: cells[1] ?? "" } });
  });
  return [...refs.values()];
}

function appleId(url: string, label: string): string | undefined {
  const explicit = label.match(/\b(?:HT|SA|APPLE)[-_]?\d{3,}\b/i)?.[0].toUpperCase();
  if (explicit) return explicit;
  try {
    const numeric = new URL(url).pathname.match(/\/(\d{5,})(?:\/)?$/)?.[1];
    return numeric ? `APPLE-${numeric}` : undefined;
  } catch { return undefined; }
}

export const appleAdapter = createAppleAdapter();

export function normalizeAppleCsaf(raw: RawAdvisory, sanitize: (value: unknown) => string | undefined): NormalizedAdvisory {
  return normalizeCsaf(raw, sanitize, { vendor: "apple", sourceId: "apple-configured-csaf" })[0];
}

export function normalizeAppleHtml(raw: RawAdvisory, sanitize: (value: unknown) => string | undefined): NormalizedAdvisory {
  const document = loadHtml(String(raw.body));
  const content = document("[itemprop='articleBody'], main, .gb-content").first();
  const bodyText = sanitize((content.length ? content : document("body")).text()) ?? "";
  const title = sanitize(read(document, "h1") ?? read(document, "title") ?? raw.ref.id) ?? raw.ref.id;
  const publishedAt = explicitDate(read(document, "time", "datetime") ?? read(document, "time") ?? raw.ref.sourceUpdatedAt);
  const scopes = appleCveScopes(document);
  const cves = [...scopes.keys()];
  const severityText = bodyText.match(/\bseverity\s*[:-]\s*(critical|high|medium|low)\b/i)?.[1];
  const evidenceDate = publishedAt ?? raw.ref.sourceUpdatedAt;
  const exploitEvidence: NormalizedExploitEvidence[] = [];
  const affectedProducts: NormalizedAffectedProduct[] = [];
  const remediations: NormalizedRemediation[] = [];
  const release = appleReleaseTitle(title);
  for (const [cveId, scope] of scopes) {
    const explicitlyNotKnown = /(?:no evidence|not aware|no known)\s+(?:of\s+)?(?:active\s+)?exploitation/i.test(scope);
    const known = !explicitlyNotKnown && /(?:actively exploited|exploitation (?:has been )?(?:observed|confirmed)|exploited in the wild)/i.test(scope);
    const zeroDayConfirmed = /(?:zero[- ]day[^.]{0,120}(?:confirmed|actively exploited|exploited)|(?:confirmed|actively exploited|exploited)[^.]{0,120}zero[- ]day)/i.test(scope);
    const zeroDayNegative = /(?:not a zero[- ]day|no evidence[^.]{0,120}zero[- ]day)/i.test(scope);
    if (known || explicitlyNotKnown) exploitEvidence.push({ cveId, type: "known_exploitation", status: known ? "confirmed" : "not_confirmed", evidenceDate, evidenceUrl: raw.resolvedUrl });
    if (zeroDayConfirmed || zeroDayNegative) exploitEvidence.push({ cveId, type: "zero_day", status: zeroDayConfirmed ? "confirmed" : "not_confirmed", evidenceDate, evidenceUrl: raw.resolvedUrl });
    const component = scope.match(/\bcomponent:\s*([^—]+)/i)?.[1]?.trim() ?? scope.match(/^([^—]+)\s+—/)?.[1]?.trim();
    const availableFor = scope.match(/Available for:\s*(.*?)(?=\s+(?:Impact|Description|CVE-|$))/i)?.[1]?.replace(/\s+—\s*$/, "").trim();
    const fixed = scope.match(/(?:fixed|available in|patched in)\s+(?:version\s+)?([\w.-]+)/i)?.[1] ?? release?.product;
    if (release) {
      affectedProducts.push({ cveId, name: release.product, ...(component ? { family: component } : {}), ...(availableFor ? { affectedVersion: availableFor } : {}), status: "affected", ...(fixed ? { fixedVersion: fixed } : {}) });
      if (fixed) remediations.push({ cveId, productName: release.product, kind: "fixed_version", fixedVersion: fixed, patchAvailable: true, sourceUrl: raw.resolvedUrl, publishedAt, updatedAt: publishedAt });
    }
  }
  const known = exploitEvidence.some((item) => item.status === "confirmed" && item.type === "known_exploitation");
  const explicitlyNotKnown = exploitEvidence.some((item) => item.status === "not_confirmed" && item.type === "known_exploitation");
  const zeroDay = exploitEvidence.some((item) => item.type === "zero_day" && item.status === "confirmed");
  const zeroDayNegative = exploitEvidence.some((item) => item.type === "zero_day" && item.status === "not_confirmed");
  return {
    vendor: "apple", sourceId: "apple-configured-csaf", vendorAdvisoryId: raw.ref.id, title, summary: bodyText.slice(0, 1_000) || undefined, sourceUrl: raw.resolvedUrl, publishedAt, sourceUpdatedAt: raw.ref.sourceUpdatedAt ?? publishedAt, vendorSeverity: severityText,
    cves: cves.map((cveId) => {
      const scopedSeverity = scopes.get(cveId)?.match(/\b(critical|high|medium|moderate|low)\b/i)?.[1];
      return { cveId, description: bodyText.slice(0, 1_000) || undefined, vendorSeverity: scopedSeverity ?? severityText, normalizedSeverity: severityFromText(scopedSeverity ?? severityText ?? ""), publishedAt, modifiedAt: raw.ref.sourceUpdatedAt ?? publishedAt };
    }), affectedProducts, remediations,
    exploitationStatus: known ? "known_exploited" : explicitlyNotKnown ? "not_known_exploited" : "unknown", zeroDayStatus: zeroDay ? "confirmed" : zeroDayNegative ? "not_confirmed" : "unknown", exploitEvidence,
    releaseEvent: publishedAt ? { id: `apple-security-release-${publishedAt.slice(0, 10)}`, eventType: "security_release", eventDate: publishedAt.slice(0, 10), label: `Apple security release — ${publishedAt.slice(0, 10)}`, sourceUrl: raw.resolvedUrl } : undefined,
  };
}

function appleCveScopes(document: ReturnType<typeof loadHtml>): Map<string, string> {
  const scopes = new Map<string, string>();
  document("p, li, [data-cve], .cve, .gb-paragraph").each((_index, node) => {
    const current = document(node).text().replace(/\s+/g, " ").trim();
    const ids = cveIds(current);
    if (ids.length !== 1) return;
    const nodeWrapper = document(node);
    const component = nodeWrapper.prevAll("h3").first().text().replace(/\s+/g, " ").trim();
    const availableFor = nodeWrapper.prevAll("p, li").filter((_i, value) => /\bAvailable for:/i.test(document(value).text())).first().text().replace(/\s+/g, " ").trim();
    scopes.set(ids[0], [`Component: ${component}`, availableFor, current].filter(Boolean).join(" — "));
  });
  return scopes;
}

function appleReleaseTitle(title: string): { product: string } | undefined {
  const match = title.match(/security content of\s+(.+)$/i);
  const product = match?.[1]?.replace(/\s+/g, " ").trim();
  return product ? { product } : undefined;
}
