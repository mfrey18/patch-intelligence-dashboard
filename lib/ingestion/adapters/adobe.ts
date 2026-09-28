import type { NormalizedAdvisory, NormalizedExploitEvidence } from "../../domain/types";
import type { AdvisoryRef, RawAdvisory, VendorAdapter } from "../contracts";
import { fetchWithPolicy, readJsonLimited } from "../safety";
import { normalizeCsaf } from "./csaf";
import { absoluteOfficialUrl, cveIds, explicitDate, fetchOfficialHtml, inWindow, links, loadHtml, normalizeRefDate, read, severityFromText } from "./html";
import { iso, list, record, stringValue } from "./utils";

const DEFAULT_INDEX_URL = "https://helpx.adobe.com/security.html";
const ADOBE_SITEMAP_URL = "https://helpx.adobe.com/sitemap.xml";
const ADOBE_HOSTS = ["adobe.com"];

export interface AdobeAdapterOptions {
  /** Explicit Adobe JSON/CSAF index. When absent, the approved public HTML path is used. */
  indexUrl?: string;
  authorization?: string;
}

export function createAdobeAdapter(options: AdobeAdapterOptions = {}): VendorAdapter {
  return options.indexUrl ? createConfiguredAdobeAdapter(options) : createAdobeHtmlAdapter();
}

function createConfiguredAdobeAdapter(options: AdobeAdapterOptions): VendorAdapter {
  return {
    vendor: "adobe",
    sourceId: "adobe-psirt-csaf",
    historicalCoverage: "configured_subset",
    async discover(ctx) {
      assertAdobeUrl(options.indexUrl!, "Adobe security index");
      const headers: Record<string, string> = { accept: "application/json" };
      if (options.authorization) headers.authorization = options.authorization;
      const response = await fetchWithPolicy(options.indexUrl!, ctx.policy, { headers });
      const payload = await readJsonLimited(response, ctx.policy.maxResponseBytes);
      return adobeJsonRefs(payload, ctx.since, ctx.until);
    },
    async fetch(ref, ctx) {
      assertAdobeUrl(ref.url, "Adobe CSAF advisory");
      const headers: Record<string, string> = { accept: "application/json" };
      if (options.authorization) headers.authorization = options.authorization;
      const response = await fetchWithPolicy(ref.url, ctx.policy, { headers });
      return { ref, contentType: response.headers.get("content-type") ?? "application/json", body: await readJsonLimited(response, ctx.policy.maxResponseBytes), fetchedAt: new Date().toISOString(), resolvedUrl: response.url, etag: response.headers.get("etag") ?? undefined, lastModified: response.headers.get("last-modified") ?? undefined };
    },
    async normalize(raw, ctx) { return normalizeAdobeCsaf(raw, ctx.observedAt, ctx.sanitizeText); },
  };
}

function createAdobeHtmlAdapter(): VendorAdapter {
  const indexUrl = DEFAULT_INDEX_URL;
  const isDefaultIndex = indexUrl === DEFAULT_INDEX_URL;
  const page = async (ctx: Parameters<VendorAdapter["discover"]>[0], cursor?: string) => {
    const current = cursor ?? indexUrl;
    const document = await fetchOfficialHtml(current, ctx, ADOBE_HOSTS);
    const $ = loadHtml(document.html);
    const refs = adobeHtmlRefs($, document.url, ctx.since, ctx.until);
    if (!refs.length && !cursor) throw new Error("Adobe official HTML index contains no identifiable APSB advisories");
    const next = links($).find((link) => /(?:next\s+page|older)/i.test(link.text) || /(?:[?&]page=|\/page\/|page=)/i.test(link.href));
    const nextUrl = next ? absoluteOfficialUrl(document.url, next.href, ADOBE_HOSTS) : undefined;
    return { refs, nextCursor: nextUrl && nextUrl !== document.url ? nextUrl : null };
  };
  return {
    vendor: "adobe",
    sourceId: "adobe-psirt-csaf",
    ...(isDefaultIndex ? { historicalCoverage: "complete_index" as const } : {}),
    async discover(ctx) {
      const sitemapRefs = isDefaultIndex ? await adobeSitemapRefs(ctx) : null;
      if (isDefaultIndex && !sitemapRefs) throw new Error("Adobe official sitemap was unavailable or malformed; refusing incomplete HTML coverage");
      if (sitemapRefs) return sitemapRefs;
      const all: AdvisoryRef[] = [];
      const seen = new Set<string>();
      const seenPages = new Set<string>();
      let cursor: string | undefined;
      do {
        if (cursor && seenPages.has(cursor)) throw new Error("Adobe official pagination repeated a page cursor");
        if (cursor) seenPages.add(cursor);
        const current = await page(ctx, cursor);
        for (const ref of current.refs) if (!seen.has(ref.id)) { seen.add(ref.id); all.push(ref); }
        cursor = current.nextCursor ?? undefined;
      } while (cursor);
      return all;
    },
    async discoverPage(ctx, cursor) {
      if (cursor) return page(ctx, cursor);
      const sitemapRefs = isDefaultIndex ? await adobeSitemapRefs(ctx) : null;
      if (isDefaultIndex && !sitemapRefs) throw new Error("Adobe official sitemap was unavailable or malformed; refusing incomplete HTML coverage");
      return sitemapRefs ? { refs: sitemapRefs, nextCursor: null } : page(ctx);
    },
    async fetch(ref, ctx) {
      const response = await fetchOfficialHtml(ref.url, ctx, ADOBE_HOSTS);
      return { ref, contentType: "text/html", body: response.html, fetchedAt: response.fetchedAt, resolvedUrl: response.url, etag: response.etag, lastModified: response.lastModified };
    },
    async normalize(raw, ctx) { return [normalizeAdobeHtml(raw, ctx.sanitizeText)]; },
  };
}

async function adobeSitemapRefs(ctx: Parameters<VendorAdapter["discover"]>[0]): Promise<AdvisoryRef[] | null> {
  const fetched = await fetchOfficialHtml(ADOBE_SITEMAP_URL, ctx, ADOBE_HOSTS);
  const document = loadHtml(fetched.html);
  const entries: AdvisoryRef[] = [];
  document("url").each((_index, node) => {
    const url = document(node).find("loc").first().text().trim();
    const match = url.match(/\b(APSB\d{2}-\d+)\.html(?:$|[?#])/i);
    if (!match) return;
    const sourceUpdatedAt = normalizeRefDate(document(node).find("lastmod").first().text().trim());
    if (sourceUpdatedAt && !inWindow(sourceUpdatedAt, ctx.since, ctx.until)) return;
    const safeUrl = absoluteOfficialUrl(fetched.url, url, ADOBE_HOSTS);
    if (!safeUrl) return;
    entries.push({ id: match[1].toUpperCase(), url: safeUrl, sourceUpdatedAt });
  });
  if (!document("url").length) return null;
  const dates = document("url").toArray().map((node) => normalizeRefDate(document(node).find("lastmod").first().text().trim())).filter((value): value is string => Boolean(value));
  const since = ctx.since;
  if (since && (!dates.some((value) => Date.parse(value) <= Date.parse(since)) || !entries.length)) throw new Error("Adobe official sitemap did not establish the requested historical boundary");
  return [...new Map(entries.map((ref) => [ref.id, ref])).values()];
}

function adobeJsonRefs(payload: unknown, since?: string, until?: string): AdvisoryRef[] {
  const refs = new Map<string, AdvisoryRef>();
  for (const value of list(record(payload).advisories ?? payload)) {
    const entry = record(value);
    const id = stringValue(entry.id ?? entry.advisory_id)?.trim().toUpperCase();
    const url = stringValue(entry.csaf_url ?? entry.url)?.trim();
    const sourceUpdatedAt = iso(entry.updated_at ?? entry.current_release_date);
    if (!id || !/^APSB\d{2}-\d+$/i.test(id) || !url) continue;
    assertAdobeUrl(url, "Adobe CSAF advisory");
    if (sourceUpdatedAt && !inWindow(sourceUpdatedAt, since, until)) continue;
    refs.set(id, { id, url, sourceUpdatedAt });
  }
  return [...refs.values()];
}

function adobeHtmlRefs(document: ReturnType<typeof loadHtml>, baseUrl: string, since?: string, until?: string): AdvisoryRef[] {
  const refs = new Map<string, AdvisoryRef>();
  // The current Adobe index is a data table: the bulletin link and its
  // publication/update dates live in sibling cells, rather than in the link
  // label. Read the row as one unit so the date belongs to that bulletin.
  document("table tr").each((_index, node) => {
    const row = document(node);
    const link = row.find("a[href]").toArray().map((value) => ({ href: row.find(value).attr("href") ?? "", text: row.find(value).text() })).find((value) => /\bAPSB\d{2}-\d+\b/i.test(`${value.href} ${value.text}`));
    if (!link?.href) return;
    const match = `${link.href} ${link.text}`.match(/\b(APSB\d{2}-\d+)\b/i);
    if (!match) return;
    const url = absoluteOfficialUrl(baseUrl, link.href, ADOBE_HOSTS);
    if (!url) return;
    const cells = row.find("th,td").toArray().map((cell) => document(cell).text().replace(/\s+/g, " ").trim());
    const dates = cells.map((value) => explicitDate(value)).filter((value): value is string => Boolean(value));
    const sourceUpdatedAt = dates.at(-1);
    if (sourceUpdatedAt && !inWindow(sourceUpdatedAt, since, until)) return;
    refs.set(match[1].toUpperCase(), { id: match[1].toUpperCase(), url, sourceUpdatedAt });
  });
  if (refs.size) return [...refs.values()];
  for (const link of links(document)) {
    const match = `${link.href} ${link.text}`.match(/\b(APSB\d{2}-\d+)\b/i);
    if (!match) continue;
    const url = absoluteOfficialUrl(baseUrl, link.href, ADOBE_HOSTS);
    if (!url) continue;
    const id = match[1].toUpperCase();
    const sourceUpdatedAt = explicitDate(link.text);
    if (sourceUpdatedAt && !inWindow(sourceUpdatedAt, since, until)) continue;
    refs.set(id, { id, url, sourceUpdatedAt });
  }
  return [...refs.values()];
}

export const adobeAdapter = createAdobeAdapter();

export function normalizeAdobeCsaf(raw: RawAdvisory, _observedAt: string, sanitize: (value: unknown) => string | undefined): NormalizedAdvisory[] {
  return normalizeCsaf(raw, sanitize, { vendor: "adobe", sourceId: "adobe-psirt-csaf", releaseEvent: (publishedAt, sourceUrl) => ({ id: `adobe-security-release-${publishedAt.slice(0, 10)}`, eventType: "security_release", eventDate: publishedAt.slice(0, 10), label: `Adobe security release — ${publishedAt.slice(0, 10)}`, sourceUrl }) });
}

export function normalizeAdobeHtml(raw: RawAdvisory, sanitize: (value: unknown) => string | undefined): NormalizedAdvisory {
  const document = loadHtml(String(raw.body));
  const bodyText = sanitize(document("body").text()) ?? "";
  const title = sanitize(read(document, "h1") ?? read(document, "title") ?? raw.ref.id) ?? raw.ref.id;
  const publishedAt = explicitDate(read(document, "time", "datetime") ?? read(document, "time") ?? raw.ref.sourceUpdatedAt);
  const scopes = adobeCveScopes(document);
  const cves = [...scopes.keys()];
  const severityText = bodyText.match(/\b(?:severity|priority)\s*[:-]\s*(critical|important|high|medium|low)\b/i)?.[1];
  const evidenceDate = publishedAt ?? raw.ref.sourceUpdatedAt;
  const exploitEvidence: NormalizedExploitEvidence[] = [];
  for (const [cveId, scope] of scopes) {
    const explicitlyNotKnown = /(?:no evidence|not aware|no known)\s+(?:of\s+)?(?:active\s+)?exploitation/i.test(scope);
    const known = !explicitlyNotKnown && /(?:actively exploited|exploitation (?:has been )?(?:observed|confirmed)|exploited in the wild)/i.test(scope);
    const zeroDayConfirmed = /(?:zero[- ]day[^.]{0,120}(?:confirmed|actively exploited|exploited)|(?:confirmed|actively exploited|exploited)[^.]{0,120}zero[- ]day)/i.test(scope);
    const zeroDayNegative = /(?:not a zero[- ]day|no evidence[^.]{0,120}zero[- ]day)/i.test(scope);
    if (known || explicitlyNotKnown) exploitEvidence.push({ cveId, type: "known_exploitation", status: known ? "confirmed" : "not_confirmed", evidenceDate, evidenceUrl: raw.resolvedUrl, summary: scope.slice(0, 500) });
    if (zeroDayConfirmed || zeroDayNegative) exploitEvidence.push({ cveId, type: "zero_day", status: zeroDayConfirmed ? "confirmed" : "not_confirmed", evidenceDate, evidenceUrl: raw.resolvedUrl, summary: scope.slice(0, 500) });
  }
  const productAssertions = adobeProductAssertions(document, raw.resolvedUrl, publishedAt);
  const remediations = [...productAssertions.remediations, ...adobeCveRemediations(document, raw.resolvedUrl, publishedAt)];
  const known = exploitEvidence.some((item) => item.type === "known_exploitation" && item.status === "confirmed");
  const explicitlyNotKnown = exploitEvidence.some((item) => item.type === "known_exploitation" && item.status === "not_confirmed");
  const zeroDay = exploitEvidence.some((item) => item.type === "zero_day" && item.status === "confirmed");
  const zeroDayNegative = exploitEvidence.some((item) => item.type === "zero_day" && item.status === "not_confirmed");
  return {
    vendor: "adobe", sourceId: "adobe-psirt-csaf", vendorAdvisoryId: raw.ref.id, title, summary: bodyText.slice(0, 1_000) || undefined, sourceUrl: raw.resolvedUrl, publishedAt, sourceUpdatedAt: raw.ref.sourceUpdatedAt ?? publishedAt, vendorSeverity: severityText, cves: cves.map((cveId) => {
      const scopedSeverity = scopes.get(cveId)?.match(/\b(critical|high|medium|moderate|low)\b/i)?.[1];
      return { cveId, normalizedSeverity: severityFromText(scopedSeverity ?? severityText ?? ""), vendorSeverity: scopedSeverity ?? severityText, description: scopes.get(cveId)?.slice(0, 1_000), publishedAt, modifiedAt: raw.ref.sourceUpdatedAt ?? publishedAt };
    }), affectedProducts: productAssertions.affectedProducts, remediations, exploitationStatus: known ? "known_exploited" : explicitlyNotKnown ? "not_known_exploited" : "unknown", zeroDayStatus: zeroDay ? "confirmed" : zeroDayNegative ? "not_confirmed" : "unknown", exploitEvidence, releaseEvent: publishedAt ? { id: `adobe-security-release-${publishedAt.slice(0, 10)}`, eventType: "security_release", eventDate: publishedAt.slice(0, 10), label: `Adobe security release — ${publishedAt.slice(0, 10)}`, sourceUrl: raw.resolvedUrl } : undefined,
  };
}

function adobeCveScopes(document: ReturnType<typeof loadHtml>): Map<string, string> {
  const scopes = new Map<string, string>();
  document("table").each((_tableIndex, table) => {
    const rows = document(table).find("tr");
    const header = rows.first().find("th,td").toArray().map((cell) => document(cell).text().replace(/\s+/g, " ").trim()).join(" ");
    if (!/CVE\s+number/i.test(header)) return;
    rows.slice(1).each((_rowIndex, row) => {
      const current = document(row).find("th,td").toArray().map((cell) => document(cell).text().replace(/\s+/g, " ").trim()).join(" ");
      const ids = cveIds(current);
      if (ids.length === 1) scopes.set(ids[0], current);
    });
  });
  // Adobe's current HelpX detail pages render the vulnerability grid as
  // div.table (rather than a <table>). Keep each CVE tied to its own row so
  // severity and description cannot bleed across vulnerabilities.
  document("div.table").each((_tableIndex, table) => {
    const rows = document(table).children("div");
    const header = rows.first().text().replace(/\s+/g, " ").trim();
    if (!/CVE\s+number/i.test(header)) return;
    rows.slice(1).each((_rowIndex, row) => {
      const current = document(row).text().replace(/\s+/g, " ").trim();
      const ids = cveIds(current);
      if (ids.length === 1) scopes.set(ids[0], current);
    });
  });
  document("main p, article p, .content p, [itemprop='articleBody'] p, [data-cve]").each((_index, node) => {
    const current = document(node).text().replace(/\s+/g, " ").trim();
    const ids = cveIds(current);
    if (ids.length !== 1) return;
    scopes.set(ids[0], current);
  });
  if (!scopes.size) for (const id of cveIds(document("main, article, body").first().text())) scopes.set(id, id);
  return scopes;
}

function adobeProductAssertions(document: ReturnType<typeof loadHtml>, sourceUrl: string, publishedAt?: string): { affectedProducts: NormalizedAdvisory["affectedProducts"]; remediations: NormalizedAdvisory["remediations"] } {
  type ProductRow = { product: string; track?: string; version: string; platform?: string };
  const affected: ProductRow[] = [];
  const updates: ProductRow[] = [];
  for (const block of adobeTabularRows(document)) {
    const headers = block.headers.map((header) => header.toLowerCase());
    const versionIndex = headers.findIndex((header) => /affected versions?|updated versions?|fixed versions?/.test(header));
    const productIndex = headers.findIndex((header) => header === "product");
    const trackIndex = headers.findIndex((header) => header === "track");
    const platformIndex = headers.findIndex((header) => header === "platform");
    if (versionIndex < 0 || productIndex < 0) continue;
    const target = headers[versionIndex].startsWith("affected") ? affected : headers[versionIndex].startsWith("updated") || headers[versionIndex].startsWith("fixed") ? updates : undefined;
    if (!target) continue;
    for (const cells of block.rows) {
      const product = cells[productIndex];
      const version = cells[versionIndex];
      if (!product || !version) continue;
      target.push({ product, version, ...(trackIndex >= 0 && cells[trackIndex] ? { track: cells[trackIndex] } : {}), ...(platformIndex >= 0 && cells[platformIndex] ? { platform: cells[platformIndex] } : {}) });
    }
  }
  const key = (row: ProductRow) => [row.product, row.track ?? "", row.platform?.replace(/\s*&\s*/g, " and ").replace(/\s+/g, " ").trim() ?? ""].join("\u0000");
  const versions = new Map<string, string[]>();
  for (const row of updates) versions.set(key(row), [...(versions.get(key(row)) ?? []), row.version]);
  const usedVersions = new Map<string, number>();
  const affectedProducts: NormalizedAdvisory["affectedProducts"] = [];
  const remediations: NormalizedAdvisory["remediations"] = [];
  for (const row of affected) {
    const candidates = versions.get(key(row)) ?? [];
    const position = usedVersions.get(key(row)) ?? 0;
    const fixedVersion = candidates[position];
    usedVersions.set(key(row), position + 1);
    affectedProducts.push({ name: row.product, ...(row.track ? { family: row.track } : {}), ...(row.platform ? { affectedVersion: `${row.version} (${row.platform})` } : { affectedVersion: row.version }), status: "affected", ...(fixedVersion ? { fixedVersion } : {}) });
    if (fixedVersion) remediations.push({ productName: row.product, kind: "fixed_version", fixedVersion, patchAvailable: true, sourceUrl, publishedAt, updatedAt: publishedAt });
  }
  return { affectedProducts, remediations };
}

function adobeCveRemediations(document: ReturnType<typeof loadHtml>, sourceUrl: string, publishedAt?: string): NormalizedAdvisory["remediations"] {
  const remediations: NormalizedAdvisory["remediations"] = [];
  for (const block of adobeTabularRows(document)) {
    const headers = block.headers.map((header) => header.toLowerCase());
    const cveIndex = headers.findIndex((header) => /cve/.test(header));
    const fixedIndex = headers.findIndex((header) => /fixed|solution|update|available|version/.test(header));
    if (cveIndex < 0 || fixedIndex < 0) continue;
    for (const cells of block.rows) {
      const ids = cveIds(cells[cveIndex] ?? "");
      const fixedVersion = cells[fixedIndex];
      if (ids.length === 1 && fixedVersion) remediations.push({ cveId: ids[0], kind: "fixed_version", fixedVersion, patchAvailable: true, sourceUrl, publishedAt, updatedAt: publishedAt });
    }
  }
  return remediations;
}

function adobeTabularRows(document: ReturnType<typeof loadHtml>): Array<{ headers: string[]; rows: string[][] }> {
  const blocks: Array<{ headers: string[]; rows: string[][] }> = [];
  document("table").each((_index, table) => {
    const rows = document(table).find("tr").toArray().map((row) => document(row).find("th,td").toArray().map((cell) => document(cell).text().replace(/\s+/g, " ").trim()));
    if (rows.length > 0 && rows[0].length > 0) blocks.push({ headers: rows[0], rows: rows.slice(1) });
  });
  document("div.table").each((_index, table) => {
    if (document(table).find("table").length) return;
    const rows = document(table).children("div").toArray().map((row) => document(row).children("div").toArray().map((cell) => document(cell).text().replace(/\s+/g, " ").trim()));
    if (rows.length > 0 && rows[0].length > 0) blocks.push({ headers: rows[0], rows: rows.slice(1) });
  });
  return blocks;
}

function assertAdobeUrl(value: string, label: string): void {
  const url = new URL(value);
  if (url.protocol !== "https:" || !(url.hostname === "adobe.com" || url.hostname.endsWith(".adobe.com"))) throw new Error(`${label} must use HTTPS on an official Adobe host`);
}
