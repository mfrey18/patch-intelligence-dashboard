import type { NormalizedAdvisory, NormalizedExploitEvidence, NormalizedAffectedProduct, NormalizedRemediation } from "../../domain/types";
import type { AdvisoryRef, RawAdvisory, VendorAdapter } from "../contracts";
import { normalizeCsaf } from "./csaf";
import { createConfiguredCsafAdapter } from "./configured-csaf";
import { absoluteOfficialUrl, cveIds, explicitDate, fetchOfficialHtml, inWindow, links, loadHtml, read, severityFromText } from "./html";

const DEFAULT_INDEX_URL = "https://chromereleases.googleblog.com/";
const CHROME_HOSTS = ["googleblog.com", "google.com", "chromium.org"];

export interface ChromeAdapterOptions {
  csafUrls?: string[];
  bearerToken?: string;
  indexUrl?: string;
}

export function createChromeAdapter(options: ChromeAdapterOptions = {}): VendorAdapter {
  if (options.csafUrls?.length) return createConfiguredCsafAdapter({ vendor: "chrome", sourceId: "chrome-configured-csaf", urls: options.csafUrls, bearerToken: options.bearerToken, allowedHosts: ["google.com", "chromium.org"], missingConfigurationMessage: "Chrome requires an official CSAF URL" });
  return createChromeHtmlAdapter(options.indexUrl ?? DEFAULT_INDEX_URL);
}

function createChromeHtmlAdapter(indexUrl: string): VendorAdapter {
  const page = async (ctx: Parameters<VendorAdapter["discover"]>[0], cursor?: string) => {
    const fetched = await fetchOfficialHtml(cursor ?? indexUrl, ctx, CHROME_HOSTS);
    const document = loadHtml(fetched.html);
    const refs = chromeRefs(document, fetched.url, ctx.since, ctx.until);
    const coverageRefs = chromeRefs(document, fetched.url, undefined, ctx.until);
    if (!refs.length && !cursor) throw new Error("Chrome official HTML index contains no identifiable release advisories");
    const pagerHref = document("#Blog1_blog-pager-older-link, a.blog-pager-older-link").first().attr("href");
    const next = pagerHref ? { href: pagerHref, text: "Older Posts" } : links(document).find((link) => /older|next/i.test(link.text) || /(?:page|start-index|updated-max|max-results)=/i.test(link.href));
    const oldest = coverageRefs.map((ref) => ref.sourceUpdatedAt).filter(Boolean).sort()[0];
    const outsideRetention = Boolean(ctx.since && oldest && Date.parse(oldest) < Date.parse(ctx.since));
    const nextUrl = outsideRetention ? undefined : next ? absoluteOfficialUrl(fetched.url, next.href, CHROME_HOSTS) : undefined;
    if (ctx.since && !nextUrl && (!oldest || Date.parse(oldest) > Date.parse(ctx.since))) throw new Error("Chrome official index did not establish the requested historical boundary");
    return { refs, nextCursor: nextUrl && nextUrl !== fetched.url ? nextUrl : null };
  };
  return {
    vendor: "chrome",
    sourceId: "chrome-configured-csaf",
    ...(indexUrl === DEFAULT_INDEX_URL ? { historicalCoverage: "complete_index" as const } : {}),
    async discover(ctx) {
      const refs: AdvisoryRef[] = [];
      const seen = new Set<string>();
      const seenPages = new Set<string>();
      let cursor: string | undefined;
      let pages = 0;
      do {
        if (++pages > 200) throw new Error("Chrome official pagination exceeded the bounded page limit");
        if (cursor && seenPages.has(cursor)) throw new Error("Chrome official pagination repeated a page cursor");
        if (cursor) seenPages.add(cursor);
        const current = await page(ctx, cursor);
        for (const ref of current.refs) if (!seen.has(ref.id)) { seen.add(ref.id); refs.push(ref); }
        cursor = current.nextCursor ?? undefined;
      } while (cursor);
      return refs;
    },
    async discoverPage(ctx, cursor) { return page(ctx, cursor); },
    async fetch(ref, ctx) {
      const fetched = await fetchOfficialHtml(ref.url, ctx, CHROME_HOSTS);
      return { ref, contentType: "text/html", body: fetched.html, fetchedAt: fetched.fetchedAt, resolvedUrl: fetched.url, etag: fetched.etag, lastModified: fetched.lastModified };
    },
    async normalize(raw, ctx) { return [normalizeChromeHtml(raw, ctx.sanitizeText)]; },
  };
}

function chromeRefs(document: ReturnType<typeof loadHtml>, baseUrl: string, since?: string, until?: string): AdvisoryRef[] {
  const refs = new Map<string, AdvisoryRef>();
  const posts = document(".post");
  if (posts.length) posts.each((_index, node) => {
    const post = document(node);
    const anchor = post.find("h2.title a[itemprop='url'], h2.title a[href]").first();
    const href = anchor.attr("href");
    const title = anchor.text().replace(/\s+/g, " ").trim();
    if (!href || !/\b(?:stable channel|extended stable)\b/i.test(title) || /\b(?:beta|dev|canary)\b/i.test(title)) return;
    const url = absoluteOfficialUrl(baseUrl, href, CHROME_HOSTS);
    if (!url || !/\.html?(?:$|[?#])/i.test(new URL(url).pathname)) return;
    const published = post.find("[itemprop='datePublished']").first();
    const sourceUpdatedAt = explicitDate(published.attr("content") ?? published.text());
    if (sourceUpdatedAt && !inWindow(sourceUpdatedAt, since, until)) return;
    const id = chromeId(url, post.attr("data-id"));
    if (id) refs.set(id, { id, url, sourceUpdatedAt, metadata: { channel: /extended stable/i.test(title) ? "extended-stable" : "stable", title } });
  });
  if (!posts.length) for (const link of links(document)) {
    const url = absoluteOfficialUrl(baseUrl, link.href, CHROME_HOSTS);
    if (!url || !/\.html?(?:$|[?#])/i.test(new URL(url).pathname)) continue;
    if (!/\b(?:stable channel|extended stable)\b/i.test(link.text) || /\b(?:beta|dev|canary)\b/i.test(link.text)) continue;
    const id = chromeId(url);
    if (id) refs.set(id, { id, url, sourceUpdatedAt: explicitDate(link.text), metadata: { title: link.text.trim() } });
  }
  return [...refs.values()].sort((left, right) => chromeRepresentativeRank(left) - chromeRepresentativeRank(right));
}

function chromeRepresentativeRank(ref: AdvisoryRef): number {
  const title = ref.metadata?.title ?? "";
  if (/^stable channel update for desktop$/i.test(title)) return 0;
  if (/^extended stable update for desktop$/i.test(title)) return 1;
  return 2;
}

function chromeId(value: string, postId?: string): string | undefined {
  try {
    const url = new URL(value);
    const canonicalPath = url.pathname.replace(/^\/+|\/+$/g, "").replace(/\.html?$/i, "");
    return postId ? `CHROME-POST-${postId}` : canonicalPath ? `CHROME-${canonicalPath}` : undefined;
  } catch { return undefined; }
}

export const chromeAdapter = createChromeAdapter();

export function normalizeChromeCsaf(raw: RawAdvisory, sanitize: (value: unknown) => string | undefined): NormalizedAdvisory {
  return normalizeCsaf(raw, sanitize, { vendor: "chrome", sourceId: "chrome-configured-csaf" })[0];
}

export function normalizeChromeHtml(raw: RawAdvisory, sanitize: (value: unknown) => string | undefined): NormalizedAdvisory {
  const document = loadHtml(String(raw.body));
  const article = chromeArticle(document);
  const bodyText = sanitize(article("body").text()) ?? "";
  const title = sanitize(read(document, ".post h2.title") ?? read(document, "h1") ?? read(document, "title") ?? raw.ref.id) ?? raw.ref.id;
  const publishedAt = explicitDate(read(document, "[itemprop='datePublished']", "content") ?? read(document, "[itemprop='datePublished']") ?? read(document, "time", "datetime") ?? read(document, "time") ?? raw.ref.sourceUpdatedAt);
  const scopes = chromeCveScopes(document);
  const cves = [...scopes.keys()];
  const severityText = bodyText.match(/\bseverity\s*[:-]\s*(critical|high|medium|low)\b/i)?.[1];
  const evidenceDate = publishedAt ?? raw.ref.sourceUpdatedAt;
  const exploitEvidence: NormalizedExploitEvidence[] = [];
  const affectedProducts: NormalizedAffectedProduct[] = [];
  const remediations: NormalizedRemediation[] = [];
  for (const [cveId, scope] of scopes) {
    const explicitlyNotKnown = /(?:no evidence|not aware|no known)\s+(?:of\s+)?(?:active\s+)?exploitation/i.test(scope);
    const known = !explicitlyNotKnown && /(?:actively exploited|exploitation (?:has been )?(?:observed|confirmed)|exploited in the wild)/i.test(scope);
    const zeroDayConfirmed = /(?:zero[- ]day[^.]{0,120}(?:confirmed|actively exploited|exploited)|(?:confirmed|actively exploited|exploited)[^.]{0,120}zero[- ]day)/i.test(scope);
    const zeroDayNegative = /(?:not a zero[- ]day|no evidence[^.]{0,120}zero[- ]day)/i.test(scope);
    if (known || explicitlyNotKnown) exploitEvidence.push({ cveId, type: "known_exploitation", status: known ? "confirmed" : "not_confirmed", evidenceDate, evidenceUrl: raw.resolvedUrl, summary: scope.slice(0, 500) });
    if (zeroDayConfirmed || zeroDayNegative) exploitEvidence.push({ cveId, type: "zero_day", status: zeroDayConfirmed ? "confirmed" : "not_confirmed", evidenceDate, evidenceUrl: raw.resolvedUrl, summary: scope.slice(0, 500) });
  }
  for (const release of chromePlatformReleases(bodyText)) {
    affectedProducts.push({ name: "Chrome", family: release.platform, fixedVersion: release.version, status: "fixed" });
    remediations.push({ productName: "Chrome", kind: "fixed_version", fixedVersion: release.version, patchAvailable: true, sourceUrl: raw.resolvedUrl, publishedAt, updatedAt: publishedAt });
  }
  const known = exploitEvidence.some((item) => item.type === "known_exploitation" && item.status === "confirmed");
  const explicitlyNotKnown = exploitEvidence.some((item) => item.type === "known_exploitation" && item.status === "not_confirmed");
  const zeroDay = exploitEvidence.some((item) => item.type === "zero_day" && item.status === "confirmed");
  const zeroDayNegative = exploitEvidence.some((item) => item.type === "zero_day" && item.status === "not_confirmed");
  return {
    vendor: "chrome", sourceId: "chrome-configured-csaf", vendorAdvisoryId: raw.ref.id, title, summary: bodyText.slice(0, 1_000) || undefined, sourceUrl: raw.resolvedUrl, publishedAt, sourceUpdatedAt: raw.ref.sourceUpdatedAt ?? publishedAt, vendorSeverity: severityText,
    cves: cves.map((cveId) => {
      const scopedSeverity = scopes.get(cveId)?.match(/\b(critical|high|medium|moderate|low)\b/i)?.[1];
      return { cveId, description: scopes.get(cveId)?.slice(0, 1_000), vendorSeverity: scopedSeverity ?? severityText, normalizedSeverity: severityFromText(scopedSeverity ?? severityText ?? ""), publishedAt, modifiedAt: raw.ref.sourceUpdatedAt ?? publishedAt };
    }), affectedProducts, remediations,
    exploitationStatus: known ? "known_exploited" : explicitlyNotKnown ? "not_known_exploited" : "unknown", zeroDayStatus: zeroDay ? "confirmed" : zeroDayNegative ? "not_confirmed" : "unknown", exploitEvidence,
    releaseEvent: publishedAt ? { id: `chrome-security-release-${publishedAt.slice(0, 10)}`, eventType: "security_release", eventDate: publishedAt.slice(0, 10), label: `Chrome security release — ${publishedAt.slice(0, 10)}`, sourceUrl: raw.resolvedUrl } : undefined,
  };
}

function chromeCveScopes(document: ReturnType<typeof loadHtml>): Map<string, string> {
  const scopes = new Map<string, string>();
  const article = chromeArticle(document);
  article("p, li, [data-cve]").each((_index, node) => {
    const current = article(node).text().replace(/\s+/g, " ").trim();
    const ids = cveIds(current);
    if (ids.length !== 1) return;
    scopes.set(ids[0], current);
  });
  return scopes;
}

function chromeArticle(document: ReturnType<typeof loadHtml>): ReturnType<typeof loadHtml> {
  const content = document(".post-content, [itemprop='articleBody'], main").first();
  if (!content.length) return loadHtml(document("body").html() ?? "");
  const template = content.find("script[type='text/template']").first();
  return template.length ? loadHtml(template.text()) : loadHtml(content.html() ?? "");
}

function chromePlatformReleases(value: string): Array<{ platform: string; version: string }> {
  const releases = new Map<string, string>();
  const add = (platform: string, version: string) => {
    const normalizedPlatform = platform.replace(/\s+and\s+/i, "/").replace(/\s*\/\s*/g, "/").trim();
    const key = `${normalizedPlatform}\u0000${version}`;
    releases.set(key, version);
  };
  for (const match of value.matchAll(/Chrome\s+\d+\s*\((\d+\.\d+\.\d+\.\d+)\)\s*([^\n]{0,20})/gi)) {
    const platform = match[2].trim();
    if (/linux|windows|mac/i.test(platform)) add(platform, match[1]);
  }
  for (const match of value.matchAll(/Chrome\s+(\d+\.\d+\.\d+\.\d+)\s*\((Linux|Windows|Mac)\)/gi)) add(match[2], match[1]);
  for (const match of value.matchAll(/(\d+\.\d+\.\d+\.\d+)(?:\/(\.?\d+))?\s+(?:for\s+)?(Windows\s*(?:\/|and)\s*Mac|Linux|Mac|Windows)/gi)) {
    const version = match[2] ? `${match[1]}/${match[2].startsWith(".") ? match[2] : `.${match[2]}`}` : match[1];
    add(match[3], version);
  }
  return [...releases].map(([key, version]) => ({ platform: key.split("\u0000")[0], version }));
}
