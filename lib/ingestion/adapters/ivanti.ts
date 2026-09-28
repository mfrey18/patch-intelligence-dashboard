import type { NormalizedAdvisory, NormalizedExploitEvidence, NormalizedRemediation } from "../../domain/types";
import type { AdvisoryRef, RawAdvisory, VendorAdapter } from "../contracts";
import { fetchWithPolicy, readTextLimited } from "../safety";
import { feedItemInWindow, parseVendorFeed, type ParsedFeedItem } from "./rss";
import { uniqueBy, validCve } from "./utils";
import { absoluteOfficialUrl, explicitDate, loadHtml, read, tableRows, text } from "./html";

const FEED_URL = "https://www.ivanti.com/blog/topics/security-advisory/rss";
const IVANTI_ORIGIN = "https://www.ivanti.com";

export interface IvantiAdapterOptions { followDetails?: boolean; }

export function createIvantiAdapter(options: IvantiAdapterOptions = {}): VendorAdapter {
  const cache = new Map<string, ParsedFeedItem>();
  const load = async (ctx: { policy: Parameters<typeof fetchWithPolicy>[1] }): Promise<ParsedFeedItem[]> => {
    const response = await fetchWithPolicy(FEED_URL, ctx.policy);
    const items = parseVendorFeed(await readTextLimited(response, ctx.policy.maxResponseBytes));
    for (const item of items) cache.set(advisoryId(item), item);
    return items;
  };
  return {
    vendor: "ivanti",
    sourceId: "ivanti-security-advisory-rss",
    historicalCoverage: options.followDetails ? "complete_index" : undefined,
    async discover(ctx) {
      const items = await load(ctx);
      if (options.followDetails) {
        const eligible = items.filter((value) => feedItemInWindow(value, ctx.since, ctx.until));
        const oldest = items.map((item) => item.publishedAt ?? item.updatedAt).filter((value): value is string => Boolean(value)).sort()[0];
        if (ctx.since && (!oldest || Date.parse(oldest) > Date.parse(ctx.since))) throw new Error("Ivanti RSS does not cover the requested historical window");
        const refs: AdvisoryRef[] = [];
        for (const item of eligible) {
          const blog = loadHtml(item.description ?? "");
          const detailUrls = [...new Set(blog("a[href]").toArray().flatMap((node) => { const value = absoluteOfficialUrl(item.link, blog(node).attr("href") ?? "", ["ivanti.com", "forums.ivanti.com"]); return value && value.includes("forums.ivanti.com/s/article/") ? [value] : []; }))];
          for (const url of detailUrls) refs.push({ id: ivantiDetailId(url), url, sourceUpdatedAt: item.updatedAt ?? item.publishedAt, metadata: { feedUrl: FEED_URL, blogUrl: item.link, blogTitle: item.title } });
        }
        if (!refs.length) throw new Error("Ivanti RSS exposed no official support advisory detail links");
        return [...new Map(refs.map((ref) => [ref.id, ref])).values()];
      }
      const refs: AdvisoryRef[] = [];
      for (const item of items.filter((value) => feedItemInWindow(value, ctx.since, ctx.until))) {
        const id = advisoryId(item);
        const publication = officialPublication(item.link);
        if (!id || !publication) continue;
        refs.push({ id, url: publication, sourceUpdatedAt: item.updatedAt ?? item.publishedAt, metadata: { feedUrl: FEED_URL } });
      }
      return refs;
    },
    async fetch(ref, ctx) {
      if (options.followDetails && ref.url.includes("forums.ivanti.com/s/article/")) {
        const detail = await import("./html").then(({ fetchOfficialHtml }) => fetchOfficialHtml(ref.url, ctx, ["ivanti.com", "forums.ivanti.com"]));
        return { ref, contentType: "text/html", body: detail.html, fetchedAt: detail.fetchedAt, resolvedUrl: detail.url, etag: detail.etag, lastModified: detail.lastModified };
      }
      let item = cache.get(ref.id);
      if (!item) item = (await load(ctx)).find((value) => advisoryId(value) === ref.id);
      if (!item) throw new Error(`Ivanti RSS item ${ref.id} is no longer present in the official feed`);
      if (!options.followDetails) return { ref, contentType: "application/rss+xml", body: item, fetchedAt: new Date().toISOString(), resolvedUrl: officialPublication(item.link) ?? ref.url, lastModified: item.updatedAt ?? item.publishedAt };
      throw new Error(`Ivanti detail reference ${ref.id} is not an official support advisory URL`);
    },
    async normalize(raw, ctx) { return typeof raw.body === "string" ? [normalizeIvantiHtml(raw.body, raw.resolvedUrl, ctx.sanitizeText)] : isDetailEnvelope(raw.body) ? [normalizeIvantiDetails(raw, ctx.sanitizeText)] : [normalizeIvantiRssItem(raw, ctx.observedAt, ctx.sanitizeText)]; },
  };
}

export const ivantiAdapter = createIvantiAdapter();
export const ivantiHtmlAdapter = createIvantiAdapter({ followDetails: true });

export function normalizeIvantiRssItem(raw: RawAdvisory, _observedAt: string, sanitize: (value: unknown) => string | undefined): NormalizedAdvisory {
  const item = raw.body as Partial<ParsedFeedItem>;
  const title = sanitize(item.title) ?? raw.ref.id;
  const plain = sanitize(item.description) ?? "";
  const cveIds = uniqueBy([...`${title} ${plain}`.matchAll(/CVE-\d{4}-\d{4,}/gi)].map((match) => validCve(match[0])).filter(Boolean) as string[], (value) => value);
  const known = /(?:evidence|aware) (?:of|that)[^.]{0,120}(?:was|were|being|been|actively )?exploited|exploitation (?:has been )?(?:observed|confirmed|detected)|exploited in the wild/i.test(plain)
    && !/(?:no evidence|not aware)[^.]{0,120}exploited/i.test(plain);
  const explicitlyNotKnown = /(?:no evidence|not aware)[^.]{0,120}(?:being |been )?exploited|no known exploitation/i.test(plain);
  const zeroDay = /\bzero[- ]day\b/i.test(plain);
  const patchAvailable = /(?:patch(?:es)?|fix(?:es)?|security update(?:s)?) (?:is|are|now (?:is|are)) available|(?:released|issued) (?:an? )?(?:patch|security update)/i.test(plain);
  const hasRemediationDirection = /(?:instructions|details) (?:on|for|about) how to remediate|apply (?:the )?(?:fix|patch|security update)|upgrade to/i.test(plain);
  const evidenceDate = item.updatedAt ?? item.publishedAt ?? raw.ref.sourceUpdatedAt;
  const exploitEvidence: NormalizedExploitEvidence[] = [];
  for (const cveId of cveIds) {
    if (known || explicitlyNotKnown) exploitEvidence.push({ cveId, type: "known_exploitation", status: known ? "confirmed" : "not_confirmed", evidenceDate, evidenceUrl: raw.resolvedUrl, summary: evidenceSentence(plain, /exploit/i) });
    if (zeroDay) exploitEvidence.push({ cveId, type: "zero_day", status: "confirmed", evidenceDate, evidenceUrl: raw.resolvedUrl, summary: evidenceSentence(plain, /zero[- ]day/i) });
  }
  // The RSS feed frequently contains generic patch-program language without
  // identifying the vulnerabilities to which it applies. Keep that language
  // out of the remediation model unless the same authoritative item names a CVE.
  const remediations: NormalizedRemediation[] = cveIds.length > 0 && (patchAvailable || hasRemediationDirection) ? [{
    kind: patchAvailable ? "patch" : "vendor_action",
    patchAvailable: patchAvailable ? true : undefined,
    action: patchAvailable ? "Apply the Ivanti security update described in the advisory." : "Follow the remediation instructions in the Ivanti security advisory.",
    sourceUrl: raw.resolvedUrl,
    publishedAt: item.publishedAt,
    updatedAt: item.updatedAt ?? item.publishedAt,
  }] : [];
  const publishedAt = item.publishedAt;
  return {
    vendor: "ivanti",
    sourceId: "ivanti-security-advisory-rss",
    vendorAdvisoryId: raw.ref.id,
    title,
    summary: plain.slice(0, 1_000) || undefined,
    sourceUrl: raw.resolvedUrl,
    publishedAt,
    sourceUpdatedAt: item.updatedAt ?? publishedAt ?? raw.ref.sourceUpdatedAt,
    exploitationStatus: known ? "known_exploited" : explicitlyNotKnown ? "not_known_exploited" : "unknown",
    zeroDayStatus: zeroDay ? "confirmed" : "unknown",
    cves: cveIds.map((cveId) => ({ cveId, description: plain.slice(0, 1_000) || undefined, normalizedSeverity: "unknown", publishedAt, modifiedAt: item.updatedAt ?? publishedAt })),
    affectedProducts: [],
    remediations,
    exploitEvidence,
    releaseEvent: publishedAt ? { id: `ivanti-security-release-${publishedAt.slice(0, 10)}`, eventType: "security_release", eventDate: publishedAt.slice(0, 10), label: `Ivanti security release — ${publishedAt.slice(0, 10)}`, sourceUrl: raw.resolvedUrl } : undefined,
  };
}

export interface IvantiHtmlDetail {
  vendorAdvisoryId: string;
  title: string;
  sourceUrl: string;
  publishedAt?: string;
  sourceUpdatedAt?: string;
  cves: string[];
  affectedProducts: NormalizedAdvisory["affectedProducts"];
  remediations: NormalizedAdvisory["remediations"];
}

export function parseIvantiDetail(html: string, sourceUrl: string): IvantiHtmlDetail {
  const document = loadHtml(html);
  const canonical = absoluteOfficialUrl(sourceUrl, read(document, "link[rel='canonical']", "href") ?? sourceUrl, ["ivanti.com", "forums.ivanti.com"]);
  if (!canonical) throw new Error("Ivanti detail URL is not official");
  const title = read(document, "meta[property='og:title']", "content") ?? text(document, "h1") ?? read(document, "title");
  if (!title) throw new Error("Ivanti detail has no explicit title");
  const id = advisoryId({ id: "", title, link: canonical });
  const body = text(document, "main") ?? text(document, "article") ?? text(document, "body") ?? "";
  const cves = looseCveIds(`${title} ${body}`);
  const dates = [read(document, "meta[property='article:published_time']", "content"), read(document, "meta[property='article:modified_time']", "content"), text(document, "time")].map((value) => explicitDate(value ?? undefined) ?? normalizeDate(value ?? undefined)).filter((value): value is string => Boolean(value));
  const affectedProducts: NormalizedAdvisory["affectedProducts"] = [];
  const remediations: NormalizedAdvisory["remediations"] = [];
  for (const row of tableRows(document)) {
    const headers = row.headers.map((value) => value.toLowerCase());
    if (headers.length > 0 && row.cells.length === headers.length && row.cells.every((value, index) => value.trim().toLowerCase() === headers[index])) continue;
    const productIndex = headers.findIndex((value) => /product|component|appliance/.test(value));
    const affectedIndex = headers.findIndex((value) => /affected|version|impact/.test(value));
    const fixedIndex = headers.findIndex((value) => /fixed|solution|remediat|upgrade|patch/.test(value));
    if (productIndex < 0 || (affectedIndex < 0 && fixedIndex < 0)) continue;
    const product = row.cells[productIndex]?.replace(/\s+/g, " ").trim();
    const affected = affectedIndex >= 0 ? row.cells[affectedIndex]?.replace(/\s+/g, " ").trim() : undefined;
    const fixed = fixedIndex >= 0 ? row.cells[fixedIndex]?.replace(/\s+/g, " ").trim() : undefined;
    if (!product || (!affected && !fixed)) continue;
    const rowCves = looseCveIds(row.cells.join(" "));
    const cveId = rowCves.length === 1 ? rowCves[0] : undefined;
    affectedProducts.push({ cveId, name: product, affectedVersion: affected, fixedVersion: fixed, status: affected ? "affected" : "fixed" });
    if (fixed) remediations.push({ cveId, productName: product, kind: "fixed_version", fixedVersion: fixed, patchAvailable: true, action: fixed, sourceUrl: canonical, publishedAt: dates[0], updatedAt: dates[1] ?? dates[0] });
  }
  return { vendorAdvisoryId: id, title, sourceUrl: canonical, publishedAt: dates[0], sourceUpdatedAt: dates[1] ?? dates[0], cves, affectedProducts, remediations };
}

export function normalizeIvantiHtml(html: string, sourceUrl: string, sanitize: (value: unknown) => string | undefined): NormalizedAdvisory {
  const parsed = parseIvantiDetail(html, sourceUrl); const publishedAt = parsed.publishedAt; const plain = sanitize(text(loadHtml(html), "body") ?? "") ?? "";
  const known = /(?:evidence|aware) (?:of|that)[^.]{0,120}(?:was|were|being|been|actively )?exploited|exploitation (?:has been )?(?:observed|confirmed|detected)|exploited in the wild/i.test(plain) && !/(?:no evidence|not aware)[^.]{0,120}exploited/i.test(plain);
  const explicitlyNotKnown = /(?:no evidence|not aware)[^.]{0,120}(?:being |been )?exploited|no known exploitation/i.test(plain);
  const zeroDay = /\bzero[- ]day\b/i.test(plain);
  const exploitEvidence = parsed.cves.flatMap((cveId) => [known || explicitlyNotKnown ? { cveId, type: "known_exploitation" as const, status: known ? "confirmed" as const : "not_confirmed" as const, evidenceDate: parsed.sourceUpdatedAt, evidenceUrl: parsed.sourceUrl } : undefined, zeroDay ? { cveId, type: "zero_day" as const, status: "confirmed" as const, evidenceDate: parsed.sourceUpdatedAt, evidenceUrl: parsed.sourceUrl } : undefined].filter((value): value is NonNullable<typeof value> => Boolean(value)));
  return { vendor: "ivanti", sourceId: "ivanti-security-advisory-rss", vendorAdvisoryId: parsed.vendorAdvisoryId, title: sanitize(parsed.title) ?? parsed.title, sourceUrl: parsed.sourceUrl, publishedAt, sourceUpdatedAt: parsed.sourceUpdatedAt, exploitationStatus: known ? "known_exploited" : explicitlyNotKnown ? "not_known_exploited" : "unknown", zeroDayStatus: zeroDay ? "confirmed" : "unknown", cves: parsed.cves.map((cveId) => ({ cveId, normalizedSeverity: "unknown", publishedAt, modifiedAt: parsed.sourceUpdatedAt })), affectedProducts: parsed.affectedProducts, remediations: parsed.remediations, exploitEvidence };
}

function isDetailEnvelope(value: unknown): value is { feedItem: ParsedFeedItem; details: Array<{ url: string; html: string }> } { return !!value && typeof value === "object" && Array.isArray((value as { details?: unknown }).details) && "feedItem" in value; }
function normalizeIvantiDetails(raw: RawAdvisory, sanitize: (value: unknown) => string | undefined): NormalizedAdvisory {
  const body = raw.body as { feedItem: ParsedFeedItem; details: Array<{ url: string; html: string }> };
  const feed = body.feedItem;
  const parsed = body.details.map((detail) => parseIvantiDetail(detail.html, detail.url));
  const fallback = normalizeIvantiRssItem({ ...raw, body: feed, contentType: "application/rss+xml", resolvedUrl: feed.link }, new Date().toISOString(), sanitize);
  const cves = uniqueBy(parsed.flatMap((detail) => detail.cves), (value) => value).map((cveId) => ({ cveId, normalizedSeverity: "unknown" as const, publishedAt: parsed.find((detail) => detail.cves.includes(cveId))?.publishedAt ?? feed.publishedAt, modifiedAt: parsed.find((detail) => detail.cves.includes(cveId))?.sourceUpdatedAt ?? feed.updatedAt ?? feed.publishedAt }));
  return { ...fallback, title: sanitize(feed.title) ?? feed.title, sourceUrl: raw.resolvedUrl, summary: sanitize(feed.description), publishedAt: feed.publishedAt, sourceUpdatedAt: feed.updatedAt ?? feed.publishedAt, cves, affectedProducts: parsed.flatMap((detail) => detail.affectedProducts), remediations: parsed.flatMap((detail) => detail.remediations), exploitEvidence: fallback.exploitEvidence };
}

function advisoryId(item: ParsedFeedItem): string {
  try { return new URL(item.link).pathname.split("/").filter(Boolean).at(-1) ?? item.id; } catch { return item.id; }
}

function ivantiDetailId(value: string): string { const url = new URL(value); const slug = decodeURIComponent(url.pathname.split("/").filter(Boolean).at(-1) ?? "").trim(); if (!slug) throw new Error(`Ivanti detail URL has no stable ID: ${value}`); return slug; }

function officialPublication(value: string): string | undefined {
  try { const url = new URL(value); return url.origin === IVANTI_ORIGIN && url.pathname.startsWith("/blog/") ? url.toString() : undefined; } catch { return undefined; }
}

function evidenceSentence(value: string, pattern: RegExp): string | undefined {
  return value.split(/(?<=[.!?])\s+/).find((sentence) => pattern.test(sentence))?.slice(0, 500);
}

function normalizeDate(value: string | undefined): string | undefined { if (!value) return undefined; const date = new Date(value); return Number.isFinite(date.getTime()) ? date.toISOString() : undefined; }
function looseCveIds(value: string): string[] { return [...new Set([...value.matchAll(/CVE-\d{4}-\d{4,}/gi)].map((match) => match[0].toUpperCase()))]; }
