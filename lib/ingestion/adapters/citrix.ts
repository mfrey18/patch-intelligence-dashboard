import { load } from "cheerio";
import type { NormalizedAdvisory } from "../../domain/types";
import type { AdvisoryRef, VendorAdapter } from "../contracts";
import { absoluteOfficialUrl, explicitDate, fetchOfficialHtml, loadHtml, read, tableRows, text } from "./html";

const CITRIX_SITEMAP = "https://support.citrix.com/sitemap.xml";
const CITRIX_HOSTS = ["citrix.com", "support.citrix.com", "cloud.com", "netscaler.com"] as const;

export interface CitrixAdapterOptions { detailUrls?: string[]; sitemapUrl?: string; indexUrl?: string; }

/** The general support sitemap supplies candidates, but does not label security bulletins exhaustively. */
export function createCitrixAdapter(options: CitrixAdapterOptions = {}): VendorAdapter {
  const configured = [...new Set(options.detailUrls ?? [])].map(checkedCitrixUrl);
  return {
    vendor: "citrix", sourceId: "citrix-configured-csaf",
    historicalCoverage: configured.length ? "configured_subset" : undefined,
    async discover(ctx) {
      if (configured.length) return configured.map((url) => ({ id: citrixId(url), url }));
      const url = options.sitemapUrl ?? (options.indexUrl ?? CITRIX_SITEMAP);
      const refs = new Map<string, AdvisoryRef>();
      const pending = [{ url, depth: 0 }];
      const visited = new Set<string>();
      let locations = 0;
      while (pending.length) {
        const next = pending.shift()!;
        if (visited.has(next.url)) throw new Error("Citrix sitemap contains a repeated or cyclic child map");
        if (visited.size >= 32 || next.depth > 8) throw new Error("Citrix sitemap traversal exceeded its map/depth limit");
        visited.add(next.url);
        const page = await fetchOfficialHtml(next.url, ctx, CITRIX_HOSTS);
        const document = load(page.html, { xml: true });
        const root = document.root().children().first();
        const kind = root.prop("tagName")?.toLowerCase();
        if (kind === "sitemapindex" || kind === "urlset") {
          if (!new RegExp(`</${kind}\\s*>\\s*$`, "i").test(page.html.trim())) throw new Error("Citrix sitemap is incomplete");
          const entryName = kind === "sitemapindex" ? "sitemap" : "url";
          if (root.children().toArray().some(entry => entry.tagName !== entryName)) throw new Error("Citrix sitemap has unresolved entry types");
          const entries = root.children(entryName).toArray();
          if (kind === "sitemapindex" && !entries.length) throw new Error("Citrix official sitemap did not expose child maps");
          for (const entry of entries) {
            const loc = document(entry).children("loc");
            if (loc.length !== 1 || !loc.text().trim()) throw new Error("Citrix sitemap has an unresolved location");
            const value = absoluteOfficialUrl(page.url, loc.text().trim(), CITRIX_HOSTS);
            if (!value) throw new Error("Citrix sitemap location leaves the approved official hosts");
            if (++locations > 200_000) throw new Error("Citrix sitemap exceeded its location limit");
            if (kind === "sitemapindex") {
              if (visited.size + pending.length >= 32) throw new Error("Citrix sitemap exceeded its map limit");
              pending.push({ url: value, depth: next.depth + 1 });
            } else if (isCitrixDetail(value)) {
              const id = citrixId(value);
              refs.set(id, { id, url: value });
              if (refs.size > 20_000) throw new Error("Citrix sitemap exceeded its advisory limit");
            }
          }
        } else if (next.depth === 0 && options.indexUrl && !options.sitemapUrl && options.indexUrl !== CITRIX_SITEMAP && !/\.xml(?:$|\?)/i.test(page.url)) {
          const html = loadHtml(page.html);
          for (const node of html("a[href]").toArray()) {
            const detail = absoluteOfficialUrl(page.url, html(node).attr("href") ?? "", CITRIX_HOSTS);
            if (!detail || !isCitrixDetail(detail)) continue;
            refs.set(citrixId(detail), { id: citrixId(detail), url: detail });
            if (refs.size > 20_000) throw new Error("Citrix index exceeded its advisory limit");
          }
        } else throw new Error("Citrix sitemap did not resolve to a sitemapindex or urlset");
      }
      if (!refs.size && !options.sitemapUrl && !options.indexUrl) throw new Error("Citrix official sitemap did not expose security bulletin detail links");
      if (!refs.size) throw new Error("Citrix official index did not expose stable security bulletin detail links");
      return [...refs.values()];
    },
    async fetch(ref, ctx) {
      const page = await import("./html").then(({ fetchOfficialHtml }) => fetchOfficialHtml(ref.url, ctx, CITRIX_HOSTS));
      return { ref, contentType: "text/html", body: page.html, fetchedAt: page.fetchedAt, resolvedUrl: page.url, etag: page.etag, lastModified: page.lastModified };
    },
    async normalize(raw, ctx) {
      const html = raw.body as string;
      return isCitrixSecurityBulletin(html) ? [normalizeCitrixHtml(html, raw.resolvedUrl, ctx.sanitizeText)] : [];
    },
  };
}

function isCitrixSecurityBulletin(html: string): boolean {
  const document = loadHtml(html);
  const article = citrixArticle(document);
  const headline = typeof article?.headline === "string" ? article.headline.trim() : "";
  const pageTitle = `${headline} ${text(document, "title") ?? ""} ${text(document, "h1") ?? ""}`;
  if (/access denied|verify (?:you|your)|captcha|just a moment|request blocked/i.test(pageTitle)) throw new Error("Citrix detail is an access challenge");
  if (!article || !headline) throw new Error("Citrix detail lacks classifiable Article metadata");
  const keywords = Array.isArray(article.keywords) ? article.keywords.filter((value): value is string => typeof value === "string").join(" ") : typeof article.keywords === "string" ? article.keywords : "";
  const securityKind = /security[ -]*(?:bulletin|advisory|update)/i;
  if (!securityKind.test(keywords) && /how to|troubleshoot|configuration|configure|best practice|faq|reference|overview/i.test(`${headline} ${keywords}`)) return false;
  if (!securityKind.test(`${headline} ${keywords}`)) {
    if (/security|vulnerab|cve-/i.test(headline) && !/how to|troubleshoot|configuration|configure|best practice|faq|reference|overview/i.test(`${headline} ${keywords}`)) throw new Error("Citrix security article classification is ambiguous");
    return false;
  }
  const content = text(document, "main") ?? text(document, "article") ?? text(document, "body") ?? "";
  if (!looseCveIds(`${headline} ${content}`).length) throw new Error("Citrix security bulletin has no CVE context");
  return true;
}

function citrixArticle(document: ReturnType<typeof loadHtml>): Record<string, unknown> | undefined {
  for (const node of document("script[type='application/ld+json']").toArray()) {
    try {
      const value: unknown = JSON.parse(document(node).text());
      if (value && typeof value === "object" && "@type" in value && value["@type"] === "Article") return value as Record<string, unknown>;
    } catch { /* A later metadata block may contain the Article. */ }
  }
  return undefined;
}

export const citrixAdapter = createCitrixAdapter();

export interface CitrixHtmlDetail {
  vendorAdvisoryId: string;
  title: string;
  sourceUrl: string;
  publishedAt?: string;
  sourceUpdatedAt?: string;
  cves: string[];
  affectedProducts: NormalizedAdvisory["affectedProducts"];
  remediations: NormalizedAdvisory["remediations"];
  preconditions: Array<{ cveId: string; text: string }>;
  revisions: Array<{ text: string }>;
  cveDetails: Record<string, { description?: string; cvssScore?: number; precondition?: string }>;
}

export function parseCitrixDetail(html: string, sourceUrl: string): CitrixHtmlDetail {
  const canonical = checkedCitrixUrl(sourceUrl);
  const document = loadHtml(html);
  const article = citrixArticle(document) ?? {};
  const title = typeof article.headline === "string" ? article.headline : read(document, "meta[property='og:title']", "content") ?? text(document, "h1") ?? read(document, "title");
  if (!title) throw new Error("Citrix detail has no explicit title");
  const body = bodyText(document);
  const cves = looseCveIds(`${title} ${body}`);
  const id = citrixId(canonical);
  const initialPublication = document("table tr").toArray().flatMap(row => {
    const cells = document(row).find("th,td").toArray().map(cell => document(cell).text().replace(/\s+/g, " ").trim());
    if (!cells.some(cell => /^initial publication$/i.test(cell))) return [];
    return cells.flatMap(cell => { const date = explicitDate(cell); return date ? [date] : []; });
  }).sort()[0];
  const publishedAt = initialPublication ?? normalizeDate(typeof article.datePublished === "string" ? article.datePublished : undefined) ?? explicitDate(text(document, "time"));
  const sourceUpdatedAt = normalizeDate(typeof article.dateModified === "string" ? article.dateModified : undefined) ?? publishedAt;
  const product = Array.isArray(article.name) ? article.name.find((value): value is string => typeof value === "string") : typeof article.name === "string" ? article.name : undefined;
  const cveDetails: CitrixHtmlDetail["cveDetails"] = {};
  const preconditions: CitrixHtmlDetail["preconditions"] = [];
  const revisions: CitrixHtmlDetail["revisions"] = [];
  const bulletinRows = [...new Map([...tableRows(document), ...citrixBulletinRows(document)].map((row) => [`${row.headers.join("|")}::${row.cells.join("|")}`, row])).values()];
  for (const row of bulletinRows) {
    const headers = row.headers.map((value) => value.toLowerCase());
    const rowCves = looseCveIds(row.cells.join(" ")); if (rowCves.length !== 1) continue;
    const cveId = rowCves[0];
    const description = row.cells[headers.findIndex((value) => /description/.test(value))] ?? undefined;
    const precondition = row.cells[headers.findIndex((value) => /pre[- ]?conditions?|requirement/.test(value))] ?? undefined;
    const cvssText = row.cells[headers.findIndex((value) => /cvss/.test(value))] ?? "";
    const score = Number(cvssText.match(/base\s+score\s*:\s*(\d+(?:\.\d+)?)/i)?.[1] ?? cvssText.match(/(?:score\s*:\s*)?(\d+(?:\.\d+)?)/i)?.[1]);
    cveDetails[cveId] = { description: clean(description), precondition: clean(precondition), cvssScore: Number.isFinite(score) ? score : undefined };
    if (precondition) preconditions.push({ cveId, text: clean(precondition) ?? precondition });
  }
  for (const match of body.matchAll(/Added the line:\s*["“]?([^"”]+)["”]?/gi)) {
    const revision = clean(match[1]);
    if (revision) revisions.push({ text: revision });
  }
  const affectedProducts: NormalizedAdvisory["affectedProducts"] = product ? [{ name: product, affectedVersion: affectedVersion(body), status: "affected" }] : [];
  const fixedVersions = [...new Set([...body.matchAll(/\b((?:\d+\.){1,3}\d+(?:-[\w.]+)?)\s+and\s+later\b/gi)].map((match) => match[1]))];
  const remediations: NormalizedAdvisory["remediations"] = fixedVersions.map((fixedVersion) => ({ productName: product, kind: "fixed_version", fixedVersion, patchAvailable: true, action: `Upgrade to ${fixedVersion} or later.`, sourceUrl: canonical, publishedAt, updatedAt: sourceUpdatedAt }));
  return { vendorAdvisoryId: id, title, sourceUrl: canonical, publishedAt, sourceUpdatedAt, cves, affectedProducts, remediations, preconditions, revisions, cveDetails };
}

export function normalizeCitrixHtml(html: string, sourceUrl: string, sanitize: (value: unknown) => string | undefined): NormalizedAdvisory {
  const parsed = parseCitrixDetail(html, sourceUrl); const publishedAt = parsed.publishedAt;
  return { vendor: "citrix", sourceId: "citrix-configured-csaf", vendorAdvisoryId: parsed.vendorAdvisoryId, title: sanitize(parsed.title) ?? parsed.title, sourceUrl: parsed.sourceUrl, publishedAt, sourceUpdatedAt: parsed.sourceUpdatedAt, exploitationStatus: "unknown", zeroDayStatus: "unknown", cves: parsed.cves.map((cveId) => ({ cveId, description: parsed.cveDetails[cveId]?.description, cvssScore: parsed.cveDetails[cveId]?.cvssScore, normalizedSeverity: "unknown", publishedAt, modifiedAt: parsed.sourceUpdatedAt })), affectedProducts: parsed.affectedProducts, remediations: parsed.remediations, exploitEvidence: [] };
}

function checkedCitrixUrl(value: string): string { const url = new URL(value); if (url.protocol !== "https:" || !CITRIX_HOSTS.some((host) => url.hostname === host || url.hostname.endsWith(`.${host}`))) throw new Error(`Citrix URL is not an approved official source: ${value}`); return url.toString(); }
function isCitrixDetail(value: string): boolean {
  const path = new URL(value).pathname;
  return /\/external\/article\/(?:CTX)?\d+\//i.test(path) && /(?:secu|vulnerab|cve)/i.test(path);
}
function citrixId(value: string): string { const url = checkedCitrixUrl(value); const match = url.match(/\/external\/article\/(CTX\d+)(?:\/|$)/i) ?? url.match(/\/external\/article\/(\d+)(?:\/|$)/i); if (!match) throw new Error(`Citrix detail URL has no stable article ID: ${value}`); return match[1].toUpperCase().startsWith("CTX") ? match[1].toUpperCase() : `CTX${match[1]}`; }
function normalizeDate(value: string | undefined): string | undefined { if (!value) return undefined; const date = new Date(value); return Number.isFinite(date.getTime()) ? date.toISOString() : undefined; }
function looseCveIds(value: string): string[] { return [...new Set([...value.matchAll(/CVE-\d{4}-\d{4,}/gi)].map((match) => match[0].toUpperCase()))]; }
function clean(value: string | undefined): string | undefined { const result = value?.replace(/\s+/g, " ").trim(); return result || undefined; }
function bodyText(document: ReturnType<typeof loadHtml>): string {
  const html = document("main").html() ?? document("article").html() ?? document("body").html() ?? "";
  return html.replace(/<\/(?:p|li|tr|br)\s*>/gi, " ").replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
}
function affectedVersion(body: string): string | undefined { const values = [...body.matchAll(/\b((?:\d+\.)+\d+\s+(?:BEFORE|before)\s+(?:\d+\.)+\d+(?:-[\w.]+)?)/g)].map((match) => match[1]); return values.length ? values.join("; ") : undefined; }
function citrixBulletinRows(document: ReturnType<typeof loadHtml>): Array<{ cells: string[]; headers: string[] }> {
  for (const table of document("table").toArray()) {
    const rows = document(table).find("tr").toArray().map((row) => document(row).find("th,td").toArray().map((cell) => document(cell).text().replace(/\s+/g, " ").trim())).filter((cells) => cells.length > 0);
    const header = rows[0];
    if (!header || !header.some((value) => /cve[- ]?id/i.test(value))) continue;
    return rows.slice(1).map((cells) => ({ cells, headers: header }));
  }
  return [];
}
