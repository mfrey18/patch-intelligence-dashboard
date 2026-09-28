import type { NormalizedAdvisory } from "../../domain/types";
import type { RawAdvisory, VendorAdapter } from "../contracts";
import { normalizeCsaf } from "./csaf";
import { createConfiguredCsafAdapter } from "./configured-csaf";
import { absoluteOfficialUrl, explicitDate, loadHtml, read, tableRows, text } from "./html";

export interface SapAdapterOptions {
  /** Explicit SAP-hosted CSAF JSON documents available to the customer's SAP account. */
  csafUrls?: string[];
  bearerToken?: string;
  /** Optional public monthly index; detail pages still require existing SAP access. */
  htmlIndexUrl?: string;
  htmlDetailUrls?: string[];
}

export function createSapAdapter(options: SapAdapterOptions = {}): VendorAdapter {
  if ((!options.csafUrls || options.csafUrls.length === 0) && (options.htmlIndexUrl || options.htmlDetailUrls?.length)) return createSapHtmlAdapter({ indexUrl: options.htmlIndexUrl, detailUrls: options.htmlDetailUrls });
  return createConfiguredCsafAdapter({
    vendor: "sap",
    sourceId: "sap-configured-csaf",
    urls: options.csafUrls,
    bearerToken: options.bearerToken,
    allowedHosts: ["sap.com"],
    missingConfigurationMessage: "SAP Security Notes require SAP for Me entitlement; configure SAP_CSAF_URLS and SAP_CSAF_TOKEN with SAP-hosted machine-readable documents",
  });
}

export const sapAdapter = createSapAdapter();

export interface SapHtmlAdapterOptions { indexUrl?: string; detailUrls?: string[]; }
const SAP_INDEX = "https://support.sap.com/en/my-support/knowledge-base/security-notes-news.html";
const SAP_HOSTS = ["sap.com", "support.sap.com"] as const;

/** Public SAP index discovery with entitled detail-page fetches. */
export function createSapHtmlAdapter(options: SapHtmlAdapterOptions = {}): VendorAdapter {
  const indexUrl = options.indexUrl ?? SAP_INDEX;
  const configured = [...new Set(options.detailUrls ?? [])].map((url) => checkedSapUrl(url));
  return {
    vendor: "sap", sourceId: "sap-configured-csaf", historicalCoverage: configured.length ? "configured_subset" : undefined,
    async discover(ctx) {
      if (configured.length) return configured.map((url) => ({ id: sapNoteId(url), url }));
      const { fetchOfficialHtml } = await import("./html");
      const page = await fetchOfficialHtml(indexUrl, ctx, SAP_HOSTS);
      const document = loadHtml(page.html);
      const monthlyUrls = new Set<string>(document("a[href]").toArray().flatMap((node) => { const href = document(node).attr("href") ?? ""; const url = absoluteOfficialUrl(page.url, href, SAP_HOSTS); return url && /\/security-notes-news\/(?:january|february|march|april|may|june|july|august|september|october|november|december)-20\d{2}\.html$/i.test(new URL(url).pathname) ? [url] : []; }));
      const archiveHref = document("a[href]").toArray().map((node) => document(node).attr("href") ?? "").find((href) => /security-patch-day-archives\.html$/i.test(href));
      if (archiveHref) {
        const archiveUrl = absoluteOfficialUrl(page.url, archiveHref, SAP_HOSTS);
        if (archiveUrl) {
          const archive = await fetchOfficialHtml(archiveUrl, ctx, SAP_HOSTS);
          const archiveDocument = loadHtml(archive.html);
          for (const node of archiveDocument("a[href]").toArray()) {
            const url = absoluteOfficialUrl(archive.url, archiveDocument(node).attr("href") ?? "", SAP_HOSTS);
            if (url && /\/security-notes-news\/(?:january|february|march|april|may|june|july|august|september|october|november|december)-20\d{2}\.html$/i.test(new URL(url).pathname)) monthlyUrls.add(url);
          }
        }
      }
      const refs = new Map<string, { id: string; url: string }>();
      const retainedMonths = [...monthlyUrls].filter((url) => {
        const match = new URL(url).pathname.match(/\/([a-z]+)-(20\d{2})\.html$/i);
        const month = match ? Date.parse(`${match[1]} 1, ${match[2]} UTC`) : NaN;
        if (!Number.isFinite(month)) throw new Error("SAP monthly index contains an invalid month");
        const nextMonth = new Date(month); nextMonth.setUTCMonth(nextMonth.getUTCMonth() + 1);
        return (!ctx.since || nextMonth.getTime() > Date.parse(ctx.since)) && (!ctx.until || month <= Date.parse(ctx.until));
      });
      if (retainedMonths.length > 48) throw new Error("SAP monthly index exceeds the bounded discovery limit");
      for (const monthlyUrl of retainedMonths) {
        const monthly = await fetchOfficialHtml(monthlyUrl, ctx, SAP_HOSTS);
        const monthlyDocument = loadHtml(monthly.html);
        for (const node of monthlyDocument("a[href]").toArray()) {
          const url = absoluteOfficialUrl(monthly.url, monthlyDocument(node).attr("href") ?? "", SAP_HOSTS);
          const id = url ? sapNoteIdOrUndefined(url) : undefined;
          if (id) refs.set(id, { id, url: url! });
        }
      }
      if (!refs.size) throw new Error("SAP public monthly index exposed no entitled security-note links; SAP for Me detail access remains required");
      return [...refs.values()];
    },
    async fetch(ref, ctx) {
      const page = await import("./html").then(({ fetchOfficialHtml }) => fetchOfficialHtml(ref.url, ctx, SAP_HOSTS));
      return { ref, contentType: "text/html", body: page.html, fetchedAt: page.fetchedAt, resolvedUrl: page.url, etag: page.etag, lastModified: page.lastModified };
    },
    async normalize(raw, ctx) { return [normalizeSapHtml(raw.body as string, raw.resolvedUrl, ctx.sanitizeText)]; },
  };
}

export interface SapHtmlDetail {
  vendorAdvisoryId: string;
  title: string;
  sourceUrl: string;
  publishedAt?: string;
  sourceUpdatedAt?: string;
  cves: string[];
  affectedProducts: NormalizedAdvisory["affectedProducts"];
  remediations: NormalizedAdvisory["remediations"];
}

export function parseSapDetail(html: string, sourceUrl: string): SapHtmlDetail {
  const canonical = checkedSapUrl(sourceUrl);
  const document = loadHtml(html);
  const id = sapNoteId(canonical);
  const title = read(document, "meta[property='og:title']", "content") ?? text(document, "h1") ?? read(document, "title");
  if (!title) throw new Error("SAP security note has no explicit title");
  const body = text(document, "main") ?? text(document, "article") ?? text(document, "body") ?? "";
  const cves = looseCveIds(`${title} ${body}`);
  const dates = [read(document, "meta[property='article:published_time']", "content"), read(document, "meta[property='article:modified_time']", "content"), text(document, "time")].map((value) => explicitDate(value ?? undefined) ?? normalizeDate(value ?? undefined)).filter((value): value is string => Boolean(value));
  const affectedProducts: NormalizedAdvisory["affectedProducts"] = [];
  const remediations: NormalizedAdvisory["remediations"] = [];
  for (const row of tableRows(document)) {
    const headers = row.headers.map((value) => value.toLowerCase());
    if (headers.length > 0 && row.cells.length === headers.length && row.cells.every((value, index) => value.trim().toLowerCase() === headers[index])) continue;
    const productIndex = headers.findIndex((value) => /product|component|software/.test(value));
    const affectedIndex = headers.findIndex((value) => /affected|version|impact/.test(value));
    const fixedIndex = headers.findIndex((value) => /correction|fixed|solution|patch|upgrade/.test(value));
    if (productIndex < 0 || (affectedIndex < 0 && fixedIndex < 0)) continue;
    const product = row.cells[productIndex]?.replace(/\s+/g, " ").trim();
    const affected = affectedIndex >= 0 ? row.cells[affectedIndex]?.replace(/\s+/g, " ").trim() : undefined;
    const fixed = fixedIndex >= 0 ? row.cells[fixedIndex]?.replace(/\s+/g, " ").trim() : undefined;
    if (!product || (!affected && !fixed)) continue;
    const rowCves = looseCveIds(row.cells.join(" ")); const cveId = rowCves.length === 1 ? rowCves[0] : undefined;
    affectedProducts.push({ cveId, name: product, affectedVersion: affected, fixedVersion: fixed, status: affected ? "affected" : "fixed" });
    if (fixed) remediations.push({ cveId, productName: product, kind: "fixed_version", fixedVersion: fixed, patchAvailable: true, action: fixed, sourceUrl: canonical, publishedAt: dates[0], updatedAt: dates[1] ?? dates[0] });
  }
  return { vendorAdvisoryId: id, title, sourceUrl: canonical, publishedAt: dates[0], sourceUpdatedAt: dates[1] ?? dates[0], cves, affectedProducts, remediations };
}

export function normalizeSapHtml(html: string, sourceUrl: string, sanitize: (value: unknown) => string | undefined): NormalizedAdvisory {
  const parsed = parseSapDetail(html, sourceUrl); const publishedAt = parsed.publishedAt;
  return { vendor: "sap", sourceId: "sap-configured-csaf", vendorAdvisoryId: parsed.vendorAdvisoryId, title: sanitize(parsed.title) ?? parsed.title, sourceUrl: parsed.sourceUrl, publishedAt, sourceUpdatedAt: parsed.sourceUpdatedAt, exploitationStatus: "unknown", zeroDayStatus: "unknown", cves: parsed.cves.map((cveId) => ({ cveId, normalizedSeverity: "unknown", publishedAt, modifiedAt: parsed.sourceUpdatedAt })), affectedProducts: parsed.affectedProducts, remediations: parsed.remediations, exploitEvidence: [] };
}

function checkedSapUrl(value: string): string { const url = new URL(value); if (url.protocol !== "https:" || !SAP_HOSTS.some((host) => url.hostname === host || url.hostname.endsWith(`.${host}`))) throw new Error(`SAP URL is not an approved official source: ${value}`); return url.toString(); }
function sapNoteId(value: string): string { const id = sapNoteIdOrUndefined(value); if (!id) throw new Error(`SAP URL has no explicit security note ID: ${value}`); return id; }
function sapNoteIdOrUndefined(value: string): string | undefined { try { const url = new URL(value); const match = url.pathname.match(/(?:security[-_ ]?note|note|security-alert)[^/]*[/-](\d{5,10})(?:\.html?)?$/i) ?? url.pathname.match(/\b(\d{7,10})\b/); return match?.[1] ? `SAP-${match[1]}` : undefined; } catch { return undefined; } }
function normalizeDate(value: string | undefined): string | undefined { if (!value) return undefined; const date = new Date(value); return Number.isFinite(date.getTime()) ? date.toISOString() : undefined; }
function looseCveIds(value: string): string[] { return [...new Set([...value.matchAll(/CVE-\d{4}-\d{4,}/gi)].map((match) => match[0].toUpperCase()))]; }

export function normalizeSapCsaf(raw: RawAdvisory, sanitize: (value: unknown) => string | undefined): NormalizedAdvisory {
  return normalizeCsaf(raw, sanitize, { vendor: "sap", sourceId: "sap-configured-csaf" })[0];
}
