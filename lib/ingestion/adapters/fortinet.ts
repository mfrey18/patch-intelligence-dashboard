import type { NormalizedAdvisory } from "../../domain/types";
import type { AdvisoryRef, RawAdvisory, VendorAdapter } from "../contracts";
import { fetchWithPolicy, readJsonLimited, readTextLimited } from "../safety";
import { normalizeCsaf } from "./csaf";
import { feedItemInWindow, parseVendorFeed } from "./rss";
import { absoluteOfficialUrl, explicitDate, loadHtml, read, severityFromText, tableRows, text } from "./html";

const FEED_URL = "https://filestore.fortinet.com/fortiguard/rss/ir.xml";
const FORTINET_HOSTS = ["fortinet.com", "fortiguard.com"] as const;

export interface FortinetAdapterOptions {
  /** Official Fortinet CSAF export URL containing a literal {id} placeholder. */
  csafUrlTemplate?: string;
  authorization?: string;
  /** Use the official advisory HTML when no configured CSAF URL is supplied. */
  htmlDetails?: boolean;
}

const INDEX_URL = "https://fortiguard.fortinet.com/psirt";

export function createFortinetAdapter(options: FortinetAdapterOptions = {}): VendorAdapter {
  const csafUrlTemplate = options.csafUrlTemplate;
  const useHtml = options.htmlDetails ?? !csafUrlTemplate;
  return {
    vendor: "fortinet",
    sourceId: "fortinet-psirt-csaf",
    historicalCoverage: csafUrlTemplate ? "configured_subset" : "complete_index",
    async discover(ctx) {
      if (csafUrlTemplate) validateTemplate(csafUrlTemplate);
      if (useHtml) return discoverFortinetHtml(ctx);
      const response = await fetchWithPolicy(FEED_URL, ctx.policy);
      const items = parseVendorFeed(await readTextLimited(response, ctx.policy.maxResponseBytes));
      const refs = new Map<string, AdvisoryRef>();
      for (const item of items.filter((value) => feedItemInWindow(value, ctx.since, ctx.until))) {
        const publication = fortinetPublication(item.link);
        const id = publication?.pathname.split("/").filter(Boolean).at(-1)?.toUpperCase();
        if (!publication || !id || !/^FG-IR-\d{2}-\d+$/i.test(id)) continue;
        refs.set(id, { id, url: csafUrlTemplate ? csafUrlTemplate.replace("{id}", encodeURIComponent(id)) : publication.toString(), sourceUpdatedAt: item.updatedAt ?? revisedAt(item.description) ?? item.publishedAt, metadata: { publicationUrl: publication.toString(), representation: csafUrlTemplate ? "csaf" : "html" } });
      }
      return [...refs.values()];
    },
    async discoverPage(ctx, cursor) {
      if (!useHtml) throw new Error("Fortinet paged discovery is only available for the public HTML index");
      const pageUrl = cursor ?? INDEX_URL;
      const page = await import("./html").then(({ fetchOfficialHtml }) => fetchOfficialHtml(pageUrl, ctx, FORTINET_HOSTS));
      const parsed = parseFortinetIndex(page.html, page.url, ctx.since, ctx.until);
      return { refs: parsed.refs, nextCursor: parsed.nextUrl ?? null };
    },
    async fetch(ref, ctx) {
      if (!options.csafUrlTemplate || ref.metadata?.representation === "html") {
        const detail = await import("./html").then(({ fetchOfficialHtml }) => fetchOfficialHtml(ref.url, ctx, FORTINET_HOSTS));
        return { ref, contentType: "text/html", body: detail.html, fetchedAt: detail.fetchedAt, resolvedUrl: detail.url, etag: detail.etag, lastModified: detail.lastModified };
      }
      const url = new URL(ref.url);
      if (!isFortinetHost(url.hostname)) throw new Error("Fortinet CSAF URL is outside an official Fortinet origin");
      const headers: Record<string, string> = { accept: "application/json" };
      if (options.authorization) headers.authorization = options.authorization;
      const response = await fetchWithPolicy(url.toString(), ctx.policy, { headers });
      return rawJson(ref, response, await readJsonLimited(response, ctx.policy.maxResponseBytes));
    },
    async normalize(raw, ctx) { return typeof raw.body === "string" ? [normalizeFortinetHtml(raw.body, raw.resolvedUrl, ctx.sanitizeText)] : normalizeFortinetCsaf(raw, ctx.observedAt, ctx.sanitizeText); },
  };
}

export const fortinetAdapter = createFortinetAdapter();

export const fortinetHtmlAdapter = fortinetAdapter;

export interface FortinetHtmlDetail {
  vendorAdvisoryId: string;
  title: string;
  sourceUrl: string;
  summary?: string;
  publishedAt?: string;
  sourceUpdatedAt?: string;
  vendorSeverity?: string;
  cvssScore?: number;
  cves: string[];
  affectedProducts: NormalizedAdvisory["affectedProducts"];
  remediations: NormalizedAdvisory["remediations"];
  exploitationStatus: NormalizedAdvisory["exploitationStatus"];
}

/** Parses Fortinet's server-rendered PSIRT detail page without executing scripts. */
export function parseFortinetHtml(html: string, sourceUrl: string): FortinetHtmlDetail {
  const document = loadHtml(html);
  const canonical = absoluteOfficialUrl(sourceUrl, read(document, "meta[property='og:url']", "content") ?? sourceUrl, FORTINET_HOSTS);
  if (!canonical) throw new Error("Fortinet detail URL is not official");
  const id = new URL(canonical).pathname.split("/").filter(Boolean).at(-1)?.toUpperCase();
  if (!id || !/^FG-IR-\d{2}-\d+$/i.test(id)) throw new Error("Fortinet detail has no explicit IR number");
  const title = text(document, "h1.title") ?? read(document, "meta[property='og:title']", "content");
  if (!title) throw new Error("Fortinet detail has no explicit title");
  const summaryHeading = document("h2").filter((_index, node) => /^summary$/i.test(document(node).text().trim())).first();
  const summary = summaryHeading.length ? summaryHeading.parent().text().replace(/\s+/g, " ").trim().replace(/^summary\s*/i, "").trim() || undefined : undefined;
  const detailText = text(document, ".content") ?? text(document, "main") ?? text(document, "body") ?? "";
  const cves = looseCveIds(detailText);
  const meta = rowsByLabel(document);
  const publishedAt = fortinetDate(meta.get("published date"));
  const vendorSeverity = meta.get("severity");
  const cvssScore = numberValue(meta.get("cvssv3 score"));
  const known = meta.get("known exploited");
  const exploitationStatus = known && /^yes$/i.test(known) ? "known_exploited" : known && /^(?:no|none)$/i.test(known) ? "not_known_exploited" : "unknown";
  const affectedProducts: NormalizedAdvisory["affectedProducts"] = [];
  const remediations: NormalizedAdvisory["remediations"] = [];
  for (const row of tableRows(document)) {
    const headers = row.headers.map((value) => value.toLowerCase());
    if (headers.length > 0 && row.cells.length === headers.length && row.cells.every((value, index) => value.trim().toLowerCase() === headers[index])) continue;
    const versionIndex = headers.findIndex((value) => /version|product|component/.test(value));
    const affectedIndex = headers.findIndex((value) => /affected|impact/.test(value));
    const solutionIndex = headers.findIndex((value) => /solution|fixed|remediat|upgrade/.test(value));
    if (versionIndex < 0 || (affectedIndex < 0 && solutionIndex < 0)) continue;
    const name = row.cells[versionIndex]?.replace(/\s+/g, " ").trim();
    const affected = affectedIndex >= 0 ? row.cells[affectedIndex]?.replace(/\s+/g, " ").trim() : undefined;
    const solution = solutionIndex >= 0 ? row.cells[solutionIndex]?.replace(/\s+/g, " ").trim() : undefined;
    if (!name || (!affected && !solution)) continue;
    if (isNegativeAssertion(affected)) {
      affectedProducts.push({ name, status: "unaffected" });
      continue;
    }
    const fixedVersion = explicitFortinetFix(solution);
    affectedProducts.push({ name, affectedVersion: affected || undefined, fixedVersion, status: affected ? "affected" : fixedVersion ? "fixed" : "unknown" });
    if (fixedVersion) remediations.push({ productName: name, kind: "fixed_version", fixedVersion, patchAvailable: true, action: solution, sourceUrl: canonical, publishedAt, updatedAt: publishedAt });
  }
  return { vendorAdvisoryId: id, title, sourceUrl: canonical, summary, publishedAt, sourceUpdatedAt: publishedAt, vendorSeverity: severityFromText(vendorSeverity ?? ""), cvssScore, cves, affectedProducts, remediations, exploitationStatus };
}

export function normalizeFortinetHtml(html: string, sourceUrl: string, sanitize: (value: unknown) => string | undefined): NormalizedAdvisory {
  const parsed = parseFortinetHtml(html, sourceUrl);
  const publishedAt = parsed.publishedAt;
  return { vendor: "fortinet", sourceId: "fortinet-psirt-csaf", vendorAdvisoryId: parsed.vendorAdvisoryId, title: sanitize(parsed.title) ?? parsed.title, summary: sanitize(parsed.summary), sourceUrl: parsed.sourceUrl, publishedAt, sourceUpdatedAt: parsed.sourceUpdatedAt, vendorSeverity: parsed.vendorSeverity, cvssScore: parsed.cvssScore, exploitationStatus: parsed.exploitationStatus, zeroDayStatus: "unknown", cves: parsed.cves.map((cveId) => ({ cveId, normalizedSeverity: "unknown", publishedAt, modifiedAt: parsed.sourceUpdatedAt })), affectedProducts: parsed.affectedProducts, remediations: parsed.remediations, exploitEvidence: [] };
}

export function normalizeFortinetCsaf(raw: RawAdvisory, _observedAt: string, sanitize: (value: unknown) => string | undefined): NormalizedAdvisory[] {
  return normalizeCsaf(raw, sanitize, { vendor: "fortinet", sourceId: "fortinet-psirt-csaf", releaseEvent: (publishedAt, sourceUrl) => ({ id: `fortinet-security-release-${publishedAt.slice(0, 10)}`, eventType: "security_release", eventDate: publishedAt.slice(0, 10), label: `Fortinet security release — ${publishedAt.slice(0, 10)}`, sourceUrl }) });
}

function validateTemplate(value: string): void {
  if (!value.includes("{id}")) throw new Error("FORTINET_CSAF_URL_TEMPLATE must contain {id}");
  const probe = new URL(value.replace("{id}", "FG-IR-00-000"));
  if (probe.protocol !== "https:" || !isFortinetHost(probe.hostname)) throw new Error("FORTINET_CSAF_URL_TEMPLATE must use HTTPS on an official Fortinet host");
}

function isFortinetHost(hostname: string): boolean { return FORTINET_HOSTS.some((host) => hostname === host || hostname.endsWith(`.${host}`)); }
function fortinetPublication(value: string): URL | undefined { try { const url = new URL(value); return isFortinetHost(url.hostname) && url.pathname.startsWith("/psirt/") ? url : undefined; } catch { return undefined; } }
function revisedAt(value?: string): string | undefined { const date = value?.match(/Revised on\s+(\d{4}-\d{2}-\d{2})/i)?.[1]; return date ? new Date(`${date}T00:00:00Z`).toISOString() : undefined; }
function rawJson(ref: AdvisoryRef, response: Response, body: unknown): RawAdvisory { return { ref, contentType: response.headers.get("content-type") ?? "application/json", body, fetchedAt: new Date().toISOString(), resolvedUrl: response.url, etag: response.headers.get("etag") ?? undefined, lastModified: response.headers.get("last-modified") ?? undefined }; }
function rowsByLabel(document: ReturnType<typeof loadHtml>): Map<string, string> { const result = new Map<string, string>(); for (const row of tableRows(document)) { if (row.cells.length < 2) continue; result.set(row.cells[0].replace(/\s+/g, " ").trim().toLowerCase(), row.cells.slice(1).join(" ").replace(/\s+/g, " ").trim()); } return result; }
function fortinetDate(value: string | undefined): string | undefined { if (!value) return undefined; return explicitDate(value) ?? (Number.isFinite(Date.parse(value)) ? new Date(value).toISOString() : undefined); }
function numberValue(value: string | undefined): number | undefined { const number = value ? Number(value.match(/\d+(?:\.\d+)?/)?.[0]) : NaN; return Number.isFinite(number) ? number : undefined; }
function looseCveIds(value: string): string[] { return [...new Set([...value.matchAll(/CVE-\d{4}-\d{4,}/gi)].map((match) => match[0].toUpperCase()))]; }
function isNegativeAssertion(value: string | undefined): boolean { return !!value && /^(?:n\/a|na|not\s+(?:affected|applicable)|unaffected|none|unknown|migrate(?:\s+to)?|no\s+fix)$/i.test(value.trim()); }
function explicitFortinetFix(value: string | undefined): string | undefined {
  if (!value || isNegativeAssertion(value)) return undefined;
  const match = value.match(/(?:upgrade|update|fixed|patch)\s+to\s+([\w][\w./-]*)(?:\s+or\s+(?:above|later))?$/i);
  return match?.[1] ?? (/^\d[\w./-]*(?:\s+or\s+(?:above|later))?$/i.test(value.trim()) ? value.replace(/\s+or\s+(?:above|later)$/i, "").trim() : undefined);
}

async function discoverFortinetHtml(ctx: Parameters<VendorAdapter["discover"]>[0]): Promise<AdvisoryRef[]> {
  const refs = new Map<string, AdvisoryRef>();
  let next: string | undefined = INDEX_URL;
  const seen = new Set<string>();
  while (next) {
    if (seen.has(next)) throw new Error("Fortinet PSIRT pagination repeated a page");
    seen.add(next);
    const response = await import("./html").then(({ fetchOfficialHtml }) => fetchOfficialHtml(next!, ctx, FORTINET_HOSTS));
    const parsed = parseFortinetIndex(response.html, response.url, ctx.since, ctx.until);
    for (const ref of parsed.refs) refs.set(ref.id, ref);
    next = parsed.nextUrl;
  }
  if (!refs.size) throw new Error("Fortinet official PSIRT index did not expose advisory detail links");
  return [...refs.values()];
}

export function parseFortinetIndex(html: string, baseUrl: string, since?: string, until?: string): { refs: AdvisoryRef[]; nextUrl?: string; oldestDate?: string } {
  const document = loadHtml(html);
  const refs: AdvisoryRef[] = [];
  let oldestDate: string | undefined;
  for (const match of html.matchAll(/getElementById\(['"](fwb_id_\d+)['"]\)[\s\S]*?location\.href\s*=\s*['"]([^'"]*\/psirt\/FG-IR-\d{2}-\d+)['"]/gi)) {
    const row = document(`#${match[1]}`); const rowText = row.text().replace(/\s+/g, " ").trim();
    const detailUrl = absoluteOfficialUrl(baseUrl, match[2], FORTINET_HOSTS);
    const id = detailUrl ? new URL(detailUrl).pathname.split("/").filter(Boolean).at(-1)?.toUpperCase() : undefined;
    if (!detailUrl || !id || !/^FG-IR-\d{2}-\d+$/i.test(id)) continue;
    const dateText = rowText.match(/Published:\s*([A-Z][a-z]{2}\s+\d{1,2},\s+\d{4})/i)?.[1];
    const publishedAt = dateText ? new Date(`${dateText} UTC`).toISOString() : undefined;
    if (publishedAt && (!oldestDate || publishedAt < oldestDate)) oldestDate = publishedAt;
    if (publishedAt && ((!since || Date.parse(publishedAt) >= Date.parse(since)) && (!until || Date.parse(publishedAt) <= Date.parse(until)))) refs.push({ id, url: detailUrl, sourceUpdatedAt: publishedAt, metadata: { representation: "html", publicationDate: publishedAt } });
  }
  const nextLink = document("a[aria-label='Next'], a[rel='next']").first();
  const nextHref = nextLink.attr("href");
  if (nextLink.length && (!nextHref || !absoluteOfficialUrl(baseUrl, nextHref, FORTINET_HOSTS))) throw new Error("Fortinet PSIRT index exposed a malformed next-page link");
  const nextUrl = nextHref ? absoluteOfficialUrl(baseUrl, nextHref, FORTINET_HOSTS) : undefined;
  return { refs, nextUrl, oldestDate };
}
