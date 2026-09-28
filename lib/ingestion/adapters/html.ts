import { load, type CheerioAPI } from "cheerio";
import type { FetchContext } from "../contracts";
import { fetchWithPolicy, readTextLimited } from "../safety";

export interface OfficialHtmlResponse {
  html: string;
  url: string;
  fetchedAt: string;
  etag?: string;
  lastModified?: string;
}

export interface HtmlLink {
  href: string;
  text: string;
}

export interface HtmlTableRow {
  cells: string[];
  headers: string[];
}

/** Fetches bounded HTML from an explicitly allowlisted official host. */
export async function fetchOfficialHtml(url: string, ctx: FetchContext, allowedHosts: readonly string[]): Promise<OfficialHtmlResponse> {
  assertOfficialHtmlUrl(url, allowedHosts);
  let current = url;
  let response: Response | undefined;
  for (let hop = 0; hop < 6; hop += 1) {
    // Manual redirects make every hop subject to the official-host policy.
    // Following first and checking only response.url would allow an
    // intermediate redirect through an unapproved host.
    response = await fetchWithPolicy(current, ctx.policy, { headers: { accept: "text/html,application/xhtml+xml" }, redirect: "manual", signal: ctx.signal }, [301, 302, 303, 307, 308], { fetch: ctx.fetch });
    if (![301, 302, 303, 307, 308].includes(response.status)) break;
    const location = response.headers.get("location");
    await response.body?.cancel();
    if (!location) throw new Error(`Official HTML redirect from ${current} has no location`);
    const next = absoluteOfficialUrl(current, location, allowedHosts);
    if (!next || next === current) throw new Error(`Official HTML redirect leaves the allowlisted host: ${location}`);
    current = next;
  }
  if (!response || [301, 302, 303, 307, 308].includes(response.status)) throw new Error("Official HTML redirect chain exceeded six hops");
  const resolvedUrl = response.url || current;
  assertOfficialHtmlUrl(resolvedUrl, allowedHosts);
  return {
    html: await readTextLimited(response, ctx.policy.maxResponseBytes),
    url: resolvedUrl,
    fetchedAt: new Date().toISOString(),
    etag: response.headers.get("etag") ?? undefined,
    lastModified: response.headers.get("last-modified") ?? undefined,
  };
}

export function loadHtml(html: string): CheerioAPI {
  return load(html);
}

/** Read the first matching attribute, or the first matching text value. */
export function read(document: CheerioAPI, selector: string, attribute?: string): string | undefined {
  const node = document(selector).first();
  if (!node.length) return undefined;
  const value = attribute ? node.attr(attribute) : node.text();
  return compact(value);
}

export function text(document: CheerioAPI, selector: string): string | undefined {
  return read(document, selector);
}

export function texts(document: CheerioAPI, selector: string): string[] {
  return document(selector).toArray().map((node) => compact(document(node).text())).filter((value): value is string => Boolean(value));
}

export function links(document: CheerioAPI, selector = "a[href]"): HtmlLink[] {
  return document(selector).toArray().flatMap((node) => {
    const value = compact(document(node).attr("href"));
    if (!value) return [];
    return [{ href: value, text: compact(document(node).text()) ?? "" }];
  });
}

/** Read simple HTML tables without assigning meaning to a vendor's columns. */
export function tableRows(document: CheerioAPI, selector = "table"): HtmlTableRow[] {
  const rows: HtmlTableRow[] = [];
  document(selector).each((_tableIndex, table) => {
    const tableNode = document(table);
    const headers = tableNode.find("thead th").toArray().map((node) => compact(document(node).text()) ?? "");
    const rowSelector = tableNode.find("tbody tr").length ? "tbody tr" : "tr";
    tableNode.find(rowSelector).each((_rowIndex, row) => {
      if (!headers.length && document(row).find("th").length && !document(row).find("td").length) return;
      const cells = document(row).find("th,td").toArray().map((node) => compact(document(node).text()) ?? "");
      if (cells.length) rows.push({ cells, headers });
    });
  });
  return rows;
}

export function absoluteOfficialUrl(base: string, value: string, allowedHosts: readonly string[]): string | undefined {
  try {
    const url = new URL(value, base);
    assertOfficialHtmlUrl(url.toString(), allowedHosts);
    return url.toString();
  } catch {
    return undefined;
  }
}

export function assertOfficialHtmlUrl(value: string, allowedHosts: readonly string[]): void {
  const url = new URL(value);
  const hostname = url.hostname.toLowerCase();
  const allowed = allowedHosts.some((host) => hostname === host || hostname.endsWith(`.${host}`));
  if (url.protocol !== "https:" || url.username || url.password || !allowed) throw new Error(`Official HTML URL is not allowlisted: ${value}`);
}

export function explicitDate(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const numeric = value.match(/\b(20\d{2})[-/](\d{1,2})[-/](\d{1,2})(?:[T\s]+(\d{1,2}):(\d{2})(?::(\d{2}))?(?:Z|\s*UTC)?)?\b/);
  const usNumeric = value.match(/\b(\d{1,2})[/-](\d{1,2})[/-](20\d{2})\b/);
  const textual = value.match(/\b(\d{1,2})\s+(Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+(20\d{2})\b/i)
    ?? value.match(/\b(Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+(\d{1,2}),\s*(20\d{2})\b/i);
  if (!numeric && !usNumeric && !textual) return undefined;
  const months = new Map(["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"].map((month, index) => [month, index + 1]));
  let year: string, month: string, day: string, hour = "00", minute = "00", second = "00";
  if (numeric) {
    [, year, month, day, hour = "00", minute = "00", second = "00"] = numeric;
  } else if (usNumeric) {
    [, month, day, year] = usNumeric;
  } else if (/^\d/.test(textual![1])) {
    [, day, month, year] = textual!;
    month = String(months.get(month.slice(0, 3).toLowerCase()) ?? "");
  } else {
    [, month, day, year] = textual!;
    month = String(months.get(month.slice(0, 3).toLowerCase()) ?? "");
  }
  const date = new Date(`${year}-${month.padStart(2, "0")}-${day.padStart(2, "0")}T${hour.padStart(2, "0")}:${minute}:${second}Z`);
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
}

export function normalizeRefDate(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? explicitDate(value) : date.toISOString();
}

export function inWindow(value: string | undefined, since?: string, until?: string): boolean {
  if (!value) return true;
  const time = Date.parse(value);
  if (!Number.isFinite(time)) return false;
  return (!since || time >= Date.parse(since)) && (!until || time <= Date.parse(until));
}

export function compact(value: string | undefined): string | undefined {
  const result = value?.replace(/\s+/g, " ").trim();
  return result || undefined;
}

export function cveIds(value: string): string[] {
  return [...new Set([...value.matchAll(/\bCVE-\d{4}-\d{4,}\b/gi)].map((match) => match[0].toUpperCase()))];
}

export function severityFromText(value: string): "critical" | "high" | "medium" | "low" | "unknown" {
  const textValue = value.toLowerCase();
  if (textValue.includes("critical")) return "critical";
  if (textValue.includes("high")) return "high";
  if (textValue.includes("medium") || textValue.includes("moderate")) return "medium";
  if (textValue.includes("low")) return "low";
  return "unknown";
}
