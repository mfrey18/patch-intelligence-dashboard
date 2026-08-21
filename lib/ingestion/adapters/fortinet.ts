import type { NormalizedAdvisory } from "../../domain/types";
import type { AdvisoryRef, RawAdvisory, VendorAdapter } from "../contracts";
import { fetchWithPolicy, readJsonLimited, readTextLimited } from "../safety";
import { normalizeCsaf } from "./csaf";
import { feedItemInWindow, parseVendorFeed } from "./rss";

const FEED_URL = "https://filestore.fortinet.com/fortiguard/rss/ir.xml";

export interface FortinetAdapterOptions {
  /** Official Fortinet CSAF export URL containing a literal {id} placeholder. */
  csafUrlTemplate?: string;
  authorization?: string;
}

export function createFortinetAdapter(options: FortinetAdapterOptions = {}): VendorAdapter {
  return {
    vendor: "fortinet",
    sourceId: "fortinet-psirt-csaf",
    async discover(ctx) {
      if (!options.csafUrlTemplate) throw new Error("Fortinet CSAF ingestion requires FORTINET_CSAF_URL_TEMPLATE; the public export is protected by an anti-bot challenge");
      validateTemplate(options.csafUrlTemplate);
      const response = await fetchWithPolicy(FEED_URL, ctx.policy);
      const items = parseVendorFeed(await readTextLimited(response, ctx.policy.maxResponseBytes));
      const refs = new Map<string, AdvisoryRef>();
      for (const item of items.filter((value) => feedItemInWindow(value, ctx.since, ctx.until))) {
        const publication = fortinetPublication(item.link);
        const id = publication?.pathname.split("/").filter(Boolean).at(-1)?.toUpperCase();
        if (!publication || !id || !/^FG-IR-\d{2}-\d+$/i.test(id)) continue;
        refs.set(id, { id, url: options.csafUrlTemplate.replace("{id}", encodeURIComponent(id)), sourceUpdatedAt: item.updatedAt ?? revisedAt(item.description) ?? item.publishedAt, metadata: { publicationUrl: publication.toString() } });
      }
      return [...refs.values()];
    },
    async fetch(ref, ctx) {
      const url = new URL(ref.url);
      if (!isFortinetHost(url.hostname)) throw new Error("Fortinet CSAF URL is outside an official Fortinet origin");
      const headers: Record<string, string> = { accept: "application/json" };
      if (options.authorization) headers.authorization = options.authorization;
      const response = await fetchWithPolicy(url.toString(), ctx.policy, { headers });
      return rawJson(ref, response, await readJsonLimited(response, ctx.policy.maxResponseBytes));
    },
    async normalize(raw, ctx) { return normalizeFortinetCsaf(raw, ctx.observedAt, ctx.sanitizeText); },
  };
}

export const fortinetAdapter = createFortinetAdapter();

export function normalizeFortinetCsaf(raw: RawAdvisory, _observedAt: string, sanitize: (value: unknown) => string | undefined): NormalizedAdvisory[] {
  return normalizeCsaf(raw, sanitize, { vendor: "fortinet", sourceId: "fortinet-psirt-csaf", releaseEvent: (publishedAt, sourceUrl) => ({ id: `fortinet-security-release-${publishedAt.slice(0, 10)}`, eventType: "security_release", eventDate: publishedAt.slice(0, 10), label: `Fortinet security release — ${publishedAt.slice(0, 10)}`, sourceUrl }) });
}

function validateTemplate(value: string): void {
  if (!value.includes("{id}")) throw new Error("FORTINET_CSAF_URL_TEMPLATE must contain {id}");
  const probe = new URL(value.replace("{id}", "FG-IR-00-000"));
  if (probe.protocol !== "https:" || !isFortinetHost(probe.hostname)) throw new Error("FORTINET_CSAF_URL_TEMPLATE must use HTTPS on an official Fortinet host");
}

function isFortinetHost(hostname: string): boolean { return hostname === "fortinet.com" || hostname.endsWith(".fortinet.com"); }
function fortinetPublication(value: string): URL | undefined { try { const url = new URL(value); return isFortinetHost(url.hostname) && url.pathname.startsWith("/psirt/") ? url : undefined; } catch { return undefined; } }
function revisedAt(value?: string): string | undefined { const date = value?.match(/Revised on\s+(\d{4}-\d{2}-\d{2})/i)?.[1]; return date ? new Date(`${date}T00:00:00Z`).toISOString() : undefined; }
function rawJson(ref: AdvisoryRef, response: Response, body: unknown): RawAdvisory { return { ref, contentType: response.headers.get("content-type") ?? "application/json", body, fetchedAt: new Date().toISOString(), resolvedUrl: response.url, etag: response.headers.get("etag") ?? undefined, lastModified: response.headers.get("last-modified") ?? undefined }; }
