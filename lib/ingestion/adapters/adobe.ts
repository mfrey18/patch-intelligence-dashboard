import type { NormalizedAdvisory } from "../../domain/types";
import type { AdvisoryRef, RawAdvisory, VendorAdapter } from "../contracts";
import { fetchWithPolicy, readJsonLimited } from "../safety";
import { normalizeCsaf } from "./csaf";
import { iso, list, record, stringValue } from "./utils";

export interface AdobeAdapterOptions {
  /** Official Adobe JSON index. No verified public endpoint exists as of 2026-08-20. */
  indexUrl?: string;
  authorization?: string;
}

export function createAdobeAdapter(options: AdobeAdapterOptions = {}): VendorAdapter {
  return {
    vendor: "adobe",
    sourceId: "adobe-psirt-csaf",
    async discover(ctx) {
      if (!options.indexUrl) throw new Error("Adobe machine-readable ingestion requires ADOBE_SECURITY_INDEX_URL; public PSIRT bulletins are HTML-only and are intentionally not scraped");
      assertAdobeUrl(options.indexUrl, "Adobe security index");
      const headers: Record<string, string> = { accept: "application/json" };
      if (options.authorization) headers.authorization = options.authorization;
      const response = await fetchWithPolicy(options.indexUrl, ctx.policy, { headers });
      const payload = await readJsonLimited(response, ctx.policy.maxResponseBytes);
      const entries = list(record(payload).advisories ?? payload);
      const refs = new Map<string, AdvisoryRef>();
      for (const value of entries) {
        const entry = record(value);
        const id = stringValue(entry.id ?? entry.advisory_id)?.trim().toUpperCase();
        const url = stringValue(entry.csaf_url ?? entry.url)?.trim();
        const sourceUpdatedAt = iso(entry.updated_at ?? entry.current_release_date);
        if (!id || !/^APSB\d{2}-\d+$/i.test(id) || !url) continue;
        assertAdobeUrl(url, "Adobe CSAF advisory");
        const timestamp = sourceUpdatedAt ? new Date(sourceUpdatedAt).getTime() : undefined;
        if (timestamp != null && ctx.since && timestamp < new Date(ctx.since).getTime()) continue;
        if (timestamp != null && ctx.until && timestamp > new Date(ctx.until).getTime()) continue;
        refs.set(id, { id, url, sourceUpdatedAt });
      }
      return [...refs.values()];
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

export const adobeAdapter = createAdobeAdapter();

export function normalizeAdobeCsaf(raw: RawAdvisory, _observedAt: string, sanitize: (value: unknown) => string | undefined): NormalizedAdvisory[] {
  return normalizeCsaf(raw, sanitize, { vendor: "adobe", sourceId: "adobe-psirt-csaf", releaseEvent: (publishedAt, sourceUrl) => ({ id: `adobe-security-release-${publishedAt.slice(0, 10)}`, eventType: "security_release", eventDate: publishedAt.slice(0, 10), label: `Adobe security release — ${publishedAt.slice(0, 10)}`, sourceUrl }) });
}

function assertAdobeUrl(value: string, label: string): void {
  const url = new URL(value);
  if (url.protocol !== "https:" || !(url.hostname === "adobe.com" || url.hostname.endsWith(".adobe.com"))) throw new Error(`${label} must use HTTPS on an official Adobe host`);
}
