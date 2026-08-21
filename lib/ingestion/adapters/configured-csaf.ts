import type { VendorId } from "../../domain/types";
import type { AdvisoryRef, VendorAdapter } from "../contracts";
import { fetchWithPolicy, readJsonLimited } from "../safety";
import { normalizeCsaf } from "./csaf";

export interface ConfiguredCsafOptions {
  vendor: VendorId;
  sourceId: string;
  urls?: string[];
  bearerToken?: string;
  allowedHosts: string[];
  missingConfigurationMessage: string;
}

/**
 * Adapter for authenticated or customer-provisioned vendor CSAF collections.
 * Only explicit document URLs are accepted; this deliberately avoids HTML
 * discovery and does not guess unpublished vendor endpoints.
 */
export function createConfiguredCsafAdapter(options: ConfiguredCsafOptions): VendorAdapter {
  const urls = validateUrls(options.urls ?? [], options.allowedHosts);
  const headers = (): HeadersInit => ({
    accept: "application/json",
    ...(options.bearerToken ? { authorization: `Bearer ${options.bearerToken}` } : {}),
  });

  return {
    vendor: options.vendor,
    sourceId: options.sourceId,
    async discover() {
      if (urls.length === 0) throw new Error(options.missingConfigurationMessage);
      return urls.map((url): AdvisoryRef => ({ id: advisoryId(url), url }));
    },
    async fetch(ref, ctx) {
      const response = await fetchWithPolicy(ref.url, ctx.policy, { headers: headers() });
      return {
        ref,
        contentType: response.headers.get("content-type") ?? "application/json",
        body: await readJsonLimited(response, ctx.policy.maxResponseBytes),
        fetchedAt: new Date().toISOString(),
        resolvedUrl: response.url,
        etag: response.headers.get("etag") ?? undefined,
        lastModified: response.headers.get("last-modified") ?? undefined,
      };
    },
    async normalize(raw, ctx) {
      return normalizeCsaf(raw, ctx.sanitizeText, { vendor: options.vendor, sourceId: options.sourceId });
    },
  };
}

function validateUrls(values: string[], allowedHosts: string[]): string[] {
  return [...new Set(values.map((value) => {
    const url = new URL(value);
    const allowed = allowedHosts.some((host) => url.hostname === host || url.hostname.endsWith(`.${host}`));
    if (url.protocol !== "https:" || !allowed || !/\.json$/i.test(url.pathname)) {
      throw new Error(`Configured CSAF URL is not an approved HTTPS JSON source: ${value}`);
    }
    return url.toString();
  }))];
}

function advisoryId(value: string): string {
  const url = new URL(value);
  return decodeURIComponent(url.pathname.split("/").filter(Boolean).at(-1) ?? url.hostname).replace(/\.json$/i, "");
}
