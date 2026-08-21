import type { NormalizedAdvisory } from "../../domain/types";
import type { AdvisoryRef, RawAdvisory, VendorAdapter } from "../contracts";
import { fetchWithPolicy, readJsonLimited, readTextLimited } from "../safety";
import { normalizeCsaf } from "./csaf";
import { feedItemInWindow, parseVendorFeed } from "./rss";

const FEED_URL = "https://security.paloaltonetworks.com/rss.xml";
const ADVISORY_ORIGIN = "https://security.paloaltonetworks.com";

export const paloAltoAdapter: VendorAdapter = {
  vendor: "palo-alto",
  sourceId: "palo-alto-psirt-csaf",
  async discover(ctx) {
    const response = await fetchWithPolicy(FEED_URL, ctx.policy);
    const items = parseVendorFeed(await readTextLimited(response, ctx.policy.maxResponseBytes));
    const refs = new Map<string, AdvisoryRef>();
    for (const item of items.filter((value) => feedItemInWindow(value, ctx.since, ctx.until))) {
      const publication = safePublicationUrl(item.link);
      const id = publication?.pathname.split("/").filter(Boolean).at(-1)?.toUpperCase();
      if (!publication || !id || !/^(?:CVE-\d{4}-\d{4,}|PAN-SA-\d{4}-\d+)$/i.test(id)) continue;
      refs.set(id, {
        id,
        url: `${ADVISORY_ORIGIN}/csaf/${encodeURIComponent(id)}`,
        sourceUpdatedAt: item.updatedAt ?? item.publishedAt,
        metadata: { publicationUrl: publication.toString(), feedTitle: item.title },
      });
    }
    return [...refs.values()];
  },
  async fetch(ref, ctx) {
    const url = new URL(ref.url);
    if (url.origin !== ADVISORY_ORIGIN || !url.pathname.startsWith("/csaf/")) throw new Error("Palo Alto CSAF URL is outside the official advisory origin");
    const response = await fetchWithPolicy(url.toString(), ctx.policy, { headers: { accept: "application/json" } });
    return rawJson(ref, response, await readJsonLimited(response, ctx.policy.maxResponseBytes));
  },
  async normalize(raw, ctx) { return normalizePaloAltoCsaf(raw, ctx.observedAt, ctx.sanitizeText); },
};

export function normalizePaloAltoCsaf(raw: RawAdvisory, _observedAt: string, sanitize: (value: unknown) => string | undefined): NormalizedAdvisory[] {
  return normalizeCsaf(raw, sanitize, {
    vendor: "palo-alto",
    sourceId: "palo-alto-psirt-csaf",
    releaseEvent: (publishedAt, sourceUrl) => ({ id: `palo-alto-security-release-${publishedAt.slice(0, 10)}`, eventType: "security_release", eventDate: publishedAt.slice(0, 10), label: `Palo Alto Networks security release — ${publishedAt.slice(0, 10)}`, sourceUrl }),
  });
}

function safePublicationUrl(value: string): URL | undefined {
  try { const url = new URL(value); return url.origin === ADVISORY_ORIGIN ? url : undefined; } catch { return undefined; }
}

async function rawJson(ref: AdvisoryRef, response: Response, body: unknown): Promise<RawAdvisory> {
  return { ref, contentType: response.headers.get("content-type") ?? "application/json", body, fetchedAt: new Date().toISOString(), resolvedUrl: response.url, etag: response.headers.get("etag") ?? undefined, lastModified: response.headers.get("last-modified") ?? undefined };
}
