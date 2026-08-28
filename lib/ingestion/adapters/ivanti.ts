import type { NormalizedAdvisory, NormalizedExploitEvidence, NormalizedRemediation } from "../../domain/types";
import type { AdvisoryRef, RawAdvisory, VendorAdapter } from "../contracts";
import { fetchWithPolicy, readTextLimited } from "../safety";
import { feedItemInWindow, parseVendorFeed, type ParsedFeedItem } from "./rss";
import { uniqueBy, validCve } from "./utils";

const FEED_URL = "https://www.ivanti.com/blog/topics/security-advisory/rss";
const IVANTI_ORIGIN = "https://www.ivanti.com";

export function createIvantiAdapter(): VendorAdapter {
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
    async discover(ctx) {
      const refs: AdvisoryRef[] = [];
      for (const item of (await load(ctx)).filter((value) => feedItemInWindow(value, ctx.since, ctx.until))) {
        const id = advisoryId(item);
        const publication = officialPublication(item.link);
        if (!id || !publication) continue;
        refs.push({ id, url: publication, sourceUpdatedAt: item.updatedAt ?? item.publishedAt, metadata: { feedUrl: FEED_URL } });
      }
      return refs;
    },
    async fetch(ref, ctx) {
      let item = cache.get(ref.id);
      if (!item) item = (await load(ctx)).find((value) => advisoryId(value) === ref.id);
      if (!item) throw new Error(`Ivanti RSS item ${ref.id} is no longer present in the official feed`);
      return { ref, contentType: "application/rss+xml", body: item, fetchedAt: new Date().toISOString(), resolvedUrl: officialPublication(item.link) ?? ref.url, lastModified: item.updatedAt ?? item.publishedAt };
    },
    async normalize(raw, ctx) { return [normalizeIvantiRssItem(raw, ctx.observedAt, ctx.sanitizeText)]; },
  };
}

export const ivantiAdapter = createIvantiAdapter();

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

function advisoryId(item: ParsedFeedItem): string {
  try { return new URL(item.link).pathname.split("/").filter(Boolean).at(-1) ?? item.id; } catch { return item.id; }
}

function officialPublication(value: string): string | undefined {
  try { const url = new URL(value); return url.origin === IVANTI_ORIGIN && url.pathname.startsWith("/blog/") ? url.toString() : undefined; } catch { return undefined; }
}

function evidenceSentence(value: string, pattern: RegExp): string | undefined {
  return value.split(/(?<=[.!?])\s+/).find((sentence) => pattern.test(sentence))?.slice(0, 500);
}
