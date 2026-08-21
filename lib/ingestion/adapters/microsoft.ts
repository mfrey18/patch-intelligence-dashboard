import type { NormalizedAdvisory } from "../../domain/types";
import type { AdvisoryRef, RawAdvisory, VendorAdapter } from "../contracts";
import { fetchWithPolicy, readJsonLimited, readTextLimited } from "../safety";
import { normalizeCsaf } from "./csaf";

const CSAF_ROOT = "https://api.msrc.microsoft.com/csaf";
const DIRECTORIES = ["advisories", "vex"] as const;

export const microsoftAdapter: VendorAdapter = {
  vendor: "microsoft",
  sourceId: "microsoft-msrc-csaf",
  async discover(ctx) {
    const since = new Date(ctx.since ?? Date.now() - 730 * 24 * 60 * 60 * 1000);
    const until = ctx.until ? new Date(ctx.until) : null;
    const refs: AdvisoryRef[] = [];
    for (const directory of DIRECTORIES) {
      const response = await fetchWithPolicy(`${CSAF_ROOT}/${directory}/changes.csv`, { ...ctx.policy, maxResponseBytes: Math.min(ctx.policy.maxResponseBytes, 6_000_000) });
      const csv = await readTextLimited(response, 6_000_000);
      for (const rawLine of csv.split(/\r?\n/)) {
        if (!rawLine.trim()) continue;
        const match = /^"(\d{4}\/[^"/]+\.json)","([^"]+)"$/.exec(rawLine.trim());
        if (!match) throw new Error(`Microsoft CSAF changes index contains an invalid row: ${rawLine.slice(0, 120)}`);
        const [, relativePath, rawModified] = match;
        const modified = new Date(rawModified);
        if (Number.isNaN(modified.getTime())) throw new Error(`Microsoft CSAF changes index has an invalid timestamp for ${relativePath}`);
        if (modified < since || (until && modified > until)) continue;
        refs.push({ id: `${directory}:${relativePath.slice(0, -5)}`, url: `${CSAF_ROOT}/${directory}/${relativePath}`, sourceUpdatedAt: modified.toISOString(), metadata: { documentType: directory === "vex" ? "vex" : "advisory" } });
      }
    }
    return refs;
  },
  async fetch(ref, ctx) {
    const response = await fetchWithPolicy(ref.url, ctx.policy);
    return { ref, contentType: response.headers.get("content-type") ?? "application/json", body: await readJsonLimited(response, ctx.policy.maxResponseBytes), fetchedAt: new Date().toISOString(), resolvedUrl: response.url, etag: response.headers.get("etag") ?? undefined, lastModified: response.headers.get("last-modified") ?? undefined };
  },
  async normalize(raw, ctx) { return normalizeMicrosoftCsaf(raw, ctx.observedAt, ctx.sanitizeText); },
};

export function normalizeMicrosoftCsaf(raw: RawAdvisory, _observedAt: string, sanitize: (value: unknown) => string | undefined): NormalizedAdvisory[] {
  return normalizeCsaf(raw, sanitize, {
    vendor: "microsoft",
    sourceId: "microsoft-msrc-csaf",
    splitByCve: true,
    advisoryIdPrefix: raw.ref.metadata?.documentType ?? "advisory",
    releaseEvent: (publishedAt, sourceUrl) => isSecondTuesday(publishedAt) ? { id: `microsoft-patch-tuesday-${publishedAt.slice(0, 7)}`, eventType: "patch_tuesday", eventDate: publishedAt.slice(0, 10), label: `${new Intl.DateTimeFormat("en", { month: "long", year: "numeric", timeZone: "UTC" }).format(new Date(publishedAt))} Patch Tuesday`, sourceUrl } : undefined,
  });
}

// Backward-compatible parser export while downstream callers migrate to CSAF naming.
export const normalizeMicrosoftCvrf = normalizeMicrosoftCsaf;

function isSecondTuesday(value: string): boolean {
  const date = new Date(value);
  return date.getUTCDay() === 2 && date.getUTCDate() >= 8 && date.getUTCDate() <= 14;
}
