import type { NormalizedAdvisory } from "../../domain/types";
import type { AdvisoryRef, RawAdvisory, VendorAdapter } from "../contracts";
import { defaultDiscoveryStart } from "../operational-policy";
import { fetchWithPolicy, readJsonLimited } from "../safety";
import { normalizeCsaf } from "./csaf";

const ORACLE_CSAF_ROOT = "https://www.oracle.com/a/tech/docs/security-alerts";
const CPU_MONTHS = [0, 3, 6, 9] as const;
const CPU_NAMES = ["jan", "apr", "jul", "oct"] as const;

export const oracleAdapter: VendorAdapter = {
  vendor: "oracle",
  sourceId: "oracle-cpu-csaf",
  async discover(ctx) {
    const since = defaultDiscoveryStart(ctx.since);
    const until = new Date(ctx.until ?? Date.now());
    const refs: AdvisoryRef[] = [];
    for (const ref of oracleCpuCandidates(since, until)) {
      const response = await fetchWithPolicy(ref.url, { ...ctx.policy, maxResponseBytes: 1_000 }, { method: "HEAD", headers: { accept: "application/json" } }, [404]);
      if (response.status === 404) continue;
      const lastModified = response.headers.get("last-modified") ?? undefined;
      refs.push({ ...ref, sourceUpdatedAt: lastModified && !Number.isNaN(new Date(lastModified).getTime()) ? new Date(lastModified).toISOString() : undefined });
    }
    return refs;
  },
  async fetch(ref, ctx) {
    const response = await fetchWithPolicy(ref.url, ctx.policy, { headers: { accept: "application/json" } });
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
    return [normalizeOracleCsaf(raw, ctx.sanitizeText)];
  },
};

export function normalizeOracleCsaf(raw: RawAdvisory, sanitize: (value: unknown) => string | undefined): NormalizedAdvisory {
  return normalizeCsaf(raw, sanitize, {
    vendor: "oracle",
    sourceId: "oracle-cpu-csaf",
    releaseEvent: (publishedAt, sourceUrl) => ({
      id: `oracle-cpu-${publishedAt.slice(0, 7)}`,
      eventType: "quarterly_cpu",
      eventDate: publishedAt.slice(0, 10),
      label: `Oracle Critical Patch Update — ${publishedAt.slice(0, 10)}`,
      sourceUrl,
    }),
  })[0];
}

export function oracleCpuCandidates(since: Date, until: Date): AdvisoryRef[] {
  if (Number.isNaN(since.getTime()) || Number.isNaN(until.getTime()) || since > until) throw new Error("Oracle discovery requires a valid date range");
  const refs: AdvisoryRef[] = [];
  for (let year = since.getUTCFullYear(); year <= until.getUTCFullYear(); year += 1) {
    CPU_MONTHS.forEach((month, index) => {
      const releaseMonth = new Date(Date.UTC(year, month, 1));
      const monthEnd = new Date(Date.UTC(year, month + 1, 0, 23, 59, 59, 999));
      if (monthEnd < since || releaseMonth > until) return;
      const slug = `cpu${CPU_NAMES[index]}${year}`;
      refs.push({ id: slug, url: `${ORACLE_CSAF_ROOT}/${slug}csaf.json` });
    });
  }
  return refs;
}
