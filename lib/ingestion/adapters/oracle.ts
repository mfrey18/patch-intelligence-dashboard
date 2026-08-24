import type { NormalizedAdvisory } from "../../domain/types";
import type { AdvisoryRef, RawAdvisory, VendorAdapter } from "../contracts";
import { defaultDiscoveryStart } from "../operational-policy";
import { fetchWithPolicy, readJsonLimited } from "../safety";
import { normalizeCsaf } from "./csaf";

const ORACLE_CSAF_ROOT = "https://www.oracle.com/a/tech/docs/security-alerts";
const CPU_MONTHS = [0, 3, 6, 9] as const;
const CPU_NAMES = ["jan", "apr", "jul", "oct"] as const;
const CSPU_MONTHS = [1, 2, 4, 5, 7, 8, 10, 11] as const;
const MONTH_NAMES = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"] as const;
const FIRST_CSPU_YEAR = 2026;

export const oracleAdapter: VendorAdapter = {
  vendor: "oracle",
  sourceId: "oracle-cpu-csaf",
  async discover(ctx) {
    const since = defaultDiscoveryStart(ctx.since);
    const until = new Date(ctx.until ?? Date.now());
    const refs: AdvisoryRef[] = [];
    for (const ref of oracleCsafCandidates(since, until)) {
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
  const isCspu = raw.ref.id.toLowerCase().startsWith("cspu");
  return normalizeCsaf(raw, sanitize, {
    vendor: "oracle",
    sourceId: "oracle-cpu-csaf",
    releaseEvent: (publishedAt, sourceUrl) => ({
      id: `oracle-${isCspu ? "cspu" : "cpu"}-${publishedAt.slice(0, 7)}`,
      eventType: isCspu ? "critical_security_patch_update" : "quarterly_cpu",
      eventDate: publishedAt.slice(0, 10),
      label: `Oracle ${isCspu ? "Critical Security Patch Update" : "Critical Patch Update"} — ${publishedAt.slice(0, 10)}`,
      sourceUrl,
    }),
  })[0];
}

/**
 * Deterministic candidates for Oracle's official CSAF publications. Oracle
 * continues quarterly CPUs and, beginning in May 2026, also publishes CSPUs
 * in the eight intervening months. HEAD checks in discover() fail closed for
 * an announced month whose document has not been published yet.
 */
export function oracleCsafCandidates(since: Date, until: Date): AdvisoryRef[] {
  const refs = oracleCpuCandidates(since, until);
  if (Number.isNaN(since.getTime()) || Number.isNaN(until.getTime()) || since > until) throw new Error("Oracle discovery requires a valid date range");
  for (let year = Math.max(FIRST_CSPU_YEAR, since.getUTCFullYear()); year <= until.getUTCFullYear(); year += 1) {
    for (const month of CSPU_MONTHS) {
      const releaseMonth = new Date(Date.UTC(year, month, 1));
      const monthEnd = new Date(Date.UTC(year, month + 1, 0, 23, 59, 59, 999));
      if (monthEnd < since || releaseMonth > until) continue;
      const slug = `cspu${MONTH_NAMES[month]}${year}`;
      refs.push({ id: slug, url: `${ORACLE_CSAF_ROOT}/${slug}csaf.json` });
    }
  }
  return refs.sort((left, right) => left.id.localeCompare(right.id));
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
