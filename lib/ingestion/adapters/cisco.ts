import type { NormalizedAdvisory } from "../../domain/types";
import type { AdvisoryRef, RawAdvisory, SourcePolicy, VendorAdapter } from "../contracts";
import { defaultDiscoveryStart } from "../operational-policy";
import { fetchWithPolicy, readJsonLimited } from "../safety";
import { list, record, stringValue } from "./utils";
import { normalizeCsaf } from "./csaf";

const OPENVULN_ROOT = "https://apix.cisco.com/security/advisories/v2";
const TOKEN_URL = "https://id.cisco.com/oauth2/default/v1/token";
interface CiscoCredentials { clientId?: string; clientSecret?: string; }

export function createCiscoAdapter(credentials: CiscoCredentials = {}): VendorAdapter {
  let tokenCache: { value: string; expiresAt: number } | null = null;
  const accessToken = async (policy: SourcePolicy): Promise<string> => {
    if (tokenCache && tokenCache.expiresAt > Date.now() + 60_000) return tokenCache.value;
    if (!credentials.clientId || !credentials.clientSecret) throw new Error("Cisco ingestion requires CISCO_CLIENT_ID and CISCO_CLIENT_SECRET");
    const body = new URLSearchParams({ client_id: credentials.clientId, client_secret: credentials.clientSecret, grant_type: "client_credentials" });
    const response = await fetchWithPolicy(TOKEN_URL, { ...policy, maxResponseBytes: 100_000 }, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body });
    const payload = record(await readJsonLimited(response, 100_000));
    const value = stringValue(payload.access_token);
    const expiresIn = Number(payload.expires_in ?? 3600);
    if (!value) throw new Error("Cisco OAuth response did not include an access token");
    tokenCache = { value, expiresAt: Date.now() + Math.max(60, Math.min(expiresIn, 3600)) * 1000 };
    return value;
  };

  return {
    vendor: "cisco",
    sourceId: "cisco-psirt-csaf",
    async discover(ctx) {
      const token = await accessToken(ctx.policy);
      const start = defaultDiscoveryStart(ctx.since);
      const end = new Date(ctx.until ?? Date.now());
      const refs = new Map<string, AdvisoryRef>();
      for (const window of dateWindows(start, end, 31)) {
        for (let pageIndex = 1; pageIndex <= 100; pageIndex += 1) {
          const query = new URLSearchParams({ startDate: window.start, endDate: window.end, pageIndex: String(pageIndex), pageSize: "100" });
          const response = await fetchWithPolicy(`${OPENVULN_ROOT}/all/lastpublished?${query}`, ctx.policy, { headers: { accept: "application/json", authorization: `Bearer ${token}` } }, [404]);
          if (response.status === 404) break;
          const payload = record(await readJsonLimited(response, ctx.policy.maxResponseBytes));
          const rows = list(payload.advisories ?? payload);
          for (const value of rows) {
            const row = record(value);
            const id = stringValue(row.advisoryId)?.trim();
            const csafUrl = stringValue(row.csafUrl)?.trim();
            if (!id || !csafUrl || !/^https:\/\/(?:sec\.cloudapps\.cisco\.com|tools\.cisco\.com)\//i.test(csafUrl)) continue;
            const rawUpdated = stringValue(row.lastUpdated);
            const sourceUpdatedAt = rawUpdated && /(?:Z|[+-]\d{2}:?\d{2})$/.test(rawUpdated) && !Number.isNaN(new Date(rawUpdated).getTime()) ? new Date(rawUpdated).toISOString() : undefined;
            refs.set(id, { id, url: csafUrl, sourceUpdatedAt, metadata: { version: String(row.version ?? ""), rawLastUpdated: rawUpdated ?? "", publicationUrl: stringValue(row.publicationUrl) ?? "" } });
          }
          if (rows.length < 100) break;
          if (pageIndex === 100) throw new Error(`Cisco discovery exceeded the 10,000-record paging envelope for ${window.start} through ${window.end}`);
        }
      }
      return [...refs.values()];
    },
    async fetch(ref, ctx) {
      const response = await fetchWithPolicy(ref.url, ctx.policy);
      return { ref, contentType: response.headers.get("content-type") ?? "application/json", body: await readJsonLimited(response, ctx.policy.maxResponseBytes), fetchedAt: new Date().toISOString(), resolvedUrl: response.url, etag: response.headers.get("etag") ?? undefined, lastModified: response.headers.get("last-modified") ?? undefined };
    },
    async normalize(raw, ctx) { return [normalizeCiscoCsaf(raw, ctx.observedAt, ctx.sanitizeText)]; },
  };
}

export const ciscoAdapter = createCiscoAdapter();

export function normalizeCiscoCsaf(raw: RawAdvisory, _observedAt: string, sanitize: (value: unknown) => string | undefined): NormalizedAdvisory {
  return normalizeCsaf(raw, sanitize, { vendor: "cisco", sourceId: "cisco-psirt-csaf", releaseEvent: (publishedAt, sourceUrl) => ({ id: `cisco-security-release-${publishedAt.slice(0, 10)}`, eventType: "security_release", eventDate: publishedAt.slice(0, 10), label: `Cisco security release — ${publishedAt.slice(0, 10)}`, sourceUrl }) })[0];
}

function dateWindows(start: Date, end: Date, days: number): Array<{ start: string; end: string }> {
  const values: Array<{ start: string; end: string }> = [];
  const cursor = new Date(Date.UTC(start.getUTCFullYear(), start.getUTCMonth(), start.getUTCDate()));
  const final = new Date(Date.UTC(end.getUTCFullYear(), end.getUTCMonth(), end.getUTCDate()));
  while (cursor <= final) {
    const windowEnd = new Date(Math.min(final.getTime(), cursor.getTime() + (days - 1) * 86_400_000));
    values.push({ start: cursor.toISOString().slice(0, 10), end: windowEnd.toISOString().slice(0, 10) });
    cursor.setUTCDate(cursor.getUTCDate() + days);
  }
  return values;
}
