/** Cloudflare Worker entry point for the vinext-starter template. */
import { handleImageOptimization, DEFAULT_DEVICE_SIZES, DEFAULT_IMAGE_SIZES } from "vinext/server/image-optimization";
import handler from "vinext/server/app-router-entry";
import { queryDashboard } from "../lib/api/dashboard-query";
import { queryCveDetail } from "../lib/api/cve-query";
import { demoDashboard } from "../lib/demo-data";
import { D1IngestionRepository, seedIngestionCatalog } from "../lib/ingestion/d1-repository";
import { ingestionBatchOutcome, runVendorAdapter } from "../lib/ingestion/pipeline";
import { createVendorAdapter, defaultSourceIds, SOURCE_IDS, type AdapterEnvironment } from "../lib/ingestion/source-registry";
import { ingestCisaKev } from "../lib/ingestion/enrichments/cisa";
import { ingestEpssBulk } from "../lib/ingestion/enrichments/epss";
import { constantTimeEqual } from "../lib/ingestion/safety";
import { addPublicCorsHeaders, publicCorsPreflight } from "../lib/api/cors";

interface Env extends AdapterEnvironment {
  ASSETS: Fetcher;
  DB: D1Database;
  INGEST_SECRET?: string;
  PUBLIC_DASHBOARD_ORIGINS?: string;
  CISCO_CLIENT_ID?: string;
  CISCO_CLIENT_SECRET?: string;
  IMAGES: {
    input(stream: ReadableStream): {
      transform(options: Record<string, unknown>): {
        output(options: { format: string; quality: number }): Promise<{ response(): Response }>;
      };
    };
  };
}

interface ExecutionContext {
  waitUntil(promise: Promise<unknown>): void;
  passThroughOnException(): void;
}

// Image security config. SVG sources with .svg extension auto-skip the
// optimization endpoint on the client side (served directly, no proxy).
// To route SVGs through the optimizer (with security headers), set
// dangerouslyAllowSVG: true in next.config.js and uncomment below:
// const imageConfig: ImageConfig = { dangerouslyAllowSVG: true };

const worker = {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const publicApiRoute = url.pathname === "/api/dashboard" || url.pathname.startsWith("/api/cves/");

    if (publicApiRoute && request.method === "OPTIONS") return withSecurityHeaders(publicCorsPreflight(request, env.PUBLIC_DASHBOARD_ORIGINS));

    if (url.pathname === "/api/dashboard" && request.method === "GET") {
      try {
        const dashboard = await queryDashboard(env.DB, url);
        const hasOperationalData = dashboard.sourceHealth.some((source) => source.lastAttempt);
        return json(dashboard.metrics.total === 0 && !hasOperationalData ? demoDashboard : dashboard, 200, request, env);
      } catch {
        return json({ ...demoDashboard, generatedAt: new Date().toISOString(), demo: true, warning: "The intelligence store is awaiting its first successful ingestion." }, 200, request, env);
      }
    }

    if (url.pathname.startsWith("/api/cves/") && request.method === "GET") {
      const cveId = decodeURIComponent(url.pathname.slice("/api/cves/".length));
      try {
        const detail = await queryCveDetail(env.DB, cveId);
        return detail ? json(detail, 200, request, env) : json({ error: "CVE not found" }, 404, request, env);
      } catch { return json({ error: "CVE detail is temporarily unavailable" }, 503, request, env); }
    }

    if (url.pathname === "/api/internal/ingest" && request.method === "POST") return handleIngestion(request, env);

    if (url.pathname === "/_vinext/image") {
      const allowedWidths = [...DEFAULT_DEVICE_SIZES, ...DEFAULT_IMAGE_SIZES];
      return handleImageOptimization(request, {
        fetchAsset: (path) => env.ASSETS.fetch(new Request(new URL(path, request.url))),
        transformImage: async (body, { width, format, quality }) => {
          const result = await env.IMAGES.input(body).transform(width > 0 ? { width } : {}).output({ format, quality });
          return result.response();
        },
      }, allowedWidths);
    }

    const response = await handler.fetch(request, env, ctx);
    return withSecurityHeaders(response);
  },
};

export default worker;

const authFailures = new Map<string, { count: number; resetAt: number }>();

async function handleIngestion(request: Request, env: Env): Promise<Response> {
  if (!env.INGEST_SECRET) return privateJson({ error: "Ingestion is not configured" }, 503);
  const client = request.headers.get("cf-connecting-ip") ?? "unknown";
  const bucket = authFailures.get(client);
  if (bucket && bucket.count >= 8 && bucket.resetAt > Date.now()) return privateJson({ error: "Too many authentication failures" }, 429);
  const supplied = request.headers.get("authorization")?.replace(/^Bearer\s+/i, "") ?? "";
  if (!constantTimeEqual(supplied, env.INGEST_SECRET)) {
    authFailures.set(client, { count: (bucket?.count ?? 0) + 1, resetAt: Date.now() + 60_000 });
    return privateJson({ error: "Unauthorized" }, 401);
  }
  authFailures.delete(client);
  const length = Number(request.headers.get("content-length") ?? 0);
  if (length > 16_384) return privateJson({ error: "Request body is too large" }, 413);
  let body: { sources?: string[]; since?: string; until?: string; idempotencyKey?: string };
  try { body = await request.json(); } catch { return privateJson({ error: "Invalid JSON body" }, 400); }
  const requested = body.sources?.length ? [...new Set(body.sources)] : defaultSourceIds(env);
  if (requested.some((source) => !SOURCE_IDS.has(source))) return privateJson({ error: "Request includes a source outside the ingestion allowlist" }, 400);
  if ((body.since && !validTimestamp(body.since)) || (body.until && !validTimestamp(body.until))) return privateJson({ error: "since and until must be valid ISO-8601 timestamps" }, 400);
  if (body.since && body.until && new Date(body.since) > new Date(body.until)) return privateJson({ error: "since must not be later than until" }, 400);
  try { await seedIngestionCatalog(env.DB); } catch (error) { return privateJson({ error: "Ingestion schema is unavailable", detail: safeError(error) }, 503); }

  const results: unknown[] = [];
  for (const sourceId of requested) {
    const holder = crypto.randomUUID();
    if (!(await acquireLease(env.DB, sourceId, holder))) { results.push({ sourceId, status: "skipped", error: "Source ingestion is already running" }); continue; }
    try {
      const key = body.idempotencyKey ? `${body.idempotencyKey}:${sourceId}` : undefined;
      const adapter = createVendorAdapter(sourceId, env);
      if (adapter) results.push(await runVendorAdapter(adapter, new D1IngestionRepository(env.DB), { since: body.since, until: body.until, idempotencyKey: key }));
      else if (sourceId === "cisa-kev") results.push(await ingestCisaKev(env.DB, key));
      else if (sourceId === "first-epss") results.push(await ingestEpssBulk(env.DB, key));
    } catch (error) { results.push({ sourceId, status: "failed", error: safeError(error) }); }
    finally { await releaseLease(env.DB, sourceId, holder); }
  }
  const outcome = ingestionBatchOutcome(results);
  return privateJson({ completedAt: new Date().toISOString(), status: outcome.status, results }, outcome.httpStatus);
}

async function acquireLease(db: D1Database, sourceId: string, holder: string): Promise<boolean> {
  const now = new Date(); const expires = new Date(now.getTime() + 10 * 60_000);
  await db.prepare("INSERT INTO ingestion_leases (source_id, holder, acquired_at, expires_at) VALUES (?, ?, ?, ?) ON CONFLICT(source_id) DO UPDATE SET holder=excluded.holder, acquired_at=excluded.acquired_at, expires_at=excluded.expires_at WHERE ingestion_leases.expires_at < ?").bind(sourceId, holder, now.toISOString(), expires.toISOString(), now.toISOString()).run();
  const lease = await db.prepare("SELECT holder FROM ingestion_leases WHERE source_id=?").bind(sourceId).first<{ holder: string }>();
  return lease?.holder === holder;
}
async function releaseLease(db: D1Database, sourceId: string, holder: string): Promise<void> { await db.prepare("DELETE FROM ingestion_leases WHERE source_id=? AND holder=?").bind(sourceId, holder).run(); }
function json(value: unknown, status = 200, request?: Request, env?: Env): Response {
  const headers = new Headers({ "content-type": "application/json; charset=utf-8", "cache-control": status === 200 ? "public, max-age=60, stale-while-revalidate=300" : "no-store" });
  if (request && env) addPublicCorsHeaders(headers, request, env.PUBLIC_DASHBOARD_ORIGINS);
  return withSecurityHeaders(new Response(JSON.stringify(value), { status, headers }));
}
function privateJson(value: unknown, status = 200): Response { return withSecurityHeaders(new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" } })); }
function validTimestamp(value: string): boolean { return value.length <= 40 && !Number.isNaN(new Date(value).getTime()) && /^\d{4}-\d{2}-\d{2}T/.test(value); }
function withSecurityHeaders(response: Response): Response { const headers = new Headers(response.headers); headers.set("x-content-type-options", "nosniff"); headers.set("referrer-policy", "strict-origin-when-cross-origin"); headers.set("x-frame-options", "DENY"); headers.set("content-security-policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"); return new Response(response.body, { status: response.status, statusText: response.statusText, headers }); }
function safeError(error: unknown): string { return error instanceof Error ? error.message.slice(0, 500) : "Unknown error"; }
