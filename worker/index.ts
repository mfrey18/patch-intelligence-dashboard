/** Cloudflare Worker entry point for the vinext-starter template. */
import { handleImageOptimization, DEFAULT_DEVICE_SIZES, DEFAULT_IMAGE_SIZES } from "vinext/server/image-optimization";
import handler from "vinext/server/app-router-entry";
import { DASHBOARD_ANALYTICS_PANELS, queryDashboard, queryDashboardAnalytics, queryDashboardExport } from "../lib/api/dashboard-query";
import type { DashboardAnalyticsPanel } from "../lib/api/contracts";
import { queryCveDetail } from "../lib/api/cve-query";
import { demoDashboard } from "../lib/demo-data";
import { D1IngestionRepository, seedIngestionCatalog } from "../lib/ingestion/d1-repository";
import { ingestionBatchOutcome, runVendorAdapter } from "../lib/ingestion/pipeline";
import { createVendorAdapter, SOURCE_IDS, type AdapterEnvironment } from "../lib/ingestion/source-registry";
import { advanceCheckpoint, checkpointBatchKey, loadOrCreateCheckpoint, markCheckpointFailed, markCheckpointRunning, type IngestionCheckpoint, type IngestionRequest } from "../lib/ingestion/orchestration";
import { clampBatchSize } from "../lib/ingestion/operational-policy";
import { ingestCisaKev } from "../lib/ingestion/enrichments/cisa";
import { ingestEpssBulk } from "../lib/ingestion/enrichments/epss";
import { constantTimeEqual } from "../lib/ingestion/safety";
import { addPublicCorsHeaders, publicCorsPreflight } from "../lib/api/cors";
import { captureD1ProductionBaseline, pruneRollingRetention } from "../lib/operations/d1-health";
import { refreshDashboardProjection } from "../lib/operations/dashboard-projection";
import { captureOperationalMonitor } from "../lib/operations/operational-monitor";

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
    const publicApiRoute = url.pathname === "/api/dashboard" || url.pathname.startsWith("/api/dashboard/") || url.pathname.startsWith("/api/cves/");

    if (publicApiRoute && request.method === "OPTIONS") return withSecurityHeaders(publicCorsPreflight(request, env.PUBLIC_DASHBOARD_ORIGINS));

    if (url.pathname === "/api/dashboard" && request.method === "GET") {
      return dashboardResponse(request, env, ctx);
    }

    if (url.pathname.startsWith("/api/dashboard/analytics/") && request.method === "GET") {
      return dashboardAnalyticsResponse(request, env, ctx);
    }

    if (url.pathname === "/api/dashboard/export" && request.method === "GET") return dashboardExportResponse(request, env);

    if (url.pathname.startsWith("/api/cves/") && request.method === "GET") {
      const cveId = decodeURIComponent(url.pathname.slice("/api/cves/".length));
      try {
        const detail = await queryCveDetail(env.DB, cveId);
        return detail ? json(detail, 200, request, env) : json({ error: "CVE not found" }, 404, request, env);
      } catch { return json({ error: "CVE detail is temporarily unavailable" }, 503, request, env); }
    }

    if (url.pathname === "/api/internal/ingest" && request.method === "POST") return handleIngestion(request, env);
    if (url.pathname === "/api/internal/health" && request.method === "GET") return handleInternalHealth(request, env);
    if (url.pathname === "/api/internal/retention" && request.method === "POST") return handleRetention(request, env);
    if (url.pathname === "/api/internal/projection" && request.method === "POST") return handleProjection(request, env);
    if (url.pathname === "/api/internal/monitor" && request.method === "GET") return handleMonitor(request, env);

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
  const authError = authorizeInternalRequest(request, env);
  if (authError) return authError;
  const length = Number(request.headers.get("content-length") ?? 0);
  if (length > 16_384) return privateJson({ error: "Request body is too large" }, 413);
  let body: IngestionRequest & { sources?: string[]; idempotencyKey?: string; maxItems?: number; refreshProjection?: boolean };
  try {
    const rawBody = await request.text();
    if (new TextEncoder().encode(rawBody).byteLength > 16_384) return privateJson({ error: "Request body is too large" }, 413);
    body = JSON.parse(rawBody) as typeof body;
  } catch { return privateJson({ error: "Invalid JSON body" }, 400); }
  const requested = [...new Set(body.sources ?? [])];
  if (body.refreshProjection != null && typeof body.refreshProjection !== "boolean") return privateJson({ error: "refreshProjection must be a boolean" }, 400);
  if (requested.length !== 1) return privateJson({ error: "Exactly one source is required per ingestion invocation" }, 400);
  const [sourceId] = requested;
  if (!SOURCE_IDS.has(sourceId)) return privateJson({ error: "Request includes a source outside the ingestion allowlist" }, 400);
  if ((body.since && !validTimestamp(body.since)) || (body.until && !validTimestamp(body.until))) return privateJson({ error: "since and until must be valid ISO-8601 timestamps" }, 400);
  if (body.since && body.until && new Date(body.since) > new Date(body.until)) return privateJson({ error: "since must not be later than until" }, 400);
  try { await seedIngestionCatalog(env.DB); } catch (error) { return privateJson({ error: "Ingestion schema is unavailable", detail: safeError(error) }, 503); }

  const results: unknown[] = [];
  const holder = crypto.randomUUID();
  if (!(await acquireLease(env.DB, sourceId, holder))) return privateJson({ completedAt: new Date().toISOString(), status: "partial", results: [{ sourceId, status: "skipped", error: "Source ingestion is already running" }] }, 207);
  let checkpoint: IngestionCheckpoint | null = null;
  let shouldRefreshProjection = false;
  try {
    const adapter = createVendorAdapter(sourceId, env);
    if (adapter) {
      checkpoint = await loadOrCreateCheckpoint(env.DB, sourceId, body);
      if (checkpoint.status === "complete") return privateJson({ completedAt: new Date().toISOString(), status: "success", results: [{ sourceId, status: "unchanged", checkpoint }] });
      await markCheckpointRunning(env.DB, checkpoint.id);
      const key = body.idempotencyKey ?? checkpointBatchKey(checkpoint);
      const result = await runVendorAdapter(adapter, new D1IngestionRepository(env.DB), {
        since: checkpoint.windowStart, until: checkpoint.windowEnd, idempotencyKey: key,
        mode: checkpoint.mode, continuation: checkpoint.continuation ?? undefined,
        checkpointId: checkpoint.id, maxItems: clampBatchSize(body.maxItems),
      });
      const nextCheckpoint = await advanceCheckpoint(env.DB, checkpoint, result);
      results.push({ ...result, checkpoint: nextCheckpoint });
      shouldRefreshProjection = body.refreshProjection !== false && (checkpoint.mode === "delta" || nextCheckpoint.status === "complete");
    } else {
      if (body.mode && body.mode !== "delta") throw new Error(`${sourceId} is a full-snapshot enrichment and only supports delta synchronization`);
      const key = body.idempotencyKey ?? `${sourceId}:delta:${new Date().toISOString().slice(0, 10)}`;
      if (sourceId === "cisa-kev") results.push(await ingestCisaKev(env.DB, key));
      else if (sourceId === "first-epss") results.push(await ingestEpssBulk(env.DB, key));
      shouldRefreshProjection = body.refreshProjection !== false;
    }
  } catch (error) {
    const message = safeError(error);
    if (checkpoint) await markCheckpointFailed(env.DB, checkpoint.id, message);
    results.push({ sourceId, status: "failed", error: message });
  } finally {
    await releaseLease(env.DB, sourceId, holder);
  }
  const outcome = ingestionBatchOutcome(results);
  let projection: unknown = null;
  if (shouldRefreshProjection) {
    try { projection = await refreshDashboardProjection(env.DB); }
    catch (error) { projection = { status: "failed", error: safeError(error), lastKnownGoodPreserved: true }; }
  }
  const projectionFailed = Boolean(projection && (projection as { status?: string }).status === "failed");
  return privateJson({ completedAt: new Date().toISOString(), status: projectionFailed ? "partial" : outcome.status, results, projection }, projectionFailed ? 207 : outcome.httpStatus);
}

async function dashboardResponse(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const cache = (globalThis as unknown as { caches?: { default?: Cache } }).caches?.default;
  const cacheKey = new Request(request.url, { method: "GET" });
  if (cache) {
    const cached = await cache.match(cacheKey);
    if (cached) return addCorsToResponse(cached, request, env);
  }
  try {
    const dashboard = await queryDashboard(env.DB, new URL(request.url));
    const hasOperationalData = dashboard.sourceHealth.some((source) => source.lastAttempt);
    const value = dashboard.metrics.total === 0 && !hasOperationalData ? demoDashboard : dashboard;
    const response = json(value);
    if (cache && value !== demoDashboard) ctx.waitUntil(cache.put(cacheKey, response.clone()));
    return addCorsToResponse(response, request, env);
  } catch {
    return json({ ...demoDashboard, generatedAt: new Date().toISOString(), demo: true, warning: "The intelligence store is awaiting its first successful ingestion." }, 200, request, env);
  }
}

async function dashboardAnalyticsResponse(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const url = new URL(request.url);
  const panel = decodeURIComponent(url.pathname.slice("/api/dashboard/analytics/".length)) as DashboardAnalyticsPanel;
  if (!DASHBOARD_ANALYTICS_PANELS.has(panel)) return json({ error: "Unknown dashboard analytics panel" }, 404, request, env);
  const cache = (globalThis as unknown as { caches?: { default?: Cache } }).caches?.default;
  const cacheKey = new Request(request.url, { method: "GET" });
  if (cache) {
    const cached = await cache.match(cacheKey);
    if (cached) return addCorsToResponse(cached, request, env);
  }
  try {
    const analytics = await queryDashboardAnalytics(env.DB, url, panel);
    const response = json(analytics, 200, undefined, undefined, analyticsCacheControl(panel));
    if (cache) ctx.waitUntil(cache.put(cacheKey, response.clone()));
    return addCorsToResponse(response, request, env);
  } catch (error) {
    console.error(JSON.stringify({ event: "dashboard_analytics_error", panel, detail: safeError(error) }));
    return json({ error: "Dashboard analytics panel is temporarily unavailable", panel }, 503, request, env);
  }
}

function analyticsCacheControl(panel: DashboardAnalyticsPanel): string {
  const edgeSeconds = panel === "patch-tuesday" ? 3_600 : panel === "epss-movers" ? 900 : panel === "products" ? 600 : 300;
  return `public, max-age=60, s-maxage=${edgeSeconds}, stale-while-revalidate=${edgeSeconds * 2}`;
}

async function dashboardExportResponse(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url); const format = url.searchParams.get("format") ?? "json";
  if (format !== "json" && format !== "csv") return json({ error: "Export format must be csv or json" }, 400, request, env);
  try {
    const exported = await queryDashboardExport(env.DB, url);
    if (format === "json") return json(exported, 200, request, env, "public, max-age=60, stale-while-revalidate=300");
    const header = ["cve_id", "priority", "priority_reasons", "vendor", "product", "severity", "cvss", "epss", "epss_percentile", "kev", "known_exploited", "zero_day", "patch_available", "published_at", "modified_at"];
    const lines = [header, ...exported.rows.map((row) => [row.cveId, row.priority.level, row.priority.reasons.join(" | "), row.vendor, row.product, row.severity, row.cvss, row.epss, row.epssPercentile, row.kev, row.knownExploited, row.zeroDay, row.patchAvailable, row.publishedAt, row.modifiedAt])].map((line) => line.map(csvCell).join(","));
    const headers = new Headers({ "content-type": "text/csv; charset=utf-8", "content-disposition": 'attachment; filename="patch-intelligence-export.csv"', "cache-control": "public, max-age=60, stale-while-revalidate=300", "x-next-cursor": exported.nextCursor ?? "" });
    addPublicCorsHeaders(headers, request, env.PUBLIC_DASHBOARD_ORIGINS);
    return withSecurityHeaders(new Response(lines.join("\r\n"), { headers }));
  } catch { return json({ error: "Dashboard export is temporarily unavailable" }, 503, request, env); }
}

function csvCell(value: unknown): string { const text = value == null ? "" : String(value); return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text; }

async function handleInternalHealth(request: Request, env: Env): Promise<Response> {
  const authError = authorizeInternalRequest(request, env);
  if (authError) return authError;
  try { return privateJson(await captureD1ProductionBaseline(env.DB)); }
  catch (error) { return privateJson({ error: "D1 health baseline failed", detail: safeError(error) }, 503); }
}

async function handleRetention(request: Request, env: Env): Promise<Response> {
  const authError = authorizeInternalRequest(request, env);
  if (authError) return authError;
  try { return privateJson({ completedAt: new Date().toISOString(), ...(await pruneRollingRetention(env.DB)) }); }
  catch (error) { return privateJson({ error: "Rolling retention failed", detail: safeError(error) }, 503); }
}

async function handleProjection(request: Request, env: Env): Promise<Response> {
  const authError = authorizeInternalRequest(request, env);
  if (authError) return authError;
  try { return privateJson(await refreshDashboardProjection(env.DB)); }
  catch (error) { return privateJson({ error: "Dashboard projection refresh failed", detail: safeError(error), lastKnownGoodPreserved: true }, 503); }
}

async function handleMonitor(request: Request, env: Env): Promise<Response> {
  const authError = authorizeInternalRequest(request, env);
  if (authError) return authError;
  try { return privateJson(await captureOperationalMonitor(env.DB)); }
  catch (error) { return privateJson({ error: "Operational monitor failed", detail: safeError(error) }, 503); }
}

function authorizeInternalRequest(request: Request, env: Env): Response | null {
  if (!env.INGEST_SECRET) return privateJson({ error: "Internal operations are not configured" }, 503);
  const client = request.headers.get("cf-connecting-ip") ?? "unknown";
  const bucket = authFailures.get(client);
  if (bucket && bucket.count >= 8 && bucket.resetAt > Date.now()) return privateJson({ error: "Too many authentication failures" }, 429);
  const supplied = request.headers.get("authorization")?.replace(/^Bearer\s+/i, "") ?? "";
  if (!constantTimeEqual(supplied, env.INGEST_SECRET)) {
    authFailures.set(client, { count: (bucket?.count ?? 0) + 1, resetAt: Date.now() + 60_000 });
    return privateJson({ error: "Unauthorized" }, 401);
  }
  authFailures.delete(client);
  return null;
}

async function acquireLease(db: D1Database, sourceId: string, holder: string): Promise<boolean> {
  const now = new Date(); const expires = new Date(now.getTime() + 10 * 60_000);
  await db.prepare("INSERT INTO ingestion_leases (source_id, holder, acquired_at, expires_at) VALUES (?, ?, ?, ?) ON CONFLICT(source_id) DO UPDATE SET holder=excluded.holder, acquired_at=excluded.acquired_at, expires_at=excluded.expires_at WHERE ingestion_leases.expires_at < ?").bind(sourceId, holder, now.toISOString(), expires.toISOString(), now.toISOString()).run();
  const lease = await db.prepare("SELECT holder FROM ingestion_leases WHERE source_id=?").bind(sourceId).first<{ holder: string }>();
  return lease?.holder === holder;
}
async function releaseLease(db: D1Database, sourceId: string, holder: string): Promise<void> { await db.prepare("DELETE FROM ingestion_leases WHERE source_id=? AND holder=?").bind(sourceId, holder).run(); }
function json(value: unknown, status = 200, request?: Request, env?: Env, cacheControl?: string): Response {
  const headers = new Headers({ "content-type": "application/json; charset=utf-8", "cache-control": status === 200 ? cacheControl ?? "public, max-age=60, stale-while-revalidate=300" : "no-store" });
  if (request && env) addPublicCorsHeaders(headers, request, env.PUBLIC_DASHBOARD_ORIGINS);
  return withSecurityHeaders(new Response(JSON.stringify(value), { status, headers }));
}
function addCorsToResponse(response: Response, request: Request, env: Env): Response {
  const headers = new Headers(response.headers);
  addPublicCorsHeaders(headers, request, env.PUBLIC_DASHBOARD_ORIGINS);
  return withSecurityHeaders(new Response(response.body, { status: response.status, statusText: response.statusText, headers }));
}
function privateJson(value: unknown, status = 200): Response { return withSecurityHeaders(new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" } })); }
function validTimestamp(value: string): boolean { return value.length <= 40 && !Number.isNaN(new Date(value).getTime()) && /^\d{4}-\d{2}-\d{2}T/.test(value); }
function withSecurityHeaders(response: Response): Response { const headers = new Headers(response.headers); headers.set("x-content-type-options", "nosniff"); headers.set("referrer-policy", "strict-origin-when-cross-origin"); headers.set("x-frame-options", "DENY"); headers.set("content-security-policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"); return new Response(response.body, { status: response.status, statusText: response.statusText, headers }); }
function safeError(error: unknown): string { return error instanceof Error ? error.message.slice(0, 500) : "Unknown error"; }
