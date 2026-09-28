import type { Database } from "../db/database";
import type { ResponseCache } from "./cache";
import { DASHBOARD_ANALYTICS_PANELS, queryDashboard, queryDashboardAnalytics, queryDashboardExport } from "../lib/api/dashboard-query";
import type { DashboardAnalyticsPanel } from "../lib/api/contracts";
import { queryCveDetail } from "../lib/api/cve-query";
import { PostgresIngestionRepository, seedIngestionCatalog } from "../lib/ingestion/postgres-repository";
import { ingestionBatchOutcome, runVendorAdapter } from "../lib/ingestion/pipeline";
import { createVendorAdapter, SOURCE_IDS, type AdapterEnvironment } from "../lib/ingestion/source-registry";
import { advanceCheckpoint, checkpointBatchKey, isScheduledSourceRequest, loadOrCreateCheckpoint, markCheckpointFailed, markCheckpointRunning, validateScheduledScope, type IngestionCheckpoint, type IngestionRequest } from "../lib/ingestion/orchestration";
import { leasedSourceDatabase, runSourceOperation, SourceBudgetExpired, SourceLeaseLost } from "../lib/ingestion/source-execution";
import { sourceProgress } from "../lib/ingestion/source-completion";
import { clampBatchSize } from "../lib/ingestion/operational-policy";
import { ingestCveEnrichment } from "../lib/ingestion/enrichments/cve";
import { ingestVulnCheck } from "../lib/ingestion/enrichments/vulncheck";
import { ingestCisaKev } from "../lib/ingestion/enrichments/cisa";
import { ingestEpssBulk } from "../lib/ingestion/enrichments/epss";
import { constantTimeEqual } from "../lib/ingestion/safety";
import { addPublicCorsHeaders, publicCorsPreflight } from "../lib/api/cors";
import { capturePostgresProductionBaseline, pruneRollingRetention } from "../lib/operations/postgres-health";
import { refreshDashboardProjection } from "../lib/operations/dashboard-projection";
import { captureOperationalMonitor } from "../lib/operations/operational-monitor";

export interface Env extends AdapterEnvironment {
  DB: Database;
  cache: ResponseCache;
  INGEST_SECRET?: string;
  PUBLIC_DASHBOARD_ORIGINS?: string;
}

interface ExecutionContext {
  waitUntil(promise: Promise<unknown>): void;
  passThroughOnException(): void;
}

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

    if (url.pathname === "/api/internal/sources" && request.method === "GET") {
      const error=authorizeInternalRequest(request,env); if(error)return error;
      await seedIngestionCatalog(env.DB);
      const sources=await sourceProgress(env.DB);
      return privateJson({sources:sources.map(source=>{
        let historicalCoverage='unverified';
        try {historicalCoverage=createVendorAdapter(String(source.id),env)?.historicalCoverage??'unverified';}catch { /* Missing configuration stays explicitly unverified. */ }
        return {...source,historicalCoverage};
      })});
    }
    if (url.pathname === "/api/internal/ingest" && request.method === "POST") return handleIngestion(request, env);
    if (url.pathname === "/api/internal/health" && request.method === "GET") return handleInternalHealth(request, env);
    if (url.pathname === "/api/internal/retention" && request.method === "POST") return handleRetention(request, env);
    if (url.pathname === "/api/internal/projection" && request.method === "POST") return handleProjection(request, env);
    if (url.pathname === "/api/internal/monitor" && request.method === "GET") return handleMonitor(request, env);

    return json({ error: "Not found" }, 404);

  },
};

export async function handleApi(request: Request, env: Env, access: "public" | "private"): Promise<Response> {
  const path = new URL(request.url).pathname;
  if ((access === "public" && path.startsWith("/api/internal/")) || (access === "private" && !path.startsWith("/api/internal/"))) return json({ error: "Not found" },404);
  try { return await worker.fetch(request, env, { waitUntil(promise) { void promise.catch(() => {}); }, passThroughOnException() {} }); }
  catch { return json({ error: "Service temporarily unavailable" },503); }
}

const authFailures = new Map<string, { count: number; resetAt: number }>();

async function handleIngestion(request: Request, env: Env): Promise<Response> {
  const authError = authorizeInternalRequest(request, env);
  if (authError) return authError;
  const length = Number(request.headers.get("content-length") ?? 0);
  if (length > 16_384) return privateJson({ error: "Request body is too large" }, 413);
  let body: IngestionRequest & { sources?: string[]; idempotencyKey?: string; maxItems?: number; refreshProjection?: boolean; budgetMs?: number; invocationStartedAt?: string };
  try {
    const rawBody = await request.text();
    if (new TextEncoder().encode(rawBody).byteLength > 16_384) return privateJson({ error: "Request body is too large" }, 413);
    body = JSON.parse(rawBody) as typeof body;
  } catch { return privateJson({ error: "Invalid JSON body" }, 400); }
  if (!body || !Array.isArray(body.sources) || body.sources.some(value=>typeof value!=="string")) return privateJson({error:"sources must be an array of source identifiers"},400);
  if (body.budgetMs != null && (!Number.isFinite(body.budgetMs) || body.budgetMs<=0)) return privateJson({error:"budgetMs must be positive"},400);
  const requested = [...new Set(body.sources ?? [])];
  if (body.refreshProjection != null && typeof body.refreshProjection !== "boolean") return privateJson({ error: "refreshProjection must be a boolean" }, 400);
  if (body.scheduled != null && typeof body.scheduled !== "boolean") return privateJson({ error: "scheduled must be a boolean" }, 400);
  if (requested.length !== 1) return privateJson({ error: "Exactly one source is required per ingestion invocation" }, 400);
  const [sourceId] = requested;
  if (!SOURCE_IDS.has(sourceId)) return privateJson({ error: "Request includes a source outside the ingestion allowlist" }, 400);
  try { validateScheduledScope(sourceId, body, body.mode ?? "delta"); }
  catch (error) { return privateJson({ error: safeError(error) }, 400); }
  if ((body.since && !validTimestamp(body.since)) || (body.until && !validTimestamp(body.until))) return privateJson({ error: "since and until must be valid ISO-8601 timestamps" }, 400);
  if (body.since && body.until && new Date(body.since) > new Date(body.until)) return privateJson({ error: "since must not be later than until" }, 400);
  try { await seedIngestionCatalog(env.DB); } catch (error) { return privateJson({ error: "Ingestion schema is unavailable", detail: safeError(error) }, 503); }

  const results: unknown[] = [];
  const holder = crypto.randomUUID();
  const scheduledSource = isScheduledSourceRequest(sourceId, body);
  if (!(await acquireLease(env.DB, sourceId, holder))) return privateJson({ completedAt: new Date().toISOString(), status: scheduledSource ? "pending" : "partial", results: [{ sourceId, status: scheduledSource ? "pending" : "skipped", ...(scheduledSource ? { reason: "Source ingestion is already running" } : { error: "Source ingestion is already running" }) }] }, scheduledSource ? 202 : 207);
  let checkpoint: IngestionCheckpoint | null = null;
  let shouldRefreshProjection = false;
  const sourceDb=leasedSourceDatabase(env.DB,sourceId,holder);
  const budgetMs=Math.max(1,Math.min(body.budgetMs ?? 90_000, 9*60_000));
  try {
    await runSourceOperation(budgetMs,request.signal,async()=>{
    // Obtaining a new holder fences every previous invocation. Recover its
    // unfinished batch immediately instead of waiting on the old run's timer.
    await sourceDb.prepare(`UPDATE source_runs r SET status='partial',completed_at=now(),bound_hit=TRUE,
      continuation_out=continuation_in,idempotency_key=NULL,
      records_failed=(SELECT COUNT(*) FROM source_run_results rr WHERE rr.source_run_id=r.id AND rr.status='failed'),
      error_summary=COALESCE(error_summary,'Interrupted source batch recovered under a new lease')
      WHERE source_id=? AND status='running'`).bind(sourceId).run();
    const readiness=await sourceDb.prepare("SELECT readiness,retry_after FROM sources WHERE id=?").bind(sourceId).first<{readiness:string;retry_after:string|null}>();
    if(readiness?.retry_after && Date.parse(readiness.retry_after)>Date.now()) {
      results.push({ sourceId, status: scheduledSource ? "pending" : "skipped", reason: "Source cooldown", retryAfter: readiness.retry_after });
    } else if(readiness?.readiness==="paused") {
      results.push({ sourceId, status: scheduledSource ? "pending" : "skipped", reason: "Source is paused" });
    } else {
      const adapter = createVendorAdapter(sourceId, env);
      if (adapter) {
        checkpoint = await loadOrCreateCheckpoint(sourceDb, sourceId, body, new Date(), {historicalCoverage:adapter.historicalCoverage==='complete_index'});
        if (checkpoint.status === "complete") { results.push({ sourceId, status: "unchanged", checkpoint }); return; }
        await markCheckpointRunning(sourceDb, checkpoint.id);
        const key = scheduledSource ? checkpointBatchKey(checkpoint) : body.idempotencyKey ?? checkpointBatchKey(checkpoint, body.checkpointId);
        const result = await runVendorAdapter(adapter, new PostgresIngestionRepository(sourceDb), {
          since: checkpoint.windowStart, until: checkpoint.windowEnd, idempotencyKey: key,
          mode: checkpoint.mode, continuation: checkpoint.continuation ?? undefined,
          checkpointId: checkpoint.id, discoveryGeneration: scheduledSource ? checkpoint.id : body.checkpointId, maxItems: scheduledSource ? (["microsoft-msrc-csaf", "palo-alto-psirt-csaf", "mozilla-mfsa-yaml"].includes(sourceId) ? 12 : 1) : clampBatchSize(body.maxItems),
        });
        const nextCheckpoint = await advanceCheckpoint(sourceDb, checkpoint, result, {historicalCoverage:adapter.historicalCoverage==='complete_index'});
        const status = scheduledSource && nextCheckpoint.status === "pending" && result.counts.failed === 0 && result.status !== "failed" ? "pending" : result.counts.failed > 0 || result.status === "failed" ? "failed" : result.status;
        const retry = result.counts.failed > 0 ? await sourceDb.prepare("SELECT retry_after FROM sources WHERE id=?").bind(sourceId).first<{ retry_after: string | null }>() : null;
        results.push({ ...result, status, ...(retry?.retry_after ? { retryAfter: retry.retry_after } : {}), checkpoint: nextCheckpoint });
        shouldRefreshProjection = body.refreshProjection !== false && (checkpoint.mode === "delta" || nextCheckpoint.status === "complete");
      } else {
        if (body.mode && body.mode !== "delta") throw new Error(`${sourceId} is a full-snapshot enrichment and only supports delta synchronization`);
        const key = body.idempotencyKey ?? (scheduledSource ? `${sourceId}:scheduled:${new Date().toISOString()}` : `${sourceId}:delta:${new Date().toISOString().slice(0, 10)}`);
        if (sourceId === "cisa-kev") results.push(await ingestCisaKev(sourceDb, key));
        else if (sourceId === "first-epss") results.push(await ingestEpssBulk(sourceDb, key));
        else if (sourceId === "vulncheck-kev") results.push(await ingestVulnCheck(sourceDb, env.VULNCHECK_API_TOKEN, key));
        else if (sourceId === "cve-list-v5" || sourceId === "nvd-cve") results.push(await ingestCveEnrichment(sourceDb, sourceId, env.NVD_API_KEY, scheduledSource ? undefined : body.idempotencyKey));
        else throw new Error("Source has no usable adapter");
        shouldRefreshProjection = body.refreshProjection !== false;
      }
    }
    });
  } catch (error) {
    const message = safeError(error);
    const interruptedCheckpoint=checkpoint as IngestionCheckpoint | null;
    if (error instanceof SourceBudgetExpired || error instanceof SourceLeaseLost) {
      // Release interrupted idempotency claims without losing completed item writes.
      // This cleanup is itself fenced; a new holder must never be overwritten.
      let interruptedFailures=0;
      try { await sourceDb.transaction(async tx=>{
        const interrupted=await tx.prepare(`UPDATE source_runs r SET status='partial',completed_at=now(),bound_hit=TRUE,
          continuation_out=continuation_in,idempotency_key=NULL,error_summary=?,
          records_failed=(SELECT COUNT(*) FROM source_run_results rr WHERE rr.source_run_id=r.id AND rr.status='failed')
          WHERE source_id=? AND status='running' RETURNING records_failed`).bind(message,sourceId).all<{records_failed:number}>();
        interruptedFailures=interrupted.results.reduce((total,row)=>total+Number(row.records_failed),0);
        if(interruptedCheckpoint) await tx.prepare("UPDATE ingestion_checkpoints SET status=?,updated_at=now() WHERE id=? AND status='running'").bind(interruptedFailures?'failed':'pending',interruptedCheckpoint.id).run();
      }); } catch { /* the replacement lease holder owns recovery */ }
      results.push({sourceId,status:interruptedFailures?'failed':'pending',reason:message,counts:{failed:interruptedFailures},...(interruptedCheckpoint?{checkpoint:{...interruptedCheckpoint,status:interruptedFailures?'failed':'pending'}}:{})});
    } else {
      if (interruptedCheckpoint) { try { await markCheckpointFailed(sourceDb, interruptedCheckpoint.id, message); } catch { /* lease fencing takes precedence */ } }
      const retry = await env.DB.prepare("SELECT retry_after FROM sources WHERE id=?").bind(sourceId).first<{ retry_after: string | null }>();
      results.push({ sourceId, status: "failed", error: message, ...(retry?.retry_after ? { retryAfter: retry.retry_after } : {}) });
    }
  } finally {
    await releaseLease(env.DB, sourceId, holder);
  }
  if (scheduledSource && results.length) {
    const run=results[0] as {status:string;counts?:{failed?:number};boundHit?:boolean;continuation?:string;retryAfter?:string;checkpoint?:IngestionCheckpoint;progress?:unknown};
    const state=(await sourceProgress(env.DB,sourceId))[0] as Record<string,unknown> | undefined;
    const complete=await env.DB.prepare("SELECT owner_id,coverage_end,completed_at FROM source_completion_evidence WHERE source_id=? AND kind IN ('delta','initial_enrichment') ORDER BY coverage_end DESC,completed_at DESC LIMIT 1").bind(sourceId).first<{owner_id:string;coverage_end:string;completed_at:string}>();
    const failed=run.status==='failed'||Boolean(run.counts?.failed);
    const pending=!failed && (run.status==='pending'||run.status==='skipped'||run.boundHit||run.checkpoint?.status==='pending'||run.checkpoint?.status==='running'||Boolean(state?.enrichment_cycle_id)||(!run.checkpoint&&!complete));
    run.progress={state:failed?'failed':pending?'pending':complete?'complete':'pending',
      ownerId:run.checkpoint?.id??state?.enrichment_cycle_id??complete?.owner_id??null,
      position:run.checkpoint ? `${run.checkpoint.id}:${run.checkpoint.windowStart}:${run.checkpoint.continuation??'start'}:${run.checkpoint.status}` : run.continuation??null,
      coverageEnd:run.checkpoint?.coverageEnd??complete?.coverage_end??null,
      retryAt:run.retryAfter??state?.retry_after??null};
    if(pending && run.status!=='failed')run.status='pending';
  }
  const outcome = ingestionBatchOutcome(results);
  let projection: unknown = null;
  if (shouldRefreshProjection) {
    try {
      projection = await refreshDashboardProjection(env.DB);
      await invalidateAnalyticsCaches(env);
    }
    catch (error) { projection = { status: "failed", error: safeError(error), lastKnownGoodPreserved: true }; }
  }
  const projectionFailed = Boolean(projection && (projection as { status?: string }).status === "failed");
  return privateJson({ completedAt: new Date().toISOString(), status: projectionFailed ? "partial" : outcome.status, results, projection }, projectionFailed ? 207 : outcome.httpStatus);
}

async function dashboardResponse(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const cache = env.cache;
  const cacheEpoch = cache.epoch;
  const cacheKey = new Request(request.url, { method: "GET" });
  if (cache) {
    const cached = await cache.match(cacheKey);
    if (cached) return addCorsToResponse(cached, request, env);
  }
  try {
    const dashboard = await queryDashboard(env.DB, new URL(request.url));
    const value = dashboard;
    const response = json(value);
    if (cache) ctx.waitUntil(cache.put(cacheKey, response.clone(), cacheEpoch));
    return addCorsToResponse(response, request, env);
  } catch (error) {
    console.error(JSON.stringify({ event: "dashboard_query_error", detail: safeError(error) }));
    return json({ error: "Dashboard intelligence is temporarily unavailable" }, 503, request, env);
  }
}

async function dashboardAnalyticsResponse(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const url = new URL(request.url);
  const panel = decodeURIComponent(url.pathname.slice("/api/dashboard/analytics/".length)) as DashboardAnalyticsPanel;
  if (!DASHBOARD_ANALYTICS_PANELS.has(panel)) return json({ error: "Unknown dashboard analytics panel" }, 404, request, env);
  const cache = env.cache;
  const cacheEpoch = cache.epoch;
  const cacheKey = new Request(request.url, { method: "GET" });
  if (cache) {
    const cached = await cache.match(cacheKey);
    if (cached) return addCorsToResponse(cached, request, env);
  }
  try {
    const analytics = await queryDashboardAnalytics(env.DB, url, panel);
    const response = json(analytics, 200, undefined, undefined, analyticsCacheControl(panel));
    if (cache) ctx.waitUntil(cache.put(cacheKey, response.clone(), cacheEpoch));
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
    const header = ["cve_id", "priority", "priority_reasons", "vendor", "product", "severity", "cvss", "epss", "epss_percentile", "kev", "known_exploited", "zero_day", "patch_available", "published_at", "modified_at", "vulncheck", "exploitation_sources", "assessment_source"];
    const lines = [header, ...exported.rows.map((row) => [row.cveId, row.priority.level, row.priority.reasons.join(" | "), row.vendor, row.product, row.severity, row.cvss, row.epss, row.epssPercentile, row.kev, row.knownExploited, row.zeroDay, row.patchAvailable, row.publishedAt, row.modifiedAt, row.vulncheck, row.exploitationSources?.join(" | "), row.assessmentSource])].map((line) => line.map(csvCell).join(","));
    const headers = new Headers({ "content-type": "text/csv; charset=utf-8", "content-disposition": 'attachment; filename="patch-intelligence-export.csv"', "cache-control": "public, max-age=60, stale-while-revalidate=300", "x-next-cursor": exported.nextCursor ?? "" });
    addPublicCorsHeaders(headers, request, env.PUBLIC_DASHBOARD_ORIGINS);
    return withSecurityHeaders(new Response(lines.join("\r\n"), { headers }));
  } catch { return json({ error: "Dashboard export is temporarily unavailable" }, 503, request, env); }
}

function csvCell(value: unknown): string { const text = value == null ? "" : String(value); return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text; }

async function handleInternalHealth(request: Request, env: Env): Promise<Response> {
  const authError = authorizeInternalRequest(request, env);
  if (authError) return authError;
  try { return privateJson(await capturePostgresProductionBaseline(env.DB)); }
  catch (error) { return privateJson({ error: "PostgreSQL health baseline failed", detail: safeError(error) }, 503); }
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
  try {
    const result = await refreshDashboardProjection(env.DB);
    await invalidateAnalyticsCaches(env);
    return privateJson(result);
  }
  catch (error) { return privateJson({ error: "Dashboard projection refresh failed", detail: safeError(error), lastKnownGoodPreserved: true }, 503); }
}

async function invalidateAnalyticsCaches(env: Env): Promise<void> { env.cache.clear(); }

async function handleMonitor(request: Request, env: Env): Promise<Response> {
  const authError = authorizeInternalRequest(request, env);
  if (authError) return authError;
  try { return privateJson(await captureOperationalMonitor(env.DB)); }
  catch (error) { return privateJson({ error: "Operational monitor failed", detail: safeError(error) }, 503); }
}

function authorizeInternalRequest(request: Request, env: Env): Response | null {
  if (!env.INGEST_SECRET) return privateJson({ error: "Internal operations are not configured" }, 503);
  const client = "private";
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

export async function acquireLease(db: Database, sourceId: string, holder: string): Promise<boolean> {
  const now = new Date(); const expires = new Date(now.getTime() + 10 * 60_000);
  const lease = await db.prepare("INSERT INTO ingestion_leases (source_id, holder, acquired_at, expires_at) VALUES (?, ?, ?, ?) ON CONFLICT(source_id) DO UPDATE SET holder=excluded.holder, acquired_at=excluded.acquired_at, expires_at=excluded.expires_at WHERE ingestion_leases.expires_at < ? RETURNING holder").bind(sourceId, holder, now.toISOString(), expires.toISOString(), now.toISOString()).first<{ holder: string }>();
  return lease?.holder === holder;
}
export async function releaseLease(db: Database, sourceId: string, holder: string): Promise<void> { await db.prepare("DELETE FROM ingestion_leases WHERE source_id=? AND holder=?").bind(sourceId, holder).run(); }
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
