import type { IngestResult } from "../contracts";
import { D1IngestionRepository } from "../d1-repository";
import { fetchWithPolicy } from "../safety";
import { INTELLIGENCE_WINDOW_MONTHS } from "../operational-policy";

export const EPSS_CURRENT_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz";

export interface EpssMetadata { modelVersion?: string; scoreDate: string; }
export interface EpssRow { cveId: string; score: number; percentile: number; }

export async function streamEpssCsv(stream: ReadableStream<Uint8Array>, onRow: (row: EpssRow) => Promise<void> | void, expectedDate?: string): Promise<{ metadata: EpssMetadata; rowCount: number }> {
  const reader = stream.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let metadata: EpssMetadata | undefined;
  let headerSeen = false;
  let rowCount = 0;
  const seen = new Set<string>();
  const consume = async (rawLine: string) => {
    const line = rawLine.trim();
    if (!line) return;
    if (line.startsWith("#")) { metadata = parseMetadata(line, expectedDate); return; }
    if (!headerSeen) { if (line.toLowerCase() !== "cve,epss,percentile") throw new Error("EPSS CSV header is invalid"); headerSeen = true; return; }
    const [rawCve, rawScore, rawPercentile, ...extra] = line.split(",");
    if (extra.length > 0 || !/^CVE-\d{4}-\d{4,}$/i.test(rawCve)) throw new Error(`EPSS row is invalid: ${line.slice(0, 80)}`);
    const cveId = rawCve.toUpperCase();
    if (seen.has(cveId)) throw new Error(`EPSS dataset contains duplicate ${cveId}`);
    seen.add(cveId);
    const score = Number(rawScore); const percentile = Number(rawPercentile);
    if (!Number.isFinite(score) || score < 0 || score > 1 || !Number.isFinite(percentile) || percentile < 0 || percentile > 1) throw new Error(`EPSS values are out of range for ${cveId}`);
    await onRow({ cveId, score, percentile }); rowCount += 1;
  };
  while (true) {
    const { value, done } = await reader.read();
    buffer += value ? decoder.decode(value, { stream: !done }) : decoder.decode();
    const lines = buffer.split(/\r?\n/); buffer = lines.pop() ?? "";
    for (const line of lines) await consume(line);
    if (done) break;
  }
  if (buffer) await consume(buffer);
  if (!headerSeen) throw new Error("EPSS CSV header is missing");
  metadata ??= expectedDate ? { scoreDate: new Date(expectedDate).toISOString() } : undefined;
  if (!metadata) throw new Error("EPSS metadata is missing and no expected date was supplied");
  return { metadata, rowCount };
}

export async function ingestEpssBulk(db: D1Database, idempotencyKey?: string, options: { url?: string; expectedDate?: string; minimumRows?: number } = {}): Promise<IngestResult> {
  const repository = new D1IngestionRepository(db);
  const startedAt = new Date().toISOString();
  const metadata = { mode: "delta" as const, maxItems: 1 };
  const { runId, reused } = await repository.beginRun("first-epss", idempotencyKey, metadata);
  const counts = { discovered: 0, inserted: 0, changed: 0, unchanged: 0, failed: 0 };
  const runFields = { mode: metadata.mode, window: {}, processed: 1, continuation: null, boundHit: false };
  if (reused) return { sourceId: "first-epss", runId, status: "unchanged", ...runFields, processed: 0, counts, errors: [], startedAt, completedAt: new Date().toISOString() };
  const url = options.url ?? EPSS_CURRENT_URL;
  try {
    const response = await fetchWithPolicy(url, { timeoutMs: 60_000, maxResponseBytes: 50_000_000, retries: 2, retryBaseMs: 500 });
    const compressed = await response.arrayBuffer();
    if (compressed.byteLength > 50_000_000) throw new Error("EPSS compressed dataset exceeds configured size limit");
    const sourceHash = await sha256Bytes(compressed);
    const trackedRows = await db.prepare(`SELECT DISTINCT c.id
      FROM cves c
      LEFT JOIN advisory_cves ac ON ac.cve_id=c.id
      LEFT JOIN advisories a ON a.id=ac.advisory_id
        AND COALESCE(a.published_at,a.source_updated_at)>=date('now','-${INTELLIGENCE_WINDOW_MONTHS} months')
      WHERE a.id IS NOT NULL OR EXISTS(
        SELECT 1 FROM kev_entries k WHERE k.cve_id=c.id AND k.active=1
          AND date(k.date_added)>=date('now','-${INTELLIGENCE_WINDOW_MONTHS} months')
      )`).all<{ id: string }>();
    const tracked = new Set((trackedRows.results ?? []).map((row) => row.id));
    let matched = 0;
    const trackedObservations: EpssRow[] = [];
    let statements: D1PreparedStatement[] = [];
    const flush = async () => { if (statements.length) { await db.batch(statements); statements = []; } };
    const gzipStream = new Blob([compressed]).stream().pipeThrough(new DecompressionStream("gzip"));
    const parsed = await streamEpssCsv(gzipStream, (row) => { if (tracked.has(row.cveId)) trackedObservations.push(row); }, options.expectedDate);
    const metadata = parsed.metadata;
    const scoreDate = metadata.scoreDate.slice(0, 10);
    const minimumRows = options.minimumRows ?? (options.url ? 1 : 100_000);
    if (parsed.rowCount < minimumRows) throw new Error(`EPSS dataset has only ${parsed.rowCount} rows; refusing to publish an incomplete snapshot`);
    const latest = await db.prepare("SELECT score_date,source_hash,status FROM epss_datasets WHERE is_current=1 LIMIT 1").first<{ score_date: string; source_hash: string; status: string }>();
    if (latest && scoreDate < latest.score_date) throw new Error("EPSS dataset date regressed");
    if (latest?.score_date === scoreDate && latest.source_hash === sourceHash && latest.status === "published") {
      counts.discovered = parsed.rowCount;
      counts.unchanged = trackedObservations.length;
      await db.prepare("UPDATE source_runs SET dataset_date=?, source_hash=? WHERE id=?").bind(scoreDate, sourceHash, runId).run();
      await repository.finishRun(runId, { status: "unchanged", ...runFields, counts, errors: [] });
      return { sourceId: "first-epss", runId, status: "unchanged", ...runFields, counts, errors: [], startedAt, completedAt: new Date().toISOString() };
    }

    await db.prepare("INSERT INTO epss_datasets (score_date, source_run_id, model_version, source_hash, source_url, row_count, matched_cve_count, status, is_current, published_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'staging', 0, ?) ON CONFLICT(score_date) DO UPDATE SET source_run_id=excluded.source_run_id, model_version=excluded.model_version, source_hash=excluded.source_hash, source_url=excluded.source_url, row_count=excluded.row_count, matched_cve_count=excluded.matched_cve_count, status='staging', published_at=excluded.published_at").bind(scoreDate, runId, metadata.modelVersion ?? null, sourceHash, response.url, parsed.rowCount, matched, metadata.scoreDate).run();
    for (const row of trackedObservations) {
      statements.push(db.prepare("INSERT INTO epss_observations (cve_id, score_date, score, percentile, model_version, source_run_id, observed_at) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(cve_id, score_date) DO UPDATE SET score=excluded.score, percentile=excluded.percentile, model_version=excluded.model_version, source_run_id=excluded.source_run_id, observed_at=excluded.observed_at").bind(row.cveId, scoreDate, row.score, row.percentile, metadata.modelVersion ?? null, runId, new Date().toISOString()));
      matched += 1;
      if (statements.length >= 75) await flush();
    }
    await db.prepare("UPDATE epss_datasets SET matched_cve_count=? WHERE score_date=?").bind(matched, scoreDate).run();
    await flush();
    await db.batch([db.prepare("UPDATE epss_datasets SET is_current=0 WHERE is_current=1"), db.prepare("UPDATE epss_datasets SET is_current=1, status='published' WHERE score_date=?").bind(scoreDate)]);
    counts.discovered = parsed.rowCount; counts.inserted = matched;
    await db.prepare("UPDATE source_runs SET dataset_date=?, source_hash=? WHERE id=?").bind(scoreDate, sourceHash, runId).run();
    const status = latest?.score_date === scoreDate ? "unchanged" : "success";
    await repository.finishRun(runId, { status, ...runFields, counts, errors: [] });
    return { sourceId: "first-epss", runId, status, ...runFields, counts, errors: [], startedAt, completedAt: new Date().toISOString() };
  } catch (error) {
    const message = error instanceof Error ? error.message : "EPSS ingestion failed";
    counts.failed = 1;
    await repository.finishRun(runId, { status: "failed", ...runFields, counts, errors: [message] });
    return { sourceId: "first-epss", runId, status: "failed", ...runFields, counts, errors: [message], startedAt, completedAt: new Date().toISOString() };
  }
}

function parseMetadata(line: string, expectedDate?: string): EpssMetadata {
  const fields = new Map(line.replace(/^#/, "").split(",").map((part) => { const index = part.indexOf(":"); return [part.slice(0, index).trim(), part.slice(index + 1).trim()]; }));
  const rawDate = fields.get("score_date") ?? expectedDate;
  if (!rawDate || Number.isNaN(new Date(rawDate).getTime())) throw new Error("EPSS score_date metadata is invalid");
  return { modelVersion: fields.get("model_version") || undefined, scoreDate: new Date(rawDate).toISOString() };
}
async function sha256Bytes(value: ArrayBuffer): Promise<string> { const digest = await crypto.subtle.digest("SHA-256", value); return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join(""); }
