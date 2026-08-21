import type { NormalizedAdvisory, VendorId } from "../domain/types";

export interface AdvisoryRef {
  id: string;
  url: string;
  sourceUpdatedAt?: string;
  metadata?: Record<string, string>;
}

export interface RawAdvisory {
  ref: AdvisoryRef;
  contentType: string;
  body: unknown;
  fetchedAt: string;
  resolvedUrl: string;
  etag?: string;
  lastModified?: string;
}

export interface SourcePolicy {
  timeoutMs: number;
  maxResponseBytes: number;
  retries: number;
  retryBaseMs: number;
}

export interface DiscoveryContext { fetch: typeof fetch; since?: string; until?: string; signal?: AbortSignal; policy: SourcePolicy; }
export interface FetchContext { fetch: typeof fetch; signal?: AbortSignal; policy: SourcePolicy; }
export interface NormalizeContext { observedAt: string; sanitizeText(value: unknown): string | undefined; }

export interface VendorAdapter {
  vendor: VendorId;
  sourceId: string;
  discover(ctx: DiscoveryContext): Promise<AdvisoryRef[]>;
  fetch(ref: AdvisoryRef, ctx: FetchContext): Promise<RawAdvisory>;
  normalize(raw: RawAdvisory, ctx: NormalizeContext): Promise<NormalizedAdvisory[]>;
}

export interface IngestCounts { discovered: number; inserted: number; changed: number; unchanged: number; failed: number; }
export interface IngestResult { sourceId: string; runId: string; status: "success" | "partial" | "failed" | "unchanged"; counts: IngestCounts; errors: string[]; startedAt: string; completedAt: string; }

export interface PriorRevision {
  advisoryId: string;
  contentHash: string;
  affectedProductsHash: string;
  remediationHash: string;
  vendorSeverity?: string;
  cvssScore?: number;
  exploitationStatus: string;
  sourceUpdatedAt?: string;
  normalized: NormalizedAdvisory;
}

export interface IngestionRepository {
  beginRun(sourceId: string, idempotencyKey?: string): Promise<{ runId: string; reused: boolean }>;
  finishRun(runId: string, result: Omit<IngestResult, "sourceId" | "runId" | "startedAt" | "completedAt">): Promise<void>;
  latestRevision(vendor: VendorId, vendorAdvisoryId: string): Promise<PriorRevision | null>;
  saveAdvisory(runId: string, advisory: NormalizedAdvisory, changeTypes: string[]): Promise<"inserted" | "changed" | "unchanged">;
  recordFailure(runId: string, ref: AdvisoryRef, error: string, durationMs: number): Promise<void>;
}

export const DEFAULT_SOURCE_POLICY: SourcePolicy = { timeoutMs: 20_000, maxResponseBytes: 8_000_000, retries: 2, retryBaseMs: 350 };
