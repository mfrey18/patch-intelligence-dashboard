import type { SourcePolicy } from "./contracts";

export function sanitizeText(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const plain = value.replace(/<script[\s\S]*?<\/script>/gi, " ").replace(/<style[\s\S]*?<\/style>/gi, " ").replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
  return plain || undefined;
}

export interface FetchPolicyRuntime {
  fetch?: typeof fetch;
  now?: () => number;
  sleep?: (milliseconds: number) => Promise<void>;
  schedule?: (request: () => Promise<Response>) => Promise<Response>;
}

export class SourceHttpError extends Error {
  constructor(readonly status: number, readonly retryAt?: number) {
    super(`Source returned HTTP ${status}${retryAt ? `; retry after ${new Date(retryAt).toISOString()}` : ""}`);
  }
}

/** Retry-After can be delay-seconds or an HTTP date. Never shorten a valid deadline. */
export function retryAfterDeadline(value: string | null, now: number): number | undefined {
  if (!value?.trim()) return undefined;
  const header = value.trim();
  const deadline = /^\d+(?:\.\d+)?$/.test(header) ? now + Number(header) * 1000 : Date.parse(header);
  return Number.isFinite(deadline) && !Number.isNaN(new Date(deadline).getTime()) && deadline >= now ? deadline : undefined;
}

export async function fetchWithPolicy(url: string, policy: SourcePolicy, init?: RequestInit, allowedStatuses: number[] = [], runtime: FetchPolicyRuntime = {}): Promise<Response> {
  const now = runtime.now ?? Date.now;
  const sleep = runtime.sleep ?? ((milliseconds: number) => new Promise<void>((resolve) => setTimeout(resolve, milliseconds)));
  const retryable = (status: number) => status === 429 || status >= 500;
  for (let attempt = 0; attempt <= policy.retries; attempt += 1) {
    let response: Response;
    try {
      const request = async () => {
        // Scheduling wait is separate from the network request timeout.
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), policy.timeoutMs);
        try { return await (runtime.fetch ?? fetch)(url, { ...init, redirect: init?.redirect ?? "follow", signal: controller.signal }); }
        finally { clearTimeout(timeout); }
      };
      response = await (runtime.schedule ? runtime.schedule(request) : request());
    } catch (error) {
      if (attempt >= policy.retries || (error instanceof SourceHttpError && (!retryable(error.status) || (error.retryAt ?? 0) - now() > 30_000))) throw error;
      const wait = Math.max(policy.retryBaseMs * 2 ** attempt, error instanceof SourceHttpError ? (error.retryAt ?? 0) - now() : 0);
      await sleep(wait);
      continue;
    }
    if (!response.ok && !allowedStatuses.includes(response.status)) {
      const retryAt = retryAfterDeadline(response.headers.get("retry-after"), now());
      const error = new SourceHttpError(response.status, retryAt);
      await response.body?.cancel();
      // Long cooldowns remain resumable. Do not clamp them and retry prematurely.
      if (!retryable(response.status) || attempt >= policy.retries || (retryAt ?? 0) - now() > 30_000) throw error;
      await sleep(Math.max(policy.retryBaseMs * 2 ** attempt, (retryAt ?? 0) - now()));
      continue;
    }
    const length = Number(response.headers.get("content-length") ?? 0);
    if (init?.method?.toUpperCase() !== "HEAD" && length > policy.maxResponseBytes) { await response.body?.cancel(); throw new Error(`Source response exceeds ${policy.maxResponseBytes} bytes`); }
    return response;
  }
  throw new Error("Source fetch failed");
}

export async function readJsonLimited(response: Response, maxBytes: number): Promise<unknown> {
  return JSON.parse(await readTextLimited(response, maxBytes));
}

export async function readTextLimited(response: Response, maxBytes: number): Promise<string> {
  const reader = response.body?.getReader();
  if (!reader) return "";
  const chunks: Uint8Array[] = []; let size = 0;
  let timedOut = false;
  const deadline = setTimeout(() => { timedOut = true; void reader.cancel("Source body timeout"); }, 60_000);
  try {
    while (true) {
      const {value,done} = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) { await reader.cancel(); throw new Error(`Source response exceeds ${maxBytes} bytes`); }
      chunks.push(value);
    }
    if (timedOut) throw new Error("Source body timeout");
    const buffer = new Uint8Array(size); let offset = 0;
    for (const chunk of chunks) { buffer.set(chunk,offset); offset += chunk.byteLength; }
    return new TextDecoder().decode(buffer);
  } finally { clearTimeout(deadline); reader.releaseLock(); }
}

export function constantTimeEqual(left: string, right: string): boolean {
  const a = new TextEncoder().encode(left);
  const b = new TextEncoder().encode(right);
  let mismatch = a.length ^ b.length;
  for (let index = 0; index < Math.max(a.length, b.length); index += 1) mismatch |= (a[index % Math.max(a.length, 1)] ?? 0) ^ (b[index % Math.max(b.length, 1)] ?? 0);
  return mismatch === 0;
}

export function sourceCooldown(error: unknown): string | null {
  if (!(error instanceof SourceHttpError)) return null;
  const deadline=error.retryAt ?? (error.status===429?Date.now()+60_000:0);
  return deadline>Date.now()?new Date(deadline).toISOString():null;
}
