import type { SourcePolicy } from "./contracts";

export function sanitizeText(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const plain = value.replace(/<script[\s\S]*?<\/script>/gi, " ").replace(/<style[\s\S]*?<\/style>/gi, " ").replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
  return plain || undefined;
}

export async function fetchWithPolicy(url: string, policy: SourcePolicy, init?: RequestInit, allowedStatuses: number[] = []): Promise<Response> {
  let lastError: unknown;
  for (let attempt = 0; attempt <= policy.retries; attempt += 1) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), policy.timeoutMs);
    try {
      const response = await fetch(url, { ...init, redirect: "follow", signal: controller.signal });
      if (!response.ok && !allowedStatuses.includes(response.status)) {
        const retryable = response.status === 429 || response.status >= 500;
        if (!retryable || attempt >= policy.retries) throw new Error(`Source returned HTTP ${response.status}`);
        const retryAfter = Number(response.headers.get("retry-after") ?? 0);
        await new Promise((resolve) => setTimeout(resolve, retryAfter > 0 ? Math.min(retryAfter * 1000, 30_000) : policy.retryBaseMs * 2 ** attempt));
        continue;
      }
      const length = Number(response.headers.get("content-length") ?? 0);
      if (length > policy.maxResponseBytes) throw new Error(`Source response exceeds ${policy.maxResponseBytes} bytes`);
      return response;
    } catch (error) {
      lastError = error;
      if (attempt < policy.retries) await new Promise((resolve) => setTimeout(resolve, policy.retryBaseMs * 2 ** attempt));
    } finally { clearTimeout(timeout); }
  }
  throw lastError instanceof Error ? lastError : new Error("Source fetch failed");
}

export async function readJsonLimited(response: Response, maxBytes: number): Promise<unknown> {
  return JSON.parse(await readTextLimited(response, maxBytes));
}

export async function readTextLimited(response: Response, maxBytes: number): Promise<string> {
  const buffer = await response.arrayBuffer();
  if (buffer.byteLength > maxBytes) throw new Error(`Source response exceeds ${maxBytes} bytes`);
  return new TextDecoder().decode(buffer);
}

export function constantTimeEqual(left: string, right: string): boolean {
  const a = new TextEncoder().encode(left);
  const b = new TextEncoder().encode(right);
  let mismatch = a.length ^ b.length;
  for (let index = 0; index < Math.max(a.length, b.length); index += 1) mismatch |= (a[index % Math.max(a.length, 1)] ?? 0) ^ (b[index % Math.max(b.length, 1)] ?? 0);
  return mismatch === 0;
}
