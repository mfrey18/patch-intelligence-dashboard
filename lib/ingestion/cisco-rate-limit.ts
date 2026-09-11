import { retryAfterDeadline, SourceHttpError, type FetchPolicyRuntime } from "./safety";

const REQUEST_INTERVAL_MS = 2200;
const DAY_MS = 86_400_000;
const DAILY_REQUEST_LIMIT = 5000;

/** One shared policy per native process, including retries and paginated calls.
 * Cisco's per-application limits are 5/sec, 30/min, 5000/day:
 * https://developer.cisco.com/docs/psirt/browsing-sorting-filterting-and-rate-limits/
 * Other clients can also consume that quota, so upstream cooldowns take precedence.
 */
export function createCiscoRequestPolicy(runtime: Omit<FetchPolicyRuntime, "schedule"> = {}): FetchPolicyRuntime {
  const now = runtime.now ?? Date.now;
  const sleep = runtime.sleep ?? ((milliseconds: number) => new Promise<void>((resolve) => setTimeout(resolve, milliseconds)));
  let queue: Promise<unknown> = Promise.resolve();
  let nextRequestAt = 0;
  let cooldownUntil = 0;
  const requests: number[] = [];
  return {
    ...runtime, now, sleep,
    schedule(request) {
      const scheduled = queue.then(async () => {
        while (requests.length && requests[0] <= now() - DAY_MS) requests.shift();
        if (requests.length >= DAILY_REQUEST_LIMIT) cooldownUntil = Math.max(cooldownUntil, requests[0] + DAY_MS);
        const wait = Math.max(nextRequestAt, cooldownUntil) - now();
        if (wait > 30_000) throw new SourceHttpError(429, Math.max(nextRequestAt, cooldownUntil));
        if (wait > 0) await sleep(wait);
        const startedAt = now();
        nextRequestAt = startedAt + REQUEST_INTERVAL_MS;
        requests.push(startedAt);
        const response = await request();
        if (response.status === 429 || response.status >= 500) {
          const retryAt = retryAfterDeadline(response.headers.get("retry-after"), now());
          if (retryAt != null) cooldownUntil = Math.max(cooldownUntil, retryAt);
          else if (response.status === 429) {
            // Unknown minute/day exhaustion: stop the batch instead of probing rapidly.
            cooldownUntil = Math.max(cooldownUntil, now() + 60_000);
            await response.body?.cancel();
            throw new SourceHttpError(429, cooldownUntil);
          }
        }
        return response;
      });
      // Keep pacing state after a failed batch; recreated adapters share this queue.
      queue = scheduled.catch(() => {});
      return scheduled;
    },
  };
}
