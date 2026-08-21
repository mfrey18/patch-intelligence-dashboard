import type { AdvisoryHashes, NormalizedAdvisory } from "../domain/types";

export function stableSerialize(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableSerialize).join(",")}]`;
  return `{${Object.entries(value as Record<string, unknown>).filter(([, entry]) => entry !== undefined).sort(([a], [b]) => a.localeCompare(b)).map(([key, entry]) => `${JSON.stringify(key)}:${stableSerialize(entry)}`).join(",")}}`;
}

export async function sha256(value: unknown): Promise<string> {
  const bytes = new TextEncoder().encode(typeof value === "string" ? value : stableSerialize(value));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export async function hashAdvisory(advisory: NormalizedAdvisory): Promise<AdvisoryHashes> {
  const affectedProducts = [...advisory.affectedProducts].sort((a, b) => stableSerialize(a).localeCompare(stableSerialize(b)));
  const remediations = [...advisory.remediations].sort((a, b) => stableSerialize(a).localeCompare(stableSerialize(b)));
  const content = { ...advisory, affectedProducts, remediations, cves: [...advisory.cves].sort((a, b) => a.cveId.localeCompare(b.cveId)), exploitEvidence: [...advisory.exploitEvidence].sort((a, b) => stableSerialize(a).localeCompare(stableSerialize(b))) };
  return { contentHash: await sha256(content), affectedProductsHash: await sha256(affectedProducts), remediationHash: await sha256(remediations) };
}
