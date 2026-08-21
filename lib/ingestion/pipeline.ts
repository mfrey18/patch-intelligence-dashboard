import type { ChangeType, NormalizedAdvisory } from "../domain/types";
import { diffAdvisory } from "./diff";
import { hashAdvisory } from "./hash";
import type { IngestionRepository, IngestResult, SourcePolicy, VendorAdapter } from "./contracts";
import { DEFAULT_SOURCE_POLICY } from "./contracts";
import { sanitizeText } from "./safety";

export interface RunVendorOptions { since?: string; until?: string; idempotencyKey?: string; policy?: Partial<SourcePolicy>; }

export async function runVendorAdapter(adapter: VendorAdapter, repository: IngestionRepository, options: RunVendorOptions = {}): Promise<IngestResult> {
  const startedAt = new Date().toISOString();
  const { runId, reused } = await repository.beginRun(adapter.sourceId, options.idempotencyKey);
  if (reused) return { sourceId: adapter.sourceId, runId, status: "unchanged", counts: { discovered: 0, inserted: 0, changed: 0, unchanged: 0, failed: 0 }, errors: [], startedAt, completedAt: new Date().toISOString() };
  const policy = { ...DEFAULT_SOURCE_POLICY, ...options.policy };
  const counts = { discovered: 0, inserted: 0, changed: 0, unchanged: 0, failed: 0 };
  const errors: string[] = [];
  try {
    const refs = await adapter.discover({ fetch, since: options.since, until: options.until, policy });
    counts.discovered = refs.length;
    for (const ref of refs) {
      const itemStart = Date.now();
      try {
        const raw = await adapter.fetch(ref, { fetch, policy });
        const advisories = await adapter.normalize(raw, { observedAt: new Date().toISOString(), sanitizeText });
        for (const advisory of advisories) {
          validateNormalizedAdvisory(advisory, adapter);
          const hashes = await hashAdvisory(advisory);
          const previous = await repository.latestRevision(adapter.vendor, advisory.vendorAdvisoryId);
          let changes = diffAdvisory(previous?.normalized ?? null, advisory);
          if (previous && previous.contentHash !== hashes.contentHash && changes.length === 0) changes = ["ADVISORY_REVISED", "SOURCE_MODIFIED"];
          const result = await repository.saveAdvisory(runId, advisory, changes);
          counts[result] += 1;
        }
      } catch (error) {
        counts.failed += 1;
        const message = safeError(error);
        errors.push(`${ref.id}: ${message}`);
        await repository.recordFailure(runId, ref, message, Date.now() - itemStart);
      }
    }
  } catch (error) {
    counts.failed += 1;
    errors.push(`discovery: ${safeError(error)}`);
  }
  const status: IngestResult["status"] = counts.failed > 0 ? counts.inserted + counts.changed + counts.unchanged > 0 ? "partial" : "failed" : counts.inserted + counts.changed === 0 ? "unchanged" : "success";
  await repository.finishRun(runId, { status, counts, errors });
  return { sourceId: adapter.sourceId, runId, status, counts, errors, startedAt, completedAt: new Date().toISOString() };
}

export function validateNormalizedAdvisory(advisory: NormalizedAdvisory, adapter: VendorAdapter): void {
  if (advisory.vendor !== adapter.vendor || advisory.sourceId !== adapter.sourceId) throw new Error("Adapter provenance does not match normalized advisory");
  if (!advisory.vendorAdvisoryId.trim() || !advisory.title.trim()) throw new Error("Normalized advisory is missing an identifier or title");
  if (!/^https:\/\//i.test(advisory.sourceUrl)) throw new Error("Normalized advisory source URL must use HTTPS");
  const cves = new Set<string>();
  for (const assertion of advisory.cves) {
    if (!/^CVE-\d{4}-\d{4,}$/.test(assertion.cveId)) throw new Error(`Invalid CVE identifier: ${assertion.cveId}`);
    if (cves.has(assertion.cveId)) throw new Error(`Duplicate CVE assertion: ${assertion.cveId}`);
    cves.add(assertion.cveId);
    if (assertion.cvssScore != null && (assertion.cvssScore < 0 || assertion.cvssScore > 10)) throw new Error(`CVSS score out of range for ${assertion.cveId}`);
  }
  for (const evidence of advisory.exploitEvidence) if (!cves.has(evidence.cveId)) throw new Error(`Exploit evidence references unasserted CVE ${evidence.cveId}`);
}

export function summarizeChange(change: ChangeType, advisory: NormalizedAdvisory): string {
  const labels: Record<ChangeType, string> = {
    NEW_ADVISORY: "New vendor advisory", NEW_CVE: "New vulnerability published", ADVISORY_REVISED: "Vendor advisory revised", SEVERITY_CHANGED: "Vendor severity changed", CVSS_CHANGED: "Vendor CVSS changed", EXPLOITATION_STATUS_CHANGED: "Exploitation status changed", KEV_ADDED: "Added to CISA KEV", KEV_REMOVED: "Removed from current CISA KEV snapshot", KEV_DEADLINE_CHANGED: "CISA KEV deadline changed", KEV_ENTRY_MODIFIED: "CISA KEV entry revised", AFFECTED_PRODUCT_ADDED: "Affected product added", AFFECTED_PRODUCT_REMOVED: "Affected product removed", FIXED_VERSION_CHANGED: "Fixed version changed", REMEDIATION_CHANGED: "Remediation guidance changed", MITIGATION_ADDED: "Mitigation added", WORKAROUND_ADDED: "Workaround added", SOURCE_MODIFIED: "Source advisory modified",
  };
  return `${labels[change]} — ${advisory.vendorAdvisoryId}`;
}

function safeError(error: unknown): string { return error instanceof Error ? error.message.slice(0, 500) : "Unknown ingestion error"; }
