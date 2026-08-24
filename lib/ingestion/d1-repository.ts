import type { ChangeType, NormalizedAdvisory, VendorId } from "../domain/types";
import type { AdvisoryRef, IngestionRepository, IngestResult, PriorRevision, RunMetadata } from "./contracts";
import { hashAdvisory, sha256 } from "./hash";
import { summarizeChange } from "./pipeline";
import { SOURCE_CATALOG } from "./source-catalog";

export class D1IngestionRepository implements IngestionRepository {
  constructor(private readonly db: D1Database) {}

  async beginRun(sourceId: string, idempotencyKey: string | undefined, metadata: RunMetadata): Promise<{ runId: string; reused: boolean; continuation: string | null; boundHit: boolean }> {
    if (idempotencyKey) {
      const existing = await this.db.prepare("SELECT id, status, records_failed, continuation_out, bound_hit FROM source_runs WHERE source_id = ? AND idempotency_key = ? LIMIT 1").bind(sourceId, idempotencyKey).first<{ id: string; status: string; records_failed: number; continuation_out: string | null; bound_hit: number }>();
      if (existing && existing.status !== "running" && existing.status !== "failed" && Number(existing.records_failed) === 0) return { runId: existing.id, reused: true, continuation: existing.continuation_out, boundHit: Boolean(existing.bound_hit) };
      // Preserve the failed/interrupted attempt as audit evidence while allowing a
      // deterministic checkpoint batch to be retried under the same public key.
      if (existing) await this.db.prepare("UPDATE source_runs SET idempotency_key=NULL WHERE id=?").bind(existing.id).run();
    }
    const runId = crypto.randomUUID();
    await this.db.prepare("INSERT INTO source_runs (id, source_id, idempotency_key, started_at, status, ingestion_mode, window_start, window_end, continuation_in, checkpoint_id, max_items, bound_hit, records_discovered, records_inserted, records_changed, records_unchanged, records_failed) VALUES (?, ?, ?, ?, 'running', ?, ?, ?, ?, ?, ?, 0, 0, 0, 0, 0, 0)").bind(runId, sourceId, idempotencyKey ?? null, new Date().toISOString(), metadata.mode, metadata.windowStart ?? null, metadata.windowEnd ?? null, metadata.continuationIn ?? null, metadata.checkpointId ?? null, metadata.maxItems).run();
    return { runId, reused: false, continuation: null, boundHit: false };
  }

  async finishRun(runId: string, result: Omit<IngestResult, "sourceId" | "runId" | "startedAt" | "completedAt">): Promise<void> {
    await this.db.prepare("UPDATE source_runs SET completed_at = ?, status = ?, ingestion_mode = ?, window_start = ?, window_end = ?, continuation_out = ?, bound_hit = ?, records_discovered = ?, records_inserted = ?, records_changed = ?, records_unchanged = ?, records_failed = ?, error_summary = ? WHERE id = ?").bind(new Date().toISOString(), result.status, result.mode, result.window.since ?? null, result.window.until ?? null, result.continuation, result.boundHit ? 1 : 0, result.counts.discovered, result.counts.inserted, result.counts.changed, result.counts.unchanged, result.counts.failed, result.errors.join(" | ").slice(0, 2000) || null, runId).run();
  }

  async latestRevision(vendor: VendorId, vendorAdvisoryId: string): Promise<PriorRevision | null> {
    const row = await this.db.prepare(`SELECT a.id AS advisory_id, r.content_hash, r.affected_products_hash, r.remediation_hash, r.vendor_severity, r.cvss_score, r.exploitation_status, r.source_updated_at, r.normalized_json FROM advisories a JOIN advisory_revisions r ON r.advisory_id = a.id WHERE a.vendor_id = ? AND a.vendor_advisory_id = ? ORDER BY r.observed_at DESC LIMIT 1`).bind(vendor, vendorAdvisoryId).first<Record<string, unknown>>();
    if (!row) return null;
    return { advisoryId: String(row.advisory_id), contentHash: String(row.content_hash), affectedProductsHash: String(row.affected_products_hash), remediationHash: String(row.remediation_hash), vendorSeverity: row.vendor_severity == null ? undefined : String(row.vendor_severity), cvssScore: row.cvss_score == null ? undefined : Number(row.cvss_score), exploitationStatus: String(row.exploitation_status), sourceUpdatedAt: row.source_updated_at == null ? undefined : String(row.source_updated_at), normalized: JSON.parse(String(row.normalized_json)) as NormalizedAdvisory };
  }

  async saveAdvisory(runId: string, advisory: NormalizedAdvisory, changeTypes: string[]): Promise<"inserted" | "changed" | "unchanged"> {
    const now = new Date().toISOString();
    const advisoryId = `${advisory.vendor}:${advisory.vendorAdvisoryId}`;
    const hashes = await hashAdvisory(advisory);
    const previous = await this.latestRevision(advisory.vendor, advisory.vendorAdvisoryId);
    if (previous?.contentHash === hashes.contentHash) {
      await this.recordResult(runId, advisory.vendorAdvisoryId, "unchanged", [], 0);
      return "unchanged";
    }
    const revisionId = crypto.randomUUID();
    const queries: D1PreparedStatement[] = [];
    queries.push(this.db.prepare("INSERT INTO advisories (id, vendor_id, source_id, vendor_advisory_id, title, summary, source_url, published_at, source_updated_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(vendor_id, vendor_advisory_id) DO UPDATE SET title=excluded.title, summary=excluded.summary, source_url=excluded.source_url, source_updated_at=excluded.source_updated_at, updated_at=excluded.updated_at").bind(advisoryId, advisory.vendor, advisory.sourceId, advisory.vendorAdvisoryId, advisory.title, advisory.summary ?? null, advisory.sourceUrl, advisory.publishedAt ?? null, advisory.sourceUpdatedAt ?? null, now, now));
    queries.push(this.db.prepare("INSERT INTO advisory_revisions (id, advisory_id, source_run_id, observed_at, source_updated_at, content_hash, affected_products_hash, remediation_hash, exploitation_status, vendor_severity, cvss_score, change_types_json, normalized_json, source_url) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)").bind(revisionId, advisoryId, runId, now, advisory.sourceUpdatedAt ?? null, hashes.contentHash, hashes.affectedProductsHash, hashes.remediationHash, advisory.exploitationStatus, advisory.vendorSeverity ?? null, advisory.cvssScore ?? null, JSON.stringify(changeTypes), JSON.stringify(advisory), advisory.sourceUrl));

    if (advisory.releaseEvent) {
      queries.push(this.db.prepare("INSERT INTO release_events (id, vendor_id, event_type, event_date, label, source_url, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET label=excluded.label, source_url=excluded.source_url, updated_at=excluded.updated_at").bind(advisory.releaseEvent.id, advisory.vendor, advisory.releaseEvent.eventType, advisory.releaseEvent.eventDate, advisory.releaseEvent.label, advisory.releaseEvent.sourceUrl ?? advisory.sourceUrl, now, now));
      queries.push(this.db.prepare("INSERT OR IGNORE INTO release_event_advisories (release_event_id, advisory_id) VALUES (?, ?)").bind(advisory.releaseEvent.id, advisoryId));
    }

    for (const assertion of advisory.cves) {
      queries.push(this.db.prepare("INSERT INTO cves (id, created_at, updated_at) VALUES (?, ?, ?) ON CONFLICT(id) DO UPDATE SET updated_at=excluded.updated_at").bind(assertion.cveId, now, now));
      queries.push(this.db.prepare("INSERT INTO advisory_cves (advisory_id, cve_id, vendor_description, vendor_cwe, vendor_severity, normalized_severity, vendor_cvss_score, vendor_cvss_vector) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(advisory_id, cve_id) DO UPDATE SET vendor_description=excluded.vendor_description, vendor_cwe=excluded.vendor_cwe, vendor_severity=excluded.vendor_severity, normalized_severity=excluded.normalized_severity, vendor_cvss_score=excluded.vendor_cvss_score, vendor_cvss_vector=excluded.vendor_cvss_vector").bind(advisoryId, assertion.cveId, assertion.description ?? null, assertion.cwe ?? null, assertion.vendorSeverity ?? null, assertion.normalizedSeverity, assertion.cvssScore ?? null, assertion.cvssVector ?? null));
    }

    // Large CSAF advisories can contain thousands of product/version assertions.
    // One prepared statement per row repeats SQL and argument metadata until
    // D1's 32 MiB RPC envelope is exceeded. These JSON-backed INSERT...SELECT
    // statements keep the same atomic db.batch transaction with bounded RPC
    // argument overhead and no loss of product or remediation applicability.
    const productRecords = new Map<string, { id: string; name: string; family: string | null }>();
    const affectedRecords: Array<Record<string, unknown>> = [];
    for (const product of advisory.affectedProducts) {
      const productId = `${advisory.vendor}:${(await sha256(product.name)).slice(0, 20)}`;
      const current = productRecords.get(product.name);
      productRecords.set(product.name, { id: productId, name: product.name, family: product.family ?? current?.family ?? null });
      affectedRecords.push({ id: crypto.randomUUID(), cveId: product.cveId ?? null, productId, affectedVersion: product.affectedVersion ?? null, fixedVersion: product.fixedVersion ?? null, status: product.status, sourceProductId: product.sourceProductId ?? null });
    }

    const remediationRecords: Array<Record<string, unknown>> = [];
    for (const remediation of advisory.remediations) {
      const productId = remediation.productName ? `${advisory.vendor}:${(await sha256(remediation.productName)).slice(0, 20)}` : null;
      if (remediation.productName && productId && !productRecords.has(remediation.productName)) productRecords.set(remediation.productName, { id: productId, name: remediation.productName, family: null });
      remediationRecords.push({ id: crypto.randomUUID(), cveId: remediation.cveId ?? null, productId, kind: remediation.kind, patchAvailable: remediation.patchAvailable == null ? null : remediation.patchAvailable ? 1 : 0, fixedVersion: remediation.fixedVersion ?? null, action: remediation.action ?? null, rebootRequired: remediation.rebootRequired == null ? null : remediation.rebootRequired ? 1 : 0, superseded: remediation.superseded == null ? null : remediation.superseded ? 1 : 0, sourceUrl: remediation.sourceUrl, publishedAt: remediation.publishedAt ?? null, updatedAt: remediation.updatedAt ?? now });
    }

    if (productRecords.size > 0) queries.push(this.db.prepare(`INSERT INTO products (id, vendor_id, name, family, created_at, updated_at)
      SELECT json_extract(value,'$.id'), ?, json_extract(value,'$.name'), json_extract(value,'$.family'), ?, ? FROM json_each(?) WHERE 1
      ON CONFLICT(vendor_id, name) DO UPDATE SET family=COALESCE(excluded.family, products.family), updated_at=excluded.updated_at`).bind(advisory.vendor, now, now, JSON.stringify([...productRecords.values()])));
    if (affectedRecords.length > 0) queries.push(this.db.prepare(`INSERT INTO affected_products (id, advisory_id, advisory_revision_id, cve_id, product_id, affected_version, fixed_version, status, source_product_id)
      SELECT json_extract(value,'$.id'), ?, ?, json_extract(value,'$.cveId'), json_extract(value,'$.productId'), json_extract(value,'$.affectedVersion'), json_extract(value,'$.fixedVersion'), json_extract(value,'$.status'), json_extract(value,'$.sourceProductId') FROM json_each(?)`).bind(advisoryId, revisionId, JSON.stringify(affectedRecords)));
    if (remediationRecords.length > 0) queries.push(this.db.prepare(`INSERT INTO remediations (id, advisory_id, advisory_revision_id, cve_id, product_id, kind, patch_available, fixed_version, action, reboot_required, superseded, source_url, published_at, updated_at)
      SELECT json_extract(value,'$.id'), ?, ?, json_extract(value,'$.cveId'), json_extract(value,'$.productId'), json_extract(value,'$.kind'), json_extract(value,'$.patchAvailable'), json_extract(value,'$.fixedVersion'), json_extract(value,'$.action'), json_extract(value,'$.rebootRequired'), json_extract(value,'$.superseded'), json_extract(value,'$.sourceUrl'), json_extract(value,'$.publishedAt'), json_extract(value,'$.updatedAt') FROM json_each(?)`).bind(advisoryId, revisionId, JSON.stringify(remediationRecords)));

    for (const evidence of advisory.exploitEvidence) {
      const evidenceId = `${evidence.cveId}:${advisory.sourceId}:${(await sha256(`${evidence.type}|${evidence.evidenceUrl}`)).slice(0, 20)}`;
      queries.push(this.db.prepare("INSERT INTO exploit_evidence (id, cve_id, advisory_id, source_id, evidence_type, status, evidence_date, evidence_url, summary, first_observed_at, last_observed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(cve_id, source_id, evidence_type, evidence_url) DO UPDATE SET status=excluded.status, evidence_date=excluded.evidence_date, summary=excluded.summary, last_observed_at=excluded.last_observed_at").bind(evidenceId, evidence.cveId, advisoryId, advisory.sourceId, evidence.type, evidence.status, evidence.evidenceDate ?? null, evidence.evidenceUrl, evidence.summary ?? null, now, now));
    }

    for (const rawChange of changeTypes) {
      const change = rawChange as ChangeType;
      const cveIds = advisory.cves.length > 0 ? advisory.cves.map((item) => item.cveId) : [null];
      for (const cveId of cveIds) queries.push(this.db.prepare("INSERT INTO intelligence_changes (id, source_run_id, entity_type, entity_id, cve_id, advisory_id, change_type, observed_at, before_json, after_json, summary) VALUES (?, ?, 'advisory', ?, ?, ?, ?, ?, ?, ?, ?)").bind(crypto.randomUUID(), runId, advisoryId, cveId, advisoryId, change, now, previous ? JSON.stringify({ severity: previous.vendorSeverity, cvss: previous.cvssScore, exploitationStatus: previous.exploitationStatus }) : null, JSON.stringify({ severity: advisory.vendorSeverity, cvss: advisory.cvssScore, exploitationStatus: advisory.exploitationStatus }), summarizeChange(change, advisory)));
    }

    await this.db.batch(queries);
    const result = previous ? "changed" : "inserted";
    await this.recordResult(runId, advisory.vendorAdvisoryId, result, changeTypes, 0);
    return result;
  }

  async recordFailure(runId: string, ref: AdvisoryRef, error: string, durationMs: number): Promise<void> { await this.recordResult(runId, ref.id, "failed", [], durationMs, error); }

  private async recordResult(runId: string, sourceRef: string, status: string, changes: string[], durationMs: number, error?: string): Promise<void> {
    await this.db.prepare("INSERT INTO source_run_results (id, source_run_id, source_ref, status, change_types_json, error_summary, duration_ms, observed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)").bind(crypto.randomUUID(), runId, sourceRef, status, JSON.stringify(changes), error?.slice(0, 1000) ?? null, durationMs, new Date().toISOString()).run();
  }
}

export async function seedIngestionCatalog(db: D1Database): Promise<void> {
  const now = new Date().toISOString();
  const vendors = [["microsoft", "Microsoft", "https://msrc.microsoft.com"], ["cisco", "Cisco", "https://sec.cloudapps.cisco.com/security/center/"], ["adobe", "Adobe", "https://helpx.adobe.com/security.html"], ["fortinet", "Fortinet", "https://fortiguard.fortinet.com/psirt"], ["palo-alto", "Palo Alto Networks", "https://security.paloaltonetworks.com"], ["ivanti", "Ivanti", "https://www.ivanti.com/support/product-documentation/security-advisories"], ["vmware-broadcom", "VMware / Broadcom", "https://support.broadcom.com/security-advisories"], ["citrix", "Citrix", "https://support.citrix.com/securitybulletins"], ["chrome", "Google Chrome", "https://chromereleases.googleblog.com"], ["mozilla", "Mozilla", "https://www.mozilla.org/security/advisories/"], ["apple", "Apple", "https://support.apple.com/en-us/100100"], ["oracle", "Oracle", "https://www.oracle.com/security-alerts/"], ["atlassian", "Atlassian", "https://www.atlassian.com/trust/security/advisories"], ["sap", "SAP", "https://support.sap.com/en/my-support/knowledge-base/security-notes-news.html"]];
  const statements: D1PreparedStatement[] = vendors.map(([id, name, url]) => db.prepare("INSERT INTO vendors (id, name, homepage_url, created_at, updated_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET name=excluded.name, homepage_url=excluded.homepage_url, updated_at=excluded.updated_at").bind(id, name, url, now, now));
  for (const source of SOURCE_CATALOG) statements.push(db.prepare("INSERT INTO sources (id, vendor_id, name, kind, discovery_url, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 1, ?, ?) ON CONFLICT(id) DO UPDATE SET vendor_id=excluded.vendor_id, name=excluded.name, kind=excluded.kind, discovery_url=excluded.discovery_url, enabled=1, updated_at=excluded.updated_at").bind(source.id, source.vendorId, source.name, source.kind, source.discoveryUrl, now, now));
  await db.batch(statements);
}
