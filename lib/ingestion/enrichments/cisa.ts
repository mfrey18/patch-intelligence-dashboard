import type { IngestResult } from "../contracts";
import { D1IngestionRepository } from "../d1-repository";
import { sha256, stableSerialize } from "../hash";
import { DEFAULT_SOURCE_POLICY } from "../contracts";
import { fetchWithPolicy, readJsonLimited, sanitizeText } from "../safety";
import { list, record, stringValue, validCve } from "../adapters/utils";

export const CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
export const CISA_KEV_FALLBACK_URL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json";

export interface CisaKevEntry { cveId: string; vendorProject: string; product: string; vulnerabilityName: string; dateAdded: string; shortDescription: string; requiredAction: string; dueDate: string; knownRansomwareCampaignUse?: string; notes?: string; cwes: string[]; }
export interface CisaKevSnapshot { catalogVersion: string; dateReleased: string; count: number; entries: CisaKevEntry[]; sourceUrl: string; }

export function parseCisaKevSnapshot(payload: unknown, sourceUrl = CISA_KEV_URL): CisaKevSnapshot {
  const root = record(payload);
  const dateReleased = requiredString(root.dateReleased, "dateReleased");
  if (Number.isNaN(new Date(dateReleased).getTime())) throw new Error("CISA KEV dateReleased is invalid");
  const values = list(root.vulnerabilities);
  const count = Number(root.count);
  if (!Number.isInteger(count) || count !== values.length) throw new Error("CISA KEV count does not match vulnerabilities length");
  const seen = new Set<string>();
  const entries = values.map((value): CisaKevEntry => {
    const item = record(value);
    const cveId = validCve(item.cveID);
    if (!cveId) throw new Error("CISA KEV entry contains an invalid CVE ID");
    if (seen.has(cveId)) throw new Error(`CISA KEV contains duplicate ${cveId}`);
    seen.add(cveId);
    const dateAdded = requiredString(item.dateAdded, `${cveId}.dateAdded`);
    const dueDate = requiredString(item.dueDate, `${cveId}.dueDate`);
    if (Number.isNaN(new Date(dateAdded).getTime()) || Number.isNaN(new Date(dueDate).getTime())) throw new Error(`CISA KEV contains an invalid date for ${cveId}`);
    return { cveId, vendorProject: requiredString(item.vendorProject, `${cveId}.vendorProject`), product: requiredString(item.product, `${cveId}.product`), vulnerabilityName: requiredString(item.vulnerabilityName, `${cveId}.vulnerabilityName`), dateAdded, shortDescription: requiredString(item.shortDescription, `${cveId}.shortDescription`), requiredAction: requiredString(item.requiredAction, `${cveId}.requiredAction`), dueDate, knownRansomwareCampaignUse: stringValue(item.knownRansomwareCampaignUse), notes: stringValue(item.notes), cwes: list(item.cwes).map(stringValue).filter(Boolean) as string[] };
  });
  return { catalogVersion: requiredString(root.catalogVersion, "catalogVersion"), dateReleased: new Date(dateReleased).toISOString(), count, entries, sourceUrl };
}

export async function ingestCisaKev(db: D1Database, idempotencyKey?: string): Promise<IngestResult> {
  const repository = new D1IngestionRepository(db);
  const startedAt = new Date().toISOString();
  const metadata = { mode: "delta" as const, maxItems: 1 };
  const { runId, reused } = await repository.beginRun("cisa-kev", idempotencyKey, metadata);
  const empty = { discovered: 0, inserted: 0, changed: 0, unchanged: 0, failed: 0 };
  const runFields = { mode: metadata.mode, window: {}, processed: 1, continuation: null, boundHit: false };
  if (reused) return { sourceId: "cisa-kev", runId, status: "unchanged", ...runFields, processed: 0, counts: empty, errors: [], startedAt, completedAt: new Date().toISOString() };
  try {
    let response: Response;
    let sourceUrl = CISA_KEV_URL;
    try { response = await fetchWithPolicy(CISA_KEV_URL, DEFAULT_SOURCE_POLICY); }
    catch { sourceUrl = CISA_KEV_FALLBACK_URL; response = await fetchWithPolicy(sourceUrl, DEFAULT_SOURCE_POLICY); }
    const snapshot = parseCisaKevSnapshot(await readJsonLimited(response, DEFAULT_SOURCE_POLICY.maxResponseBytes), sourceUrl);
    const existingRows = await db.prepare("SELECT cve_id, due_date, entry_hash, active FROM kev_entries").all<{ cve_id: string; due_date: string | null; entry_hash: string; active: number }>();
    const existing = new Map((existingRows.results ?? []).map((row) => [row.cve_id, row]));
    const activeCount = [...existing.values()].filter((row) => Boolean(row.active)).length;
    if (activeCount > 100 && snapshot.count < activeCount * 0.9) throw new Error("CISA KEV snapshot is suspiciously smaller than the last known-good snapshot");
    const latest = await db.prepare("SELECT dataset_date FROM source_runs WHERE source_id='cisa-kev' AND status IN ('success','unchanged') AND dataset_date IS NOT NULL ORDER BY dataset_date DESC LIMIT 1").first<{ dataset_date: string }>();
    if (latest && new Date(snapshot.dateReleased) < new Date(latest.dataset_date)) throw new Error("CISA KEV snapshot date regressed");

    const now = new Date().toISOString();
    const counts = { discovered: snapshot.count, inserted: 0, changed: 0, unchanged: 0, failed: 0 };
    const seen = new Set<string>();
    const statements: D1PreparedStatement[] = [];
    for (const entry of snapshot.entries) {
      seen.add(entry.cveId);
      const entryHash = await sha256(entry);
      const previous = existing.get(entry.cveId);
      const changeTypes = !previous ? ["KEV_ADDED"] : previous.due_date !== entry.dueDate ? ["KEV_DEADLINE_CHANGED", ...(previous.entry_hash !== entryHash ? ["KEV_ENTRY_MODIFIED"] : [])] : previous.entry_hash !== entryHash ? ["KEV_ENTRY_MODIFIED"] : [];
      if (!previous) counts.inserted += 1; else if (changeTypes.length) counts.changed += 1; else counts.unchanged += 1;
      statements.push(db.prepare("INSERT INTO cves (id, created_at, updated_at) VALUES (?, ?, ?) ON CONFLICT(id) DO UPDATE SET updated_at=excluded.updated_at").bind(entry.cveId, now, now));
      statements.push(db.prepare("INSERT INTO kev_entries (cve_id, source_run_id, active, date_added, due_date, required_action, known_ransomware_campaign_use, entry_hash, source_url, first_observed_at, last_observed_at, removed_at) VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, NULL) ON CONFLICT(cve_id) DO UPDATE SET source_run_id=excluded.source_run_id, active=1, date_added=excluded.date_added, due_date=excluded.due_date, required_action=excluded.required_action, known_ransomware_campaign_use=excluded.known_ransomware_campaign_use, entry_hash=excluded.entry_hash, source_url=excluded.source_url, last_observed_at=excluded.last_observed_at, removed_at=NULL").bind(entry.cveId, runId, entry.dateAdded, entry.dueDate, sanitizeText(entry.requiredAction) ?? entry.requiredAction, entry.knownRansomwareCampaignUse ?? null, entryHash, snapshot.sourceUrl, now, now));
      statements.push(db.prepare("INSERT INTO exploit_evidence (id, cve_id, advisory_id, source_id, evidence_type, status, evidence_date, evidence_url, summary, first_observed_at, last_observed_at) VALUES (?, ?, NULL, 'cisa-kev', 'known_exploitation', 'confirmed', ?, ?, ?, ?, ?) ON CONFLICT(cve_id, source_id, evidence_type, evidence_url) DO UPDATE SET status='confirmed', evidence_date=excluded.evidence_date, summary=excluded.summary, last_observed_at=excluded.last_observed_at").bind(`${entry.cveId}:cisa-kev`, entry.cveId, entry.dateAdded, snapshot.sourceUrl, `CISA KEV: ${sanitizeText(entry.vulnerabilityName) ?? entry.vulnerabilityName}`, now, now));
      for (const changeType of changeTypes) statements.push(db.prepare("INSERT INTO intelligence_changes (id, source_run_id, entity_type, entity_id, cve_id, change_type, observed_at, before_json, after_json, summary) VALUES (?, ?, 'kev_entry', ?, ?, ?, ?, ?, ?, ?)").bind(crypto.randomUUID(), runId, entry.cveId, entry.cveId, changeType, now, previous ? JSON.stringify({ dueDate: previous.due_date, entryHash: previous.entry_hash }) : null, JSON.stringify({ dueDate: entry.dueDate, entryHash }), changeType === "KEV_ADDED" ? `${entry.cveId} added to CISA KEV` : changeType === "KEV_DEADLINE_CHANGED" ? `${entry.cveId} KEV deadline changed` : `${entry.cveId} KEV entry revised`));
    }
    for (const [cveId, previous] of existing) if (previous.active && !seen.has(cveId)) {
      counts.changed += 1;
      statements.push(db.prepare("UPDATE kev_entries SET active=0, removed_at=?, last_observed_at=?, source_run_id=? WHERE cve_id=?").bind(now, now, runId, cveId));
      statements.push(db.prepare("INSERT INTO intelligence_changes (id, source_run_id, entity_type, entity_id, cve_id, change_type, observed_at, before_json, after_json, summary) VALUES (?, ?, 'kev_entry', ?, ?, 'KEV_REMOVED', ?, ?, ?, ?)").bind(crypto.randomUUID(), runId, cveId, cveId, now, JSON.stringify({ active: true }), JSON.stringify({ active: false }), `${cveId} removed from current CISA KEV snapshot`));
    }
    for (let index = 0; index < statements.length; index += 75) await db.batch(statements.slice(index, index + 75));
    const snapshotHash = await sha256(stableSerialize(snapshot.entries));
    await db.prepare("UPDATE source_runs SET dataset_date=?, source_hash=? WHERE id=?").bind(snapshot.dateReleased, snapshotHash, runId).run();
    const status = counts.inserted + counts.changed > 0 ? "success" : "unchanged";
    await repository.finishRun(runId, { status, ...runFields, counts, errors: [] });
    return { sourceId: "cisa-kev", runId, status, ...runFields, counts, errors: [], startedAt, completedAt: new Date().toISOString() };
  } catch (error) {
    const message = error instanceof Error ? error.message : "CISA KEV ingestion failed";
    const counts = { ...empty, failed: 1 };
    await repository.finishRun(runId, { status: "failed", ...runFields, counts, errors: [message] });
    return { sourceId: "cisa-kev", runId, status: "failed", ...runFields, counts, errors: [message], startedAt, completedAt: new Date().toISOString() };
  }
}

function requiredString(value: unknown, field: string): string { const text = stringValue(value)?.trim(); if (!text) throw new Error(`CISA KEV is missing ${field}`); return text; }
