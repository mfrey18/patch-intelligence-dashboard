import type { NormalizedAdvisory, NormalizedAffectedProduct, NormalizedExploitEvidence, NormalizedReleaseEvent, NormalizedRemediation, VendorId } from "../../domain/types";
import type { RawAdvisory } from "../contracts";
import { firstString, iso, list, normalizeSeverity, numberValue, path, record, stringValue, uniqueBy, validCve } from "./utils";

interface CsafOptions {
  vendor: VendorId;
  sourceId: string;
  splitByCve?: boolean;
  advisoryIdPrefix?: string;
  releaseEvent?(publishedAt: string, sourceUrl: string): NormalizedReleaseEvent | undefined;
}

/** Shared CSAF 2.x semantics used by every CSAF-backed vendor adapter. */
export function normalizeCsaf(raw: RawAdvisory, sanitize: (value: unknown) => string | undefined, options: CsafOptions): NormalizedAdvisory[] {
  const root = record(raw.body);
  const document = record(root.document);
  const tracking = record(document.tracking);
  const baseId = firstString(tracking.id, raw.ref.id) ?? raw.ref.id;
  const title = sanitize(document.title) ?? baseId;
  const notes = list(document.notes).map((note) => sanitize(record(note).text)).filter(Boolean) as string[];
  const publishedAt = iso(tracking.initial_release_date);
  const sourceUpdatedAt = iso(tracking.current_release_date) ?? raw.ref.sourceUpdatedAt ?? raw.lastModified;
  const products = productNames(root.product_tree);
  const cves: NormalizedAdvisory["cves"] = [];
  const affectedProducts: NormalizedAffectedProduct[] = [];
  const remediations: NormalizedRemediation[] = [];
  const exploitEvidence: NormalizedExploitEvidence[] = [];

  for (const rawVulnerability of list(root.vulnerabilities)) {
    const vulnerability = record(rawVulnerability);
    const cveId = validCve(vulnerability.cve);
    if (!cveId) continue;
    const scores = list(vulnerability.scores).map(record);
    const scoreObject = scores.map((entry) => record(entry.cvss_v4 ?? entry.cvss_v3 ?? entry.cvss_v2)).find((entry) => Object.keys(entry).length > 0) ?? {};
    const cvssScore = numberValue(scoreObject.baseScore ?? scoreObject.base_score);
    const cvssVector = firstString(scoreObject.vectorString, scoreObject.vector_string);
    const aggregateSeverity = firstString(path(document, "aggregate_severity", "text"));
    const severityText = firstString(scoreObject.baseSeverity, scoreObject.base_severity, vulnerability.severity, aggregateSeverity);
    const vulnerabilityNotes = list(vulnerability.notes).map((note) => sanitize(record(note).text)).filter(Boolean) as string[];
    const cweValue = record(vulnerability.cwe);
    cves.push({ cveId, description: vulnerabilityNotes.find((note) => note.length > 40), cwe: firstString(cweValue.id, vulnerability.cwe), vendorSeverity: severityText, normalizedSeverity: normalizeSeverity(severityText, cvssScore), cvssScore, cvssVector, publishedAt, modifiedAt: sourceUpdatedAt });

    for (const [rawStatus, ids] of Object.entries(record(vulnerability.product_status))) {
      const status = rawStatus === "known_affected" || rawStatus === "under_investigation" ? "affected" : rawStatus === "fixed" ? "fixed" : rawStatus === "known_not_affected" ? "unaffected" : "unknown";
      for (const productId of list(ids).map(stringValue).filter(Boolean) as string[]) affectedProducts.push({ cveId, sourceProductId: productId, name: products.get(productId) ?? productId, status });
    }

    for (const rawRemediation of list(vulnerability.remediations)) {
      const remediation = record(rawRemediation);
      const category = (firstString(remediation.category) ?? "vendor_action").toLowerCase();
      const kind = category === "vendor_fix" ? "patch" : category === "workaround" ? "workaround" : category === "mitigation" ? "mitigation" : "vendor_action";
      const action = sanitize(remediation.details);
      const fixedVersion = firstString(remediation.fixed_version, remediation.fixed_release);
      const explicitRestart = remediation.restart_required;
      const rebootRequired = typeof explicitRestart === "boolean" ? explicitRestart : /(?:restart|reboot) (?:is )?required/i.test(action ?? "") ? true : undefined;
      const base = { cveId, kind, patchAvailable: category === "vendor_fix" ? true : undefined, fixedVersion, action, rebootRequired, sourceUrl: firstString(remediation.url) ?? raw.resolvedUrl, publishedAt: iso(remediation.date), updatedAt: sourceUpdatedAt } satisfies NormalizedRemediation;
      const productIds = list(remediation.product_ids).map(stringValue).filter(Boolean) as string[];
      remediations.push(...(productIds.length ? productIds.map((id) => ({ ...base, productName: products.get(id) ?? id })) : [base]));
    }

    for (const rawThreat of list(vulnerability.threats)) {
      const threat = record(rawThreat);
      const category = (firstString(threat.category) ?? "").toLowerCase();
      const details = sanitize(threat.details) ?? "";
      if (category !== "exploit_status") continue;
      const notKnown = /(?:no evidence|not aware)[^.]{0,160}(?:being |been |actively )?exploited|no known exploitation|exploited\s*:\s*no/i.test(details);
      const known = !notKnown && /known exploited|exploitation (?:has been )?(?:observed|detected)|actively exploited|exploited\s*:\s*yes/i.test(details);
      const notZeroDay = /not (?:a |an )?zero[- ]day|no evidence[^.]{0,160}zero[- ]day/i.test(details);
      const zeroDay = !notZeroDay && /zero[- ]day/i.test(details);
      const publicDisclosure = /publicly disclosed\s*:\s*yes|public disclosure confirmed/i.test(details);
      const evidenceDate = iso(threat.date) ?? sourceUpdatedAt;
      const evidenceUrl = firstString(threat.url) ?? raw.resolvedUrl;
      if (known || notKnown) exploitEvidence.push({ cveId, type: "known_exploitation", status: known ? "confirmed" : "not_confirmed", evidenceDate, evidenceUrl, summary: details });
      if (publicDisclosure) exploitEvidence.push({ cveId, type: "public_disclosure", status: "confirmed", evidenceDate, evidenceUrl, summary: details });
      if (zeroDay || notZeroDay) exploitEvidence.push({ cveId, type: "zero_day", status: zeroDay ? "confirmed" : "not_confirmed", evidenceDate, evidenceUrl, summary: details });
    }
  }

  const normalizedCves = uniqueBy(cves, (item) => item.cveId);
  const releaseEvent = publishedAt ? options.releaseEvent?.(publishedAt, raw.resolvedUrl) : undefined;
  const makeAdvisory = (selectedCves: NormalizedAdvisory["cves"], suffix?: string): NormalizedAdvisory => {
    const selected = new Set(selectedCves.map((item) => item.cveId));
    const selectedEvidence = exploitEvidence.filter((item) => selected.has(item.cveId));
    const highest = [...selectedCves].sort((a, b) => (b.cvssScore ?? -1) - (a.cvssScore ?? -1))[0];
    const hasKnown = selectedEvidence.some((item) => item.type === "known_exploitation" && item.status === "confirmed");
    const hasExplicitNegative = selectedEvidence.some((item) => item.type === "known_exploitation" && item.status === "not_confirmed");
    const hasZeroDay = selectedEvidence.some((item) => item.type === "zero_day" && item.status === "confirmed");
    const hasExplicitNonZeroDay = selectedEvidence.some((item) => item.type === "zero_day" && item.status === "not_confirmed");
    const prefixedId = options.advisoryIdPrefix ? `${options.advisoryIdPrefix}:${baseId}` : baseId;
    return { vendor: options.vendor, sourceId: options.sourceId, vendorAdvisoryId: suffix ? `${prefixedId}:${suffix}` : prefixedId, title: suffix ? `${suffix} — ${title}` : title, summary: notes.find((note) => note.length > 40) ?? highest?.description, sourceUrl: raw.resolvedUrl, publishedAt, sourceUpdatedAt, vendorSeverity: highest?.vendorSeverity, cvssScore: highest?.cvssScore, exploitationStatus: hasKnown ? "known_exploited" : hasExplicitNegative ? "not_known_exploited" : "unknown", zeroDayStatus: hasZeroDay ? "confirmed" : hasExplicitNonZeroDay ? "not_confirmed" : "unknown", cves: selectedCves, affectedProducts: uniqueBy(affectedProducts.filter((item) => !item.cveId || selected.has(item.cveId)), (item) => `${item.cveId}|${item.sourceProductId}|${item.status}`), remediations: uniqueBy(remediations.filter((item) => !item.cveId || selected.has(item.cveId)), (item) => `${item.cveId}|${item.productName}|${item.kind}|${item.fixedVersion}|${item.action}`), exploitEvidence: uniqueBy(selectedEvidence, (item) => `${item.cveId}|${item.type}|${item.status}|${item.evidenceUrl}`), releaseEvent };
  };

  return options.splitByCve ? normalizedCves.map((item) => makeAdvisory([item], item.cveId)) : [makeAdvisory(normalizedCves)];
}

function productNames(tree: unknown): Map<string, string> {
  const names = new Map<string, string>();
  const visit = (value: unknown) => { for (const item of list(value)) { const branch = record(item); const product = record(branch.product); const id = firstString(product.product_id); const name = firstString(product.name, branch.name); if (id && name) names.set(id, name); visit(branch.branches); } };
  visit(record(tree).branches);
  return names;
}
