import type { CveDetailResponse } from "./contracts";

export function assertCveProvenance(detail: CveDetailResponse): void {
  const requireEvidence = (sourceId: string, url: string, observedAt: string, label: string) => {
    if (!sourceId.trim()) throw new Error(`${label} is missing a source identifier`);
    if (!/^https:\/\//i.test(url)) throw new Error(`${label} is missing an authoritative HTTPS source URL`);
    if (Number.isNaN(new Date(observedAt).getTime())) throw new Error(`${label} is missing a valid observed timestamp`);
  };

  for (const advisory of detail.advisories) requireEvidence(advisory.sourceId, advisory.sourceUrl, advisory.observedAt, `Advisory ${advisory.id}`);
  for (const product of detail.affectedProducts) requireEvidence(product.sourceId, product.sourceUrl, product.observedAt, `Affected product ${product.product}`);
  for (const remediation of detail.remediations) requireEvidence(remediation.sourceId, remediation.sourceUrl, remediation.observedAt, `Remediation ${remediation.advisoryId}`);
  for (const evidence of detail.exploitation.evidence) requireEvidence(evidence.sourceId, evidence.url, evidence.observedAt, `Exploitation evidence ${evidence.type}`);
  if (detail.kev) requireEvidence(detail.kev.sourceId, detail.kev.sourceUrl, detail.kev.observedAt, "CISA KEV assertion");
  for (const observation of detail.epss.history) requireEvidence(observation.sourceId, observation.sourceUrl, observation.observedAt, `EPSS observation ${observation.scoreDate}`);

  const components = detail.priority.components;
  if (components.kev !== Boolean(detail.kev?.active)) throw new Error("Priority KEV component does not match the sourced KEV assertion");
  if ((components.exploitationStatus === "known_exploited") !== detail.exploitation.knownExploited) throw new Error("Priority exploitation component does not match authoritative evidence");
  if (components.epssPercentile !== (detail.epss.current?.percentile ?? null)) throw new Error("Priority EPSS component does not match the current FIRST dataset");
  if (!detail.priority.reasons.length) throw new Error("Priority is missing human-readable reasons");
}
