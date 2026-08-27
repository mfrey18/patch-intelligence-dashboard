# Production source validation

The production source set remains intentionally limited to Microsoft MSRC, Cisco PSIRT, CISA KEV, FIRST EPSS, Palo Alto PSIRT, and Mozilla MFSA. A source is not promoted merely because an adapter exists.

## Acceptance checks

For every enabled source:

- discovery and fetch use the catalogued authoritative origin;
- parser fixtures preserve source identifiers, URLs, and observed timestamps;
- canonical CVEs remain separate from vendor severity, products, remediation, and exploitation assertions;
- a delta can complete or return a resumable checkpoint without losing last-known-good data;
- zero records is not treated as success evidence for historical coverage;
- failed assertions are not inferred from CVSS, EPSS, titles, or product-version patterns.

The Worker deployment smoke test exercises all panel endpoints, the Patch Tuesday reconciliation contract, and bounded CSV/JSON export. The daily operations monitor independently checks freshness, repeated failures, batch-bound pressure, projection parity/lag, leases, core latency, and D1 capacity.

## August 26, 2026 validation snapshot

The production read model contained 5,149 Microsoft, 112 Cisco, 1,002 Palo Alto, and 58 Mozilla CVEs. The Palo Alto increase followed the bounded six-month population and includes PAN-SA advisories that authoritatively republish upstream Chromium CVEs affecting Prisma Browser; those records remain Palo Alto advisory assertions and do not replace canonical CVE identity. The public sample set retained Palo Alto product provenance. Palo Alto patch availability remained unknown because the sampled CSAF assertions did not expose the shared adapter's explicit `vendor_fix` semantics; the dashboard does not infer a patch from an advisory's existence.

CISA KEV synchronized 1,676 catalog entries with no failed records. FIRST EPSS processed the bulk daily dataset and inserted 9,598 observations relevant to CVEs retained in D1. Microsoft and Cisco retained resumable checkpoints: Microsoft was still bounded under the Free-plan batch policy, while Cisco's six-month backfill remained at an April daily window. Palo Alto and Mozilla each had an inert zero-width delta checkpoint left by older orchestration; migration 0007 closes only those exact completed-work states.

The initial August Patch Tuesday validation exposed 422 Microsoft-reported CVEs but 669 linked records. The excess was exactly 247 Microsoft VEX ecosystem records incorrectly associated by publication date. Patch Tuesday membership now excludes VEX documents, legacy links are removed, and the canonical event URL is restored to Microsoft's release note. The release note's product-family table is stored as vendor-reported analytics; linked product assertions remain separately available and drive severity and threat counts.

Follow-up reconciliation found that the August release's 422 Microsoft CVEs comprise 20 Microsoft-CNA records released on August 6 plus 402 released on August 11. Date-only second-Tuesday association therefore omitted valid release membership. Microsoft ingestion now fetches one bounded SUG OData membership document per release, retains only Microsoft-CNA records assigned to that release and published through the event date, and links those CVEs without inferring severity, exploitation, or remediation. CSAF advisories continue to supply the detailed vendor assertions.

Only the six validated production sources are marked enabled for freshness monitoring. Registered adapters in later expansion groups stay hidden from production-health expectations until deliberately promoted.

## Expansion gate

Adobe, Fortinet, and Ivanti remain outside the production source list until each passes the same fixtures, bounded replay, real-output review, provenance acceptance, and partial-failure checks. Adobe and Fortinet stay fail-closed without configured authoritative structured exports. VMware/Broadcom, Citrix, Chrome, Apple, Oracle, Atlassian, and SAP remain later groups; the existence of parser code alone is not production approval.
