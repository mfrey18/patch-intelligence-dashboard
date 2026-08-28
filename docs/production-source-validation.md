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

## August 27, 2026 expansion-source validation

No source in this group was promoted. The shared fixtures pass, but a parser fixture is only one part of the production gate; the live authoritative distribution must also provide complete, repeatable input to the same contract.

| Source | Live authoritative result | Production decision |
| --- | --- | --- |
| Adobe PSIRT | The public security bulletin index is HTML and exposes no verified JSON/CSAF discovery feed. Supplying that page to the JSON adapter is rejected, and the standard CSAF provider-metadata locations return 404. | **Quarantined / fail closed.** Enable only after Adobe supplies a verified official structured index, configured through `ADOBE_SECURITY_INDEX_URL`. |
| Fortinet PSIRT | The official RSS feed is reachable and returned 44 advisories in the rolling window. The advisory site advertises CSAF downloads, but automated access is challenge-protected; no verified direct export template or CSAF provider metadata was available. A guessed official-host template returned 404 and is not accepted as production configuration. | **Quarantined / fail closed.** Enable only after a direct official CSAF URL template or authenticated export is obtained and a bounded replay succeeds. |
| Ivanti | The official RSS feed returned eight security-update posts in the rolling window. Only one post named a CVE, none supplied structured affected-product assertions, and generic monthly patch language appeared independently of CVE-level detail. | **Quarantined / incomplete.** Do not promote the RSS-only adapter until an authoritative advisory source supplies dependable CVE, product, and remediation mappings. |

The default-source resolver is restricted to `PRODUCTION_SOURCE_IDS`, so credentials or adapter registration alone cannot silently promote a quarantined source. Ivanti normalization also refuses to create remediation rows from generic RSS patch language when the item asserts no CVE.
