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

## Snapshot before this milestone

The August 26, 2026 production snapshot contained 5,149 Microsoft, 112 Cisco, 58 Mozilla, and zero Palo Alto CVEs in the six-month read model. The Palo Alto source was fresh but its latest three-day delta correctly discovered zero new records; that did **not** prove historical population. The authoritative RSS feed and `/csaf/{advisory-id}` JSON endpoint were verified independently. A resumable six-month Palo Alto backfill is therefore required before its coverage can be described as populated.

Microsoft's repeated batch-bound warning reflected the completed high-volume historical population and is expected to age out of the 24-hour alert window. It remains actionable if it recurs during ordinary daily delta operation.

## Expansion gate

Adobe, Fortinet, and Ivanti remain outside the production source list until each passes the same fixtures, bounded replay, real-output review, provenance acceptance, and partial-failure checks. Adobe and Fortinet stay fail-closed without configured authoritative structured exports. VMware/Broadcom, Citrix, Chrome, Apple, Oracle, Atlassian, and SAP remain later groups; the existence of parser code alone is not production approval.
