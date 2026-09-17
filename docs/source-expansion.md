# Source expansion rollout

The expansion runs on the native Node/PostgreSQL service. Existing production sources remain enabled. New connectors default to validating or pending; installing code is not a claim of production coverage.

## Source status

| Source | Implemented input | Release state / prerequisite |
| --- | --- | --- |
| Oracle | CPU/CSPU CSAF; six-month reconciliation, 64 MB document limit | Live sample validated; full replay and two distinct-day delta cycles required |
| Atlassian | Public CVE API with durable pages; cached product assertions and 6.5-second pacing | Live API currently returns empty responses/timeouts; remains validating |
| Red Hat | Official changes index and security CSAF/VEX documents | Live sample validated; non-security RHBA/RHEA entries excluded; replay/cycles required |
| VMware/Broadcom | Public paginated advisory JSON index; optional configured CSAF override | POST endpoint validated on September 17; advisory/CVE mappings available, complete product/fix details absent; remains gated |
| Adobe | Configured official structured index | Verified feed/configuration required |
| Fortinet | RSS discovery with configured official CSAF template | Verified accessible export required |
| Ivanti | Configured official CSAF override; legacy RSS remains manual-only | RSS is incomplete; complete structured mapping required |
| Apple / SAP | Configured official CSAF documents | Verified feed; SAP entitlement/publication rights required |
| Citrix / Chrome | Configured official CSAF documents | No complete public feed verified; no automatic coverage claimed |
| CVE Program | Pinned CVE List V5 JSON and daily delta log | Validation, initial queue completion and two cycles required |
| NVD | CVE API, daily modification pages and weekly reconciliation | Optional API key increases throughput; initial queue completion and two cycles required |
| VulnCheck | Community KEV backup snapshot and cited exploitation references | Server-side Community token required; attribution is displayed |

See [feed access and credential storage](feed-credentials.md) for signup links, exact runtime storage, and vendor-specific prerequisites.

## Operating the rollout

1. Apply migrations with `pnpm db:migrate`, then `pnpm db:seed`. Reader/writer default privileges must cover newly created tables as configured in `ops/postgres/roles.sql`.
2. Store source credentials only in the native service's secret environment. Restart the service after configuration changes. Missing tokens do not enable a source.
3. Run `node --import tsx scripts/validate-expansion.ts SOURCE...` for read-only live parser samples. Reports are written to ignored `work/source-expansion/`.
4. With private `API_ORIGIN` and `INGEST_SECRET`, run `SOURCE_ID=oracle-cpu-csaf INGEST_MODE=backfill node scripts/sync-expansion.mjs`. Repeat to resume the same dated checkpoint; use workflow-dispatch's explicit checkpoint ID for longer backfills.
5. Run two complete delta cycles on distinct days. Review provenance, product/remediation mapping, source completeness and representative output before promotion. Merely returning zero records is insufficient.
6. Run `node --import tsx scripts/source-readiness.ts SOURCE production` using the native writer environment. Promotion checks completed cycles and vendor backfill coverage. To stop scheduling, use `paused` and a safe public reason. Seeding preserves operator state.
7. The hourly expansion workflow reads the private readiness catalog; only enabled production sources run automatically. Vendor checkpoints and enrichment queues survive bounded attempts. No credentials are returned by the catalog endpoint.

Enrichment refreshes newly queued CVEs, polls source changes daily and reconciles records weekly. Work is bounded to 50 records per batch (8 for NVD without a key), with up to 30 attempts per source per workflow. An initial backlog may need multiple runs. The existing six sources retain their established daily workflow.

## Data semantics

- The public universe remains current six-month vendor advisories plus active CISA/VulnCheck entries added within six months. Bootstrap observation time never replaces source addition time.
- Canonical descriptions/dates prefer the CNA record. Assessments prefer CNA, then NVD, then other providers; within a provider prefer CVSS 4.0, 3.1, 3.0, then 2.0. Alternatives and provenance remain visible.
- Vendor severity stays primary in dashboard ranking; canonical values fill unknown assessments. Rejected CVEs remain available by ID but are excluded from active totals.
- VulnCheck does not write CISA membership. Its catalog assertion and cited exploitation reports create source-labelled exploitation evidence. XDB links are retained as references, never interpreted as zero-day evidence.
- Removing a catalog entry deactivates membership without claiming exploitation never occurred. Corrected evidence within a present, validated entry retires superseded source references.
- Incomplete or suspiciously shrinking snapshots never replace the last good membership set. API keys are not forwarded to snapshot download hosts.

## Validation and rollback

Run `pnpm lint`, `pnpm typecheck`, `pnpm test`, `pnpm pages:build` and the local/public browser suites. Integration tests cover canonical/projection parity, fallback scores, source filters, rejected records, snapshot semantics and durable discovery retry.

Before release, capture the native database backup and prior deployed SHA. Pause a faulty source, keep audit history, and restore the previous application release/projection when needed. Additive migrations can remain installed when rolling back the application.

A source is **live** only after promotion and verified scheduled cycles. Sources lacking feeds/credentials remain explicitly pending. Do not describe the entire roster as live when these prerequisites are outstanding.
