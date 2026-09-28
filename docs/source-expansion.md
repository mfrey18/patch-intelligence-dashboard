# Source expansion rollout

The expansion runs on the native Node/PostgreSQL service. Existing production sources remain enabled. New connectors default to validating or pending; installing code is not a claim of production coverage.

## Source status

| Source | Implemented input | Release state / prerequisite |
| --- | --- | --- |
| Oracle | CPU/CSPU CSAF; six-month reconciliation, 64 MB document limit | Live sample validated; full replay and two distinct-day delta cycles required |
| Atlassian | Public CVE API with durable pages; cached product assertions and 6.5-second pacing | Live API currently returns empty responses/timeouts; remains validating |
| Red Hat | Official changes index and security CSAF/VEX documents | Live sample validated; non-security RHBA/RHEA entries excluded; replay/cycles required |
| VMware/Broadcom | Paginated official JSON index and linked HTML details; CSAF override retained | Two live detail matrices validated with products and explicit fixes; paginated historical replay and two delta dates required |
| Adobe | Public APSB discovery and vendor-specific HTML details | Live product/fix samples and six-month official sitemap traversal validated; bounded replay and two delta dates still required |
| Fortinet | Historical PSIRT HTML index/details; configured CSAF retained | Two live product/fix samples validated; durable index pagination implemented; historical replay and two delta dates required |
| Ivanti | Official RSS discovery to individual support advisories | Individual detail path implemented; incomplete RSS history or inaccessible/CVE-empty details blocks coverage |
| Apple | Public security-release index and component advisories; CSAF override | Live scoped product/fix samples and six-month index boundary validated; bounded replay and two delta dates still required |
| SAP | Public monthly/archive index to entitled security-note details; CSAF override | Existing SAP entitlement is required for details; public traversal does not prove note completeness |
| Citrix / NetScaler | Official sitemap/index discovery and bulletin HTML | Bounded sitemap traversal and detail classification implemented; general support sitemap cannot prove exhaustive bulletin coverage, so historical certification remains blocked |
| Chrome | Official Stable/Extended Stable release posts and pagination | Live desktop platform builds and six-month pagination validated; bounded replay and two delta dates still required |
| CVE Program | Pinned CVE List V5 JSON and daily delta log | Validation, initial queue completion and two cycles required |
| NVD | CVE API, daily modification pages and weekly reconciliation | Optional API key increases throughput; initial queue completion and two cycles required |
| VulnCheck | Community KEV backup snapshot and cited exploitation references | Server-side Community token required; attribution is displayed |

See [feed access and credential storage](feed-credentials.md) for signup links, exact runtime storage, and vendor-specific prerequisites.

## Operating the rollout

1. Apply migrations with `pnpm db:migrate`, then `pnpm db:seed`. Reader/writer default privileges must cover newly created tables as configured in `ops/postgres/roles.sql`.
2. Store source credentials only in the native service's secret environment. Restart the service after configuration changes. Missing tokens do not enable a source.
3. Run `node --import tsx scripts/validate-expansion.ts SOURCE...` for read-only live parser samples. Reports are written to ignored `work/source-expansion/`.
4. With private `API_ORIGIN` and `INGEST_SECRET`, run `SOURCE_ID=oracle-cpu-csaf INGEST_MODE=backfill node scripts/sync-expansion.mjs`. Supply `CHECKPOINT_ID=backfill:oracle:validation-1` on every invocation to resume the same manual replay. Scheduled delta requests select the oldest unfinished work automatically across UTC midnight.
5. Run two complete delta cycles on distinct days. Review provenance, product/remediation mapping, source completeness and representative output before promotion. Merely returning zero records is insufficient.
6. Run `node --import tsx scripts/source-readiness.ts SOURCE production` using the native writer environment. Promotion checks immutable completed-cycle evidence: two distinct UTC delta dates in seven days, fresh coverage, a completed six-month vendor backfill from verified historical discovery (or the initial enrichment membership), useful representative records, no unresolved work, and a fresh passing projection. Batch success cannot satisfy those gates. To stop scheduling, use `paused` and a safe public reason. Seeding preserves operator state.
7. The hourly expansion workflow reads the private readiness catalog; only enabled production sources run automatically. Vendor checkpoints and enrichment queues survive bounded attempts. No credentials are returned by the catalog endpoint.

Enrichment captures a finite membership and modification target for each cycle. CVE Program cycles pin a freshly resolved repository revision and reconcile retained records so gaps in the bounded delta log cannot lose updates; NVD resumes modification pages through the fixed target. Missing records are recorded explicitly and retried in later reconciliation; rejected records remain excluded from active totals. Work is bounded to 50 records per batch (8 for NVD without a key), with up to 50 batches or ten minutes per source invocation, including upstream cooldowns. Cisco scheduled work remains one advisory per batch while using the same 50-batch/ten-minute invocation cap. Hourly jobs isolate sources with a maximum of three running simultaneously. An initial backlog may need multiple runs. The existing six sources retain their established daily workflow.

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

## Completion and interruption

The API owns checkpoint selection. Scheduled work resumes the oldest unfinished window with its original continuation and frozen discovery pages. After completion it creates a fresh overlap window from the last completed boundary; expansion vendors periodically reconcile the retained six-month index. Explicit manual replays preserve their supplied identity.

Budget expiry and persisted cooldowns report `pending`, preserve durable progress, and never count as a completed daily cycle. Actual request failures remain visible even if a later attempt recovers. Monitoring alerts on stalled progress, old backlog, failed requests, and stale completed coverage. Source writes are fenced by the lease holder and request deadline; late responses cannot commit after cancellation.

Official HTML uses vendor-specific parsers and bounded, allowlisted retrieval. Configured document lists are subsets, not historical coverage proof. `historicalCoverage` in the private source catalog explains whether an adapter supports verified full-index traversal; it does not enable the source. The source's readiness reason, cooldown, completed coverage and active checkpoint/queue are also available there.

Architecture alternatives and the synthesis are recorded in [source-ingestion-architecture.md](source-ingestion-architecture.md).

## September 2026 deployment verification

The completion migration can expose unfinished legacy scheduled checkpoints that were previously hidden by newer successful batches. At the September 28 cutover, Microsoft still had September 17, September 19, and September 23 daily checkpoints at `offset:600`. The new runner resumed their original windows and frozen discovery, rather than treating newer completed coverage as proof that the older work had finished.

If the post-migration monitor reports this backlog, run the bounded daily runner for the affected source, preserving its default scheduled mode. Repeat bounded invocations while progress continues, then refresh the dashboard projection and recheck the private monitor. Do not delete checkpoints, synthesize completion certificates, or weaken the age alert to pass deployment.

Application readiness and the final cutover gate are separate steps. A failed cutover gate may leave the new application running after a successful migration and local readiness check. Check the deployed SHA before recovery. The installed deployment helper treats release directories as immutable; retrying deployment of an already-installed SHA is not a substitute for resolving the operational gate.
