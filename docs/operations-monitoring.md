# Production operations monitoring

The immediate post-deployment monitoring layer is intentionally bounded for Cloudflare Workers Free and keeps Cloudflare management credentials out of the Worker.

## Daily checks

The `Production operations monitor` GitHub Actions workflow runs daily after the normal ingestion window and can also be dispatched manually. It:

- calls authenticated `GET /api/internal/monitor`;
- requires a non-empty, parity-checked projection;
- checks that projection state count matches the stored fact count;
- detects a projection older than, or behind, successful ingestion;
- checks the six production sources for freshness and newer failures;
- reports repeated Free-plan batch-bound hits;
- reports active ingestion or projection leases;
- measures the dashboard core query and warns above 1,000 ms;
- queries D1 size and rolling 24-hour row usage with narrowly scoped Cloudflare deployment credentials, warns at 4,000,000 rows read or 80,000 rows written, and fails at 400,000,000 bytes;
- archives the complete JSON result for 30 days.

Warnings create GitHub Actions annotations. Critical alerts set monitor status to `unhealthy` and fail the workflow. The scheduled ingestion housekeeping job runs the same authenticated health gate immediately after publishing its single daily projection.

## Projection publication

Projection refresh follows:

1. Acquire the projection lease.
2. Build `cve_dashboard_facts_staging` from authoritative normalized tables.
3. Compare canonical and staged metrics.
4. If parity fails, record the failure and preserve current facts.
5. If parity passes, atomically delete stale facts, insert new facts, and update only materially changed static or volatile fields before publishing parity metadata.
6. Release the lease on success or failure.

Parity covers total CVEs, Critical, High, known exploitation, CISA KEV, zero-day, patch availability, P1/P2/P3, Microsoft, and Cisco counts. This is an acceptance guard, not a replacement for detailed source fixtures or CVE-detail provenance tests.

## Response guidance

- `projection_missing`, `projection_count_mismatch`, or `projection_parity_unverified`: stop publication changes and inspect the latest projection attempt.
- `projection_behind_ingestion`: run one authenticated projection refresh after confirming ingestion is idle.
- `source_stale` or `source_latest_attempt_failed`: investigate only that source; do not disable other adapters.
- `source_repeated_bound_hits`: inspect the checkpoint and increase workflow attempts only if each Worker invocation remains within the configured bound.
- `ingestion_lease_active` or `projection_lease_active`: confirm a run is actually active; retention clears expired operational state.
- `dashboard_core_slow`: inspect structured `dashboard_query` logs and the archived D1 baseline before changing indexes.
- `d1_rows_read_pressure` or `d1_rows_written_pressure`: inspect D1 query insights before the UTC reset; these warnings use a rolling 24-hour observation and are early-pressure indicators rather than billing-day counters.
- D1 size at or above 400 MB: review rolling EPSS retention and table growth before the Free-plan ceiling is approached; do not delete audit-critical revision history.
