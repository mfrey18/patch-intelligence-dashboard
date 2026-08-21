# D1 production baseline

This document records read-only production observations before the Free-plan/six-month migration and provides the procedure for capturing the post-migration baseline. It is intentionally evidence-driven; D1 is not sharded or redesigned without measured need.

## Baseline fields

The authenticated `GET /api/internal/health` endpoint captures:

- database bytes from SQLite page count × page size;
- row counts for major intelligence, enrichment, audit, checkpoint, and lease tables;
- non-automatic index inventory;
- largest tables by row count;
- EPSS observation count, dataset-day count, date range, and observations per dataset day;
- representative dashboard-summary, priority-signal, current-EPSS, and source-health query latency;
- the slowest measured important query;
- directional current, +6-month, and +12-month row/byte projections.

Projections retain only a rolling six months of EPSS observations while projecting advisory/revision/change/run audit growth linearly from observed activity. Whole-database average bytes per row makes the byte figures directional rather than a storage guarantee.

## Pre-migration production snapshot

Capture date: 2026-08-21. Database: `patch-intelligence-prod` (`f908eb4e-eed5-4a09-afc2-ba090b09b42f`). Read-only Wrangler queries reported 5,541,888 bytes and 11,820 rows across the major tables measured below.

| Table | Rows |
| --- | ---: |
| intelligence_changes | 1,828 |
| cves | 1,750 |
| exploit_evidence | 1,722 |
| epss_observations | 1,699 |
| kev_entries | 1,673 |
| affected_products | 1,414 |
| remediations | 1,140 |
| source_run_results | 365 |
| advisory_cves | 77 |
| advisories | 71 |
| advisory_revisions | 71 |
| source_runs | 9 |
| epss_datasets | 1 |

EPSS contains 1,699 observations for one dataset day (`2026-08-20`), so its current observed growth rate is 1,699 tracked-CVE observations for each retained daily snapshot. This is a startup sample, not a mature trend.

The database had 22 named non-automatic indexes. Existing coverage includes CVE identity, advisory publication, vendor/advisory identity, severity, revision hashes/observation time, affected-product and remediation CVE/revision joins, KEV state/deadline, EPSS date, intelligence-change time/CVE, source-run identity/time, and product/vendor identity. Migration `0001` adds composite indexes for vendor/publication and modification filters, exploitation and remediation state, product/CVE/revision joins, current EPSS selection, change-type/time, checkpoint lookup, and source-run status/checkpoints. Priority remains derived from indexed KEV/exploitation/severity/EPSS components rather than storing a stale opaque score.

Representative production SQL timings were:

| Query | D1 SQL duration |
| --- | ---: |
| priority-signal count | 3.1244 ms |
| current EPSS join | 2.8560 ms |
| rolling six-month summary | 2.1854 ms |
| latest source-run health | 0.5275 ms |

The priority-signal component query was the slowest of these four SQL probes. However, the existing production `GET /api/dashboard?limit=1` request exceeded a 20-second client timeout without filters; a Microsoft-filtered request returned in approximately 19.8 seconds, while Cisco and Critical-filtered requests also exceeded 20 seconds. Worker root and invalid-CVE routes remained responsive, isolating the issue to dashboard composition rather than Worker reachability.

The implementation now removes the multiplicative `affected_products × remediations × exploit_evidence` join from the dashboard CTE and replaces it with indexed existence/scalar lookups. The authenticated health capture measures the complete default dashboard API composition as `dashboard_api_default`, not only component probes. Post-deployment latency must be recorded before Gate #1 can pass. No D1 redesign or sharding is supported until that optimized query is measured.

Directional capacity estimates use the observed 1,699 EPSS rows/day, a 183-day retained window, the current whole-database average of 468.86 bytes/row, and a startup allowance of 60 audit/run rows/day until at least seven representative production days exist:

| Horizon | Estimated rows | Estimated bytes |
| --- | ---: | ---: |
| complete current six-month window | 321,038 | 150,520,866 (143.55 MiB) |
| 6 additional months | 332,018 | 155,668,915 (148.46 MiB) |
| 12 additional months | 342,998 | 160,816,963 (153.37 MiB) |

Because EPSS is rolling, it approaches a bounded six-month plateau; the additional growth shown is retained advisory/revision/change/run audit data. Recalculate after a representative week and after completing the six-month backfill.

The new `ingestion_checkpoints` table and source-run metadata do not exist in production until migration `0001_free_plan_six_month.sql` is explicitly reviewed and applied by the ordered deployment workflow.

## Post-migration capture

```bash
curl --fail --silent \
  -H "Authorization: Bearer $INGEST_SECRET" \
  "$PUBLIC_API_BASE_URL/api/internal/health"
```

Record the output with the Worker version and migration list before invoking retention. Investigate query plans or indexes if an important dashboard query is materially slower than its peers; do not shard preemptively.
