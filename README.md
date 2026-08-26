# Vulnerability Intelligence Dashboard

A Cloudflare-compatible vulnerability-intelligence system built with vinext, React, D1, and Drizzle. It monitors cross-vendor vulnerability disclosures, threat evidence, CISA KEV, EPSS, zero-days, and material advisory changes while keeping canonical CVE identity separate from vendor assertions. Structured remediation remains available as supporting CVE context.

The repository also includes a static GitHub Pages client. It reuses the dashboard and CVE-detail components while calling the Cloudflare-hosted read-only API. D1, vendor credentials, and ingestion remain exclusively on Cloudflare.

## Implemented vertical slice

- Microsoft Security Response Center public CSAF advisory/VEX discovery and normalization
- Cisco PSIRT OpenVuln v2 discovery with CSAF detail normalization
- CISA KEV full-snapshot synchronization with soft lifecycle changes
- FIRST EPSS bulk daily synchronization with history and model metadata
- Shared `DISCOVER -> FETCH -> VALIDATE -> NORMALIZE -> DIFF -> UPSERT -> ENRICH -> PUBLISH` contracts and policies
- Explainable P1/P2/P3 intelligence priority
- Reusable vendor release-event intelligence, including Microsoft Patch Tuesday comparison
- Filtered/cursor-paginated dashboard API and complete CVE intelligence API
- Public read-only dashboard plus protected, allowlisted internal ingestion

## Vulnerability-intelligence surfaces

The public hierarchy is vulnerability-first: six primary KPIs (total, Critical, High, known exploited, CISA KEV, and zero-days), a compact since-last-refresh strip, explainable P1/P2/P3 prioritization, and threat-first revision changes. Remediation and patch state are still retained and filterable, but appear as supporting CVE/advisory context rather than the product identity.

Dashboard analytics are computed in D1 against the active filtered six-month set:

- monthly disclosure activity by severity;
- monthly known-exploited, KEV, zero-day, and high-EPSS observations;
- same-model EPSS percentile movers over a seven-day window with one-day tolerance;
- emerging vulnerabilities with human-readable inclusion reasons;
- observed threat-signal counts by vendor;
- change-category counters and explicit canonical-CWE coverage.

`High EPSS` means a current FIRST EPSS percentile of at least 0.90. It is predictive enrichment and never creates exploitation or zero-day evidence. EPSS movers require a published current dataset, a same-model observation six to eight days earlier, and at least a five-percentile-point increase.

The Next/Worker application exposes `/vendor/[vendor]` and `/compare?cves=CVE-...,CVE-...`. The GitHub Pages client provides the same views through `#/vendor/[vendor]` and `#/compare/CVE-...,CVE-...`. Comparison accepts two or three unique, valid CVE identifiers and remains read-only and URL-shareable. Dashboard filter URLs can be copied directly with the `Copy view URL` action.

Product-scoped routes are intentionally deferred. The current affected-product records preserve authoritative names and source identifiers, but not every source provides a stable, vendor-scoped canonical product slug. The route helper therefore fails closed until that identity contract exists; it does not create permanent URLs from loosely normalized display names.

Additional adapters use the same contracts: Palo Alto Networks, Ivanti, Mozilla, Oracle, and Atlassian have verified public machine-readable discovery. Adobe, Fortinet, Apple, and SAP are fail-closed configuration adapters for official vendor/customer feeds; they never fall back to HTML scraping.

No source parser infers patch availability, fixed versions, reboot requirements, exploitation, or zero-day status from CVSS, EPSS, or version patterns.

## Local development

Requirements: Node.js 22.13+ and pnpm.

```bash
pnpm install
Copy-Item .dev.vars.example .dev.vars
pnpm dev
```

Replace the placeholder in `.dev.vars` with a long random local secret. The dashboard renders an honest empty state until the first successful ingestion; it does not ship invented vendor records.

Generate or apply the D1 schema:

```bash
pnpm db:generate
pnpm wrangler d1 execute site-creator-d1 --local --file=drizzle/0000_patch_intelligence_core.sql
pnpm wrangler d1 migrations apply site-creator-d1 --local
```

Run one source per ingestion invocation:

```bash
Invoke-RestMethod -Method Post -Uri http://localhost:3000/api/internal/ingest -Headers @{ Authorization = "Bearer $env:INGEST_SECRET" } -ContentType application/json -Body '{"sources":["microsoft-msrc-csaf"],"mode":"delta","idempotencyKey":"local-ms-delta-2026-08-21"}'
```

Allowed source IDs are centralized in `lib/ingestion/source-catalog.ts`. Exactly one source is required per invocation so a failing or subrequest-heavy adapter cannot obscure or block another source. Cisco requires OpenVuln client credentials. Adobe and Fortinet accept only official-hosted configured indexes/CSAF exports. Apple and SAP accept only allowlisted vendor-hosted CSAF URLs, with an optional bearer token. Each source commits independently and preserves last-known-good data on failure.

The public dataset targets a rolling six-month advisory/CVE window. Vendor ingestion has explicit modes:

- **Delta** is the normal three-day overlap for newly published or modified advisories. It does not scan the full window.
- **Replay** requires explicit timestamps and deterministically re-fetches a selected interval for reconciliation, revision detection, and idempotency checks.
- **Backfill** starts at the six-month boundary and advances through persisted one-day checkpoints until the requested range is complete.
- **Patch Tuesday reconciliation** is a targeted Microsoft one-day window used in addition to the daily delta.

Manual backfill dispatches default to the stable `backfill:<source>:six-month` checkpoint and accept 1-50 bounded Worker invocations per Actions run. Re-dispatch the same source until the checkpoint reports complete.

The public six-month vulnerability universe includes CVEs with a current vendor advisory and active CISA KEV entries added during the same six-month window. KEV-only records remain explicitly unattributed: vendor severity, affected products, and remediation are not inferred.

Cloudflare Workers Free permits 50 external subrequests per invocation. The shared policy processes at most 12 discovered advisory documents per invocation; with discovery and up to two retries, this keeps a conservative reserve for redirects and vendor authentication. Continuation state is persisted in D1, retries reuse deterministic idempotency keys, materially unchanged content does not create another revision, and leases are released on both success and failure.

## Validation

```bash
pnpm test
pnpm lint
pnpm build
VITE_API_BASE_URL=https://api.example.workers.dev PAGES_BASE_PATH=/repository-name/ pnpm run pages:build
pnpm run test:pages
```

The focused suites cover normalized adapter fixtures, hashing and revision diffs, canonical/vendor separation rules, remediation and exploitation semantics, KEV validation, EPSS metadata/history, explainable priority boundaries, analytics thresholds, same-model EPSS mover guards, emerging-inclusion reasons, and safe vendor/comparison routes.

## API

- `GET /api/dashboard` — filtered vulnerability summary, intelligence changes, priority distribution, activity/threat/vendor/product/CWE analytics, EPSS movers, release-event context, coverage/freshness, and cursor-paginated rows. Filter state is URL-native.
- `GET /api/dashboard?include=core` — fast metrics, rows, changes, and source health while every analytics panel loads independently.
- `GET /api/dashboard/analytics/:panel` — independently cached activity, emerging, EPSS-mover, vendor, CWE, product, and Patch Tuesday analytics.
- `GET /api/dashboard/export?format=csv|json` — bounded export of up to 1,000 filtered rows with cursor continuation.
- `GET /api/cves/:id` — canonical CVE data, vendor assertions, affected products, remediation, exploitation evidence, KEV, EPSS current/history, timeline, and source links.
- `POST /api/internal/ingest` — bearer-protected, idempotent, source-allowlisted ingestion with bounded request size and per-source leases.
- `GET /api/internal/health` — bearer-protected D1 size, row/index inventory, EPSS growth, representative query latency, and directional capacity projections.
- `POST /api/internal/retention` — bearer-protected rolling retention for EPSS history plus completed-checkpoint and expired-lease housekeeping; advisory/revision audit history is preserved.
- `POST /api/internal/projection` — bearer-protected reconciliation/population of the disposable dashboard read model.
- `GET /api/internal/monitor` — bearer-protected projection parity/freshness, source health, lease, batch-bound, and core-latency monitoring.

Cross-origin access is available only for the public read-only `GET /api/dashboard*` and `GET /api/cves/:id` routes, and only to exact origins configured through `PUBLIC_DASHBOARD_ORIGINS`. Internal routes never emit browser CORS headers.

## GitHub Pages + Cloudflare

See `docs/github-pages-cloudflare.md` for the one-time D1 setup and required GitHub repository variables/secrets. The Worker workflow validates, checks and applies backward-compatible migrations, deploys and smoke-tests the API. Only a successful Worker workflow on `main` triggers the Pages workflow, so the static client cannot race ahead of its API schema. Both production workflows share a non-cancelling concurrency group.

## Source semantics and maintenance

- CISA KEV is ingested as a complete mutable snapshot. `dateAdded` is membership date and `dueDate` is the federal remediation deadline; neither implies a patch. Valid removals are soft-ended, while malformed or suspiciously reduced snapshots are rejected.
- FIRST EPSS uses the bulk daily gzip dataset. Current score is tied to the latest published dataset date, so a CVE absent from the newest snapshot does not retain a stale current score. Historical rows remain keyed by CVE and score date.
- Microsoft and Cisco remediation/exploitation fields are normalized only when their structured source data or explicit vendor text supports them. Source-format changes require fixture updates before parser changes are promoted.
- Palo Alto uses its official RSS plus CSAF endpoint. Ivanti uses full official RSS content only. Mozilla uses bounded commit history from the official Foundation Security Advisories YAML repository so deltas include only files added or modified in the requested window. Oracle uses official quarterly CPU and monthly CSPU CSAF documents. Atlassian uses its public Vulnerability API and is rate-limited by the vendor to 10 requests/minute.
- Adobe and Fortinet require configured authoritative machine-readable endpoints; Apple exposes only HTML publicly, while SAP Security Notes require entitlement. VMware/Broadcom, Citrix, and Chrome are intentionally deferred because no stable official structured advisory feed was verified. HTML/portal parsers were not introduced.
- Daily production scheduling is limited to sources that currently satisfy both the authoritative-data policy and Workers Free execution bounds: Microsoft, Cisco, CISA KEV, FIRST EPSS, Palo Alto Networks, and Mozilla. Ivanti RSS is advisory-only for most current entries and is not claimed as complete CVE coverage. Oracle CPU/CSPU and Atlassian remain manual validation sources until their large-document/pagination paths are proven within Free-plan CPU and D1/subrequest limits.
- RSS discovery is a current-feed mechanism and cannot guarantee a complete six-month backfill. A verified vendor manifest or entitled feed is required before claiming historical completeness for those sources.
- The public query and retained EPSS trend data are constrained to a rolling six-month window. Advisory revisions, intelligence changes, and source-run audit records are retained when relational or audit value requires them.

The production-readiness decision and runbook are in `docs/production-readiness.md`. The current capacity snapshot is recorded in `docs/d1-production-baseline.md`.

Production access settings and public deployment are intentionally not changed by this repository.
