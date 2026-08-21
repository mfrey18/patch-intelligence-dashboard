# Patch Intelligence Dashboard

A Cloudflare-compatible operational patch-intelligence system built with vinext, React, D1, and Drizzle. It keeps canonical CVE identity separate from vendor assertions and preserves advisory revisions, structured remediation, authoritative exploitation evidence, CISA KEV state, and daily FIRST EPSS observations.

The repository also includes a static GitHub Pages client. It reuses the dashboard and CVE-detail components while calling the Cloudflare-hosted read-only API. D1, vendor credentials, and ingestion remain exclusively on Cloudflare.

## Implemented vertical slice

- Microsoft Security Response Center public CSAF advisory/VEX discovery and normalization
- Cisco PSIRT OpenVuln v2 discovery with CSAF detail normalization
- CISA KEV full-snapshot synchronization with soft lifecycle changes
- FIRST EPSS bulk daily synchronization with history and model metadata
- Shared `DISCOVER -> FETCH -> VALIDATE -> NORMALIZE -> DIFF -> UPSERT -> ENRICH -> PUBLISH` contracts and policies
- Explainable P1/P2/P3 operational priority
- Patch Tuesday release events and comparison with the prior event
- Filtered/cursor-paginated dashboard API and complete CVE intelligence API
- Public read-only dashboard plus protected, allowlisted internal ingestion

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
```

Run a source-selective ingestion:

```bash
Invoke-RestMethod -Method Post -Uri http://localhost:3000/api/internal/ingest -Headers @{ Authorization = "Bearer $env:INGEST_SECRET" } -ContentType application/json -Body '{"sources":["microsoft-msrc-csaf","cisco-psirt-csaf","cisa-kev","first-epss"],"idempotencyKey":"local-initial"}'
```

Allowed source IDs are centralized in `lib/ingestion/source-catalog.ts`. Omitting `sources` runs public sources plus configured private sources; credential-dependent sources are not selected until configured. Cisco requires OpenVuln client credentials. Adobe and Fortinet accept only official-hosted configured indexes/CSAF exports. Apple and SAP accept only allowlisted vendor-hosted CSAF URLs, with an optional bearer token. Each source commits independently, preserves last-known-good data on failure, and reports partial success.

## Validation

```bash
pnpm test
pnpm lint
pnpm build
VITE_API_BASE_URL=https://api.example.workers.dev PAGES_BASE_PATH=/repository-name/ pnpm run pages:build
pnpm run test:pages
```

The focused suites cover normalized adapter fixtures, hashing and revision diffs, canonical/vendor separation rules, remediation and exploitation semantics, KEV validation, EPSS metadata/history, and explainable priority boundaries.

## API

- `GET /api/dashboard` — filtered summary, since-refresh changes, priority distribution, chart data, release event comparison, source health, and cursor-paginated rows. Filter state is URL-native.
- `GET /api/cves/:id` — canonical CVE data, vendor assertions, affected products, remediation, exploitation evidence, KEV, EPSS current/history, timeline, and source links.
- `POST /api/internal/ingest` — bearer-protected, idempotent, source-allowlisted ingestion with bounded request size and per-source leases.

Cross-origin access is available only for `GET /api/dashboard` and `GET /api/cves/:id`, and only to exact origins configured through `PUBLIC_DASHBOARD_ORIGINS`. The internal ingestion route never emits browser CORS headers.

## GitHub Pages + Cloudflare

See `docs/github-pages-cloudflare.md` for the one-time D1 setup and required GitHub repository variables/secrets. The workflows are intentionally separate: `.github/workflows/cloudflare.yml` validates and deploys the Worker, while `.github/workflows/pages.yml` publishes the static dashboard after the Worker origin is configured.

## Source semantics and maintenance

- CISA KEV is ingested as a complete mutable snapshot. `dateAdded` is membership date and `dueDate` is the federal remediation deadline; neither implies a patch. Valid removals are soft-ended, while malformed or suspiciously reduced snapshots are rejected.
- FIRST EPSS uses the bulk daily gzip dataset. Current score is tied to the latest published dataset date, so a CVE absent from the newest snapshot does not retain a stale current score. Historical rows remain keyed by CVE and score date.
- Microsoft and Cisco remediation/exploitation fields are normalized only when their structured source data or explicit vendor text supports them. Source-format changes require fixture updates before parser changes are promoted.
- Palo Alto uses its official RSS plus CSAF endpoint. Ivanti uses full official RSS content only. Mozilla uses the official Foundation Security Advisories YAML repository. Oracle uses quarterly official CSAF documents. Atlassian uses its public Vulnerability API and is rate-limited by the vendor to 10 requests/minute.
- Adobe and Fortinet require configured authoritative machine-readable endpoints; Apple exposes only HTML publicly, while SAP Security Notes require entitlement. VMware/Broadcom, Citrix, and Chrome are intentionally deferred because no stable official structured advisory feed was verified. HTML/portal parsers were not introduced.
- RSS discovery is a current-feed mechanism and cannot guarantee a complete 24-month backfill. A verified vendor manifest or entitled feed is required before claiming historical completeness for those sources.
- The public query is constrained to a rolling 24-month window. Older EPSS observations can remain available on CVE detail pages for trend context.

Production access settings and public deployment are intentionally not changed by this repository.
