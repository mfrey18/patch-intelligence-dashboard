# Production Readiness Gate #1

This gate controls whether the current release candidate may be marked ready, merged, and published. It does not grant permission to merge or deploy. A PASS requires evidence; a FAIL requires correction before merge; a DEFER must be genuinely nonblocking and include a rationale.

## Required deployment order

1. Validate TypeScript, ESLint, focused unit/integration tests, the Worker build, rendered Worker artifact, the static Pages build, and the static artifact.
2. Confirm the production Worker name, D1 database name/ID, public API origin, and exact CORS origins.
3. List production D1 migrations and record the current Worker version and pre-change D1 baseline for rollback.
4. Apply pending backward-compatible D1 migrations. Use expand → deploy → populate → later cleanup; do not deploy code that expects an unapplied schema.
5. Deploy the Worker.
6. Smoke-test the public API and verify unauthenticated ingestion is rejected.
7. Deploy GitHub Pages only after the Worker workflow succeeds.
8. Smoke-test browser → Worker → D1 under the repository base path.

The workflows serialize production releases with the shared `production-deployment` concurrency group. The Worker job uses the `production-worker` environment and Pages uses `github-pages`.

## Pre-publish evidence checklist

- [ ] Review the final release-candidate diff and commits; confirm no unrelated redesign or secret material.
- [x] `pnpm exec tsc --noEmit`
- [x] `pnpm lint`
- [x] `pnpm run test:focused`
- [x] `pnpm run build`
- [x] `pnpm run test:rendered`
- [x] `pnpm run pages:build` with the production API origin and repository base path.
- [x] `pnpm run test:pages` with the same settings.
- [x] `pnpm exec wrangler deploy --dry-run --config dist/server/wrangler.json`
- [x] Confirm production D1 migration state and capture the D1 baseline.
- [x] Record the active Worker version before deployment for rollback.
- [x] Verify Pages Actions source and workflow configuration.
- [ ] Verify `PUBLIC_API_BASE_URL` and exact `PUBLIC_DASHBOARD_ORIGINS`.
- [x] Verify no localhost, development origin, credentials, or unresolved build variables appear in `dist-pages`.
- [x] Verify all product copy, queries, defaults, and tests consistently use six months.

Do not weaken a test or parser policy to obtain a PASS.

## Production end-to-end acceptance

- [ ] GitHub Pages loads under `/patch-intelligence-dashboard/` (or its configured repository base path).
- [ ] Browser requests use the production Cloudflare API and CORS accepts only the intended Pages/custom origins.
- [ ] Summary metrics and vulnerability rows load from D1; URL filter state survives refresh/share.
- [ ] Cisco, Microsoft, KEV, EPSS, remediation, priority, zero-day, exploitation, and patch-state filters reconcile with D1 queries.
- [ ] A representative CVE page shows canonical data separately from vendor assertions, products, remediation, exploitation/KEV, current and historical EPSS, timeline, and authoritative provenance.
- [ ] Priority includes its input components and human-readable reasons.
- [ ] Invalid CVE requests return 404 safely; unauthenticated ingestion/health/retention requests return 401 or the documented unconfigured response.
- [ ] Six-month boundary behavior is correct, including records exactly on the cutoff.
- [ ] Per-source status, counts, freshness, last success/failure, lease state, checkpoint state, and last-known-good preservation are observable.

## Recurring operations after the vertical slice is stable

Daily jobs are separate authenticated invocations for CISA KEV, FIRST EPSS, Microsoft delta, Cisco delta, and each production-ready vendor delta. Patch Tuesday adds a Microsoft reconciliation. Periodic bounded replay validates historical consistency and idempotency. Backfill repeatedly advances persisted one-day windows until the rolling six-month range is complete.

Alert on stale sources, repeated failures, abnormal discovered/changed counts, expired or stuck leases, and repeated configured-bound hits. Rotate the scoped Cloudflare deployment token before August 21, 2027.

## Current gate record

Production update captured 2026-08-21: PR #4 merged to `main` at `b625921aa22a8f33c8f94f11da3ee5d1402c3948`; the GitHub Actions deployment applied `0001_free_plan_six_month.sql` to D1 `f908eb4e-eed5-4a09-afc2-ba090b09b42f` and deployed active Worker preview/version `119cf8f8`. Public dashboard/API smoke tests, exact CORS, unauthenticated-ingestion rejection, and a bounded 12-item Microsoft delta all passed. The workflow then failed before Pages deployment because D1 returned `SQLITE_AUTH` for the health endpoint's `PRAGMA page_count` probe.

Draft PR #5 at commit `87d1b61605cd5ee78373d6402cc3ba368934263e` removes the unsupported Worker PRAGMAs, obtains authoritative `database_size` through `wrangler d1 info --json`, and archives the combined baseline. Cloudflare's redundant direct Git integration for the stale `patch-intelligence-dashboard` Worker was disconnected; GitHub Actions remains the only production deployment owner for `patch-intelligence-api`.

The gate remains **FAIL** until PR #5 is reviewed, explicitly authorized for merge, and its ordered workflow records a passing D1 baseline and triggers a successful GitHub Pages deployment plus browser-to-Worker-to-D1 acceptance. Deferred adapters without authoritative structured sources remain **DEFER** and do not justify weakening fail-closed behavior.
