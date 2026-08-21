# Production Readiness Gate #1

This gate controls whether PR #1 may be marked ready, merged, and published. It does not grant permission to merge or deploy. A PASS requires evidence; a FAIL requires correction before merge; a DEFER must be genuinely nonblocking and include a rationale.

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

- [ ] Review the final PR #1 diff and commits; confirm no unrelated redesign or secret material.
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

Rollback baseline captured 2026-08-21: active Worker version `de525b11-19fc-4360-94c9-a179f01d3b28`; production D1 ID `f908eb4e-eed5-4a09-afc2-ba090b09b42f`; database size 5,541,888 bytes. Remote migration inspection shows `0001_free_plan_six_month.sql` is pending. It was validated successfully against a disposable local database but was not applied to production.

PR #1 is open, draft, mergeable, and unmerged at head `160ed638b74f338752a4ab2bd93caec587d5f6d2` (3 commits, 87 changed files). The Free-plan/six-month hardening in the current working tree is newer than that PR head, so the final PR diff/commit review cannot be checked off until these changes are committed and pushed through the existing authorized workflow.

The gate remains **FAIL** until the pending migration and Worker are deployed through the ordered workflow and the new Microsoft checkpointed path completes a bounded production validation. Deferred vendor adapters without authoritative structured sources remain **DEFER** and do not justify weakening fail-closed behavior.
