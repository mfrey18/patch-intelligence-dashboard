# GitHub Pages + Cloudflare deployment

The GitHub Pages build is a static React client. It calls the public read-only API hosted by the Cloudflare Worker. D1, source credentials, and the authenticated ingestion endpoint remain on Cloudflare.

## One-time Cloudflare setup

1. Authenticate with `pnpm exec wrangler login`.
2. Create the database with `pnpm exec wrangler d1 create patch-intelligence-prod`.
3. Apply the schema once with `pnpm exec wrangler d1 execute patch-intelligence-prod --remote --file=drizzle/0000_patch_intelligence_core.sql`.
4. Apply subsequent backward-compatible migrations with `pnpm exec wrangler d1 migrations apply patch-intelligence-prod --remote`.
5. Create a scoped Cloudflare API token that can deploy Workers and apply D1 migrations only to the intended account/resources.

## GitHub repository configuration

In **Settings → Secrets and variables → Actions**, add these secrets:

- `CLOUDFLARE_API_TOKEN`
- `CLOUDFLARE_ACCOUNT_ID`
- `INGEST_SECRET`

Add these repository variables:

- `CLOUDFLARE_D1_DATABASE_ID` — ID returned by `wrangler d1 create`
- `CLOUDFLARE_D1_DATABASE_NAME` — normally `patch-intelligence-prod`
- `PUBLIC_API_BASE_URL` — deployed Worker origin, without a trailing slash
- `PUBLIC_DASHBOARD_ORIGINS` — comma-separated exact browser origins, normally `https://OWNER.github.io` and any custom domain
- `ENABLE_SCHEDULED_INGESTION` — leave unset/false until Gate #1 and the production vertical slice pass; set to `true` to enable scheduled source-isolated jobs

In **Settings → Pages**, set the publishing source to **GitHub Actions**.

Create or review the `production-worker` GitHub Actions environment. Scope Worker deployment credentials to that environment when possible. GitHub Pages uses the built-in `github-pages` environment. The Worker and Pages workflows share `production-deployment` concurrency and do not cancel an active production release.

The Worker workflow owns production ordering: validation, resource checks, migration-state inspection, migration application, Worker deployment, and Worker smoke tests. A successful run on `main` triggers the Pages build/deployment, followed by the browser-to-Worker-to-D1 acceptance checks in the production runbook. If the final Worker URL is not known initially, deploy the Worker, set `PUBLIC_API_BASE_URL`, and manually rerun Pages only after the Worker smoke test succeeds.

Deployment does not run vendor ingestion or create ingestion checkpoints. Source deltas, Patch Tuesday reconciliation, replay, and backfill run through `.github/workflows/ingestion.yml`, where their leases and resumable checkpoints remain operationally isolated from schema and application releases.

Keep Cloudflare's direct Git build/deploy integration disconnected for the production Worker. GitHub Actions is the single deployment owner; enabling Cloudflare push-triggered deploys would bypass migration ordering and the shared `production-deployment` concurrency gate.

## Optional vendor credentials

Set Cisco and other private vendor credentials directly as Cloudflare Worker secrets, or extend the Cloudflare workflow's explicit `secrets` list. Never expose them as `VITE_*` variables because those values are compiled into the public Pages bundle.

Rotate the Cloudflare deployment token before **August 21, 2027**. Record the replacement owner and rotation date without committing the token itself.

## Local split-deployment check

Run the Worker with `pnpm dev`. In another terminal, run `pnpm run pages:dev`. The static client defaults to `http://localhost:3000` in development. Add the static dev origin to `PUBLIC_DASHBOARD_ORIGINS` in `.dev.vars`.

## Production ingestion cadence

- Daily, invoke CISA KEV, FIRST EPSS, Microsoft delta, Cisco delta, and each production-ready vendor delta as separate authenticated requests.
- Around Patch Tuesday, add a targeted Microsoft `patch_tuesday` reconciliation; do not replace the daily delta.
- Schedule bounded `replay` intervals for consistency and revision/idempotency checks.
- Drive `backfill` by repeatedly invoking the same checkpoint until it reports `complete`. Never attempt the six-month range in one Worker request.
- Run authenticated retention after a successful daily cycle and alert on stale sources, repeated failures, abnormal counts, expired/stuck leases, or repeated `boundHit` results.
- Run `.github/workflows/operations-monitor.yml` daily. It captures runtime health and D1 size before publishing or resolving the production alert, then enforces projection parity, the one-second core-latency objective, and the 400 MB D1 warning threshold.

`.github/workflows/ingestion.yml` encodes this cadence but keeps schedules disabled until `ENABLE_SCHEDULED_INGESTION=true`. Its matrix uses `fail-fast: false`, so one failed source does not cancel healthy source jobs. Replay and backfill remain manual bounded invocations.

Example bounded Microsoft backfill request:

```json
{
  "sources": ["microsoft-msrc-csaf"],
  "mode": "backfill",
  "checkpointId": "microsoft-six-month-2026-08-21",
  "maxItems": 12
}
```

Use the same checkpoint identifier for every continuation invocation. D1 preserves the window and continuation token. A failed batch stays on its current window; a successful batch advances only after its deterministic discovery set has been exhausted.
