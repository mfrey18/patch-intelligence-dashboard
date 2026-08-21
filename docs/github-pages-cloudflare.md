# GitHub Pages + Cloudflare deployment

The GitHub Pages build is a static React client. It calls the public read-only API hosted by the Cloudflare Worker. D1, source credentials, and the authenticated ingestion endpoint remain on Cloudflare.

## One-time Cloudflare setup

1. Authenticate with `pnpm exec wrangler login`.
2. Create the database with `pnpm exec wrangler d1 create patch-intelligence-prod`.
3. Apply the schema once with `pnpm exec wrangler d1 execute patch-intelligence-prod --remote --file=drizzle/0000_patch_intelligence_core.sql`.
4. Create a scoped Cloudflare API token that can deploy Workers in this account.

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

In **Settings → Pages**, set the publishing source to **GitHub Actions**.

The first Worker deployment must complete before the Pages deployment can load data. If the final Worker URL is not known initially, deploy the Worker, set `PUBLIC_API_BASE_URL`, and rerun the Pages workflow.

## Optional vendor credentials

Set Cisco and other private vendor credentials directly as Cloudflare Worker secrets, or extend the Cloudflare workflow's explicit `secrets` list. Never expose them as `VITE_*` variables because those values are compiled into the public Pages bundle.

## Local split-deployment check

Run the Worker with `pnpm dev`. In another terminal, run `pnpm run pages:dev`. The static client defaults to `http://localhost:3000` in development. Add the static dev origin to `PUBLIC_DASHBOARD_ORIGINS` in `.dev.vars`.
