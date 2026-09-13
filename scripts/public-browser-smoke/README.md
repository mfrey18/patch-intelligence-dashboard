# Public browser smoke

The `Verify public dashboard without Tailscale` workflow uses a fresh GitHub-hosted runner with no tailnet join, no private credentials, and read-only repository permissions. It follows a successful main-branch Pages deployment or a controlled manual dispatch from main after `DATABASE_BACKEND=postgres`.

It exercises the real deployed UI: populated data, all seven analytics responses, pagination, Cisco/Microsoft filters, combined severity, filter persistence, CVE search, real CSV download and JSON export, detail/provenance, and an honest empty state. It also probes the public internal-route exclusion. It stores screenshots, a Playwright trace, exported files, and a timestamped JSON report for 30 days, including failures. These contain public dashboard data only.

The script is bounded to 180 browser API requests and eight minutes; the workflow has a 15-minute timeout. This is functional smoke evidence, not a sustained load test or an uptime guarantee. The recorded Pages workflow SHA identifies the workflow run, not independently verified installed native release metadata; retain protected deployment evidence alongside it.

For local script validation, use an existing loopback Pages preview and matching public API origin:

```sh
npm ci --ignore-scripts --prefix scripts/public-browser-smoke
scripts/public-browser-smoke/node_modules/.bin/playwright install chromium
SMOKE_LOCAL_VALIDATION=true \
  PAGE_URL=http://127.0.0.1:4173/patch-intelligence-dashboard/ \
  PUBLIC_API_BASE_URL=http://127.0.0.1:4173 \
  SMOKE_OUTPUT_DIR=work/public-browser-smoke-local \
  node scripts/public-browser-smoke/run.mjs
```

Local output explicitly says it is not outside-tailnet proof. Never disconnect the production Mac's system Tailscale daemon to manufacture that proof: it also provides Funnel. The production workflow checks the intended fixed Pages/Funnel endpoints and runs independently of this Mac's administrator connection.
