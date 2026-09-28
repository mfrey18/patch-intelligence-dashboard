# Feed access and credentials

Verified 2026-09-28. These are server-side ingestion settings. Official HTML is an approved input alongside structured vendor feeds. Adding an account does not establish complete historical coverage or explicit remediation data.

## Credentials to obtain

| Integration | Obtain access | Runtime variable | Current need |
| --- | --- | --- | --- |
| VulnCheck Community KEV | [Join/sign in](https://www.vulncheck.com/community), then profile → **Tokens & SSH Keys** → **Create Token** ([official instructions](https://docs.vulncheck.com/getting-started/api-tokens)) | `VULNCHECK_API_TOKEN` | Required before live KEV validation. Use a dedicated dashboard token and save it when shown. |
| NVD | [Request an API key from NIST](https://nvd.nist.gov/developers/request-an-api-key) | `NVD_API_KEY` | Optional. Public requests already validate; a key increases practical enrichment throughput. |
| Cisco (existing integration) | Existing Cisco API application | `CISCO_CLIENT_ID`, `CISCO_CLIENT_SECRET` | Already operational; preserve the existing values. |

No new credentials are required for Oracle public CSAF, Red Hat public CSAF, CVE List V5, the public Atlassian vulnerability API, or the documented Broadcom advisory index. Atlassian explicitly documents [public access and 10 requests/minute](https://developer.atlassian.com/platform/security-vulnerability-api/). Its current timeout/empty-body behavior is not an authentication failure.

## Exact production storage

The launchd service `com.patch.api` starts `ops/run-api.sh`, which sources:

`/Library/PatchIntelligence/secrets/api.env`

Verified ownership: `_patchapp:staff`, mode `0600`. Preserve that ownership and mode. An administrator can edit the existing file with:

```sh
sudoedit /Library/PatchIntelligence/secrets/api.env
sudo launchctl kickstart -k system/com.patch.api
```

Add only the obtained values for `NVD_API_KEY` and/or `VULNCHECK_API_TOKEN`; preserve database URLs, ingestion authorization and existing vendor settings. This is a shell-sourced file, so quote values as shell literals. Do not paste tokens into chat, put them in command arguments/history, or put them in `VITE_*` settings. The static Pages build must never receive these credentials.

`.env.example` documents names only. The production service does not automatically load a repository `.env` or legacy `.dev.vars`. Keep the actual credentials in the native secret file. GitHub Actions only needs its existing `NATIVE_INGEST_SECRET` to invoke the private service; upstream vendor tokens belong on the service, not in the Pages environment.

The existing, operator-readable `/Library/PatchIntelligence/secrets/github-setup.json` contains deployment/bootstrap credentials, including the private ingestion token. It was used in memory for authorized validation; no values were logged. Do not use that bootstrap export as the storage location for new vendor tokens.

After restart, validate one private `vulncheck-kev` delta batch and inspect its run result and attribution. For NVD, validate a bounded `nvd-cve` batch. Do not promote either source merely because a credential is present; queue completion and distinct-day validation gates still apply.

## Sources with optional structured overrides or access gates

| Vendor | Verified public source / next step | Configuration only after verification |
| --- | --- | --- |
| Broadcom | [Official JSON API instructions](https://knowledge.broadcom.com/external/article/408302/json-api-for-product-security-advisories.html). The POST endpoint works without credentials. The adapter follows each official detail link and records only explicit product/fix relationships; the index alone does not provide them. | Optional `BROADCOM_CSAF_URLS` override for official structured documents |
| Adobe | [Security bulletins](https://www.adobe.com/trust/security.html). No complete official structured endpoint was verified in this pass. | `ADOBE_SECURITY_INDEX_URL`, optional vendor-provided `ADOBE_SECURITY_AUTHORIZATION` |
| Fortinet | [FortiGuard PSIRT](https://www.fortiguard.com/psirt). The default adapter traverses the public PSIRT HTML index and detail pages; a configured CSAF template remains an optional override. | `FORTINET_CSAF_URL_TEMPLATE`, optional vendor-provided `FORTINET_CSAF_AUTHORIZATION` |
| Ivanti | The default adapter uses the public security-advisory RSS for discovery and follows each linked official support advisory. A structured override is optional; complete RSS history and detail mappings still require validation. | `IVANTI_CSAF_URLS` |
| Apple | [Apple security releases](https://support.apple.com/100100) are public. No complete CSAF source was verified. | `APPLE_CSAF_URLS`; `APPLE_CSAF_TOKEN` is an adapter option, not evidence that Apple offers a token service |
| SAP | [SAP Security Notes](https://support.sap.com/en/my-support/knowledge-base/security-notes-news.html). The public monthly index and archive expose note links, but note details require existing SAP for Me entitlement. | `SAP_SECURITY_INDEX_URL`, `SAP_SECURITY_DETAIL_URLS`, or optional `SAP_CSAF_URLS` / `SAP_CSAF_TOKEN` |
| Citrix / NetScaler | [Official sitemap](https://support.citrix.com/sitemap.xml) and bulletin pages provide public discovery and HTML detail parsing. The sitemap's complete historical bulletin coverage still requires validation. | `CITRIX_SECURITY_SITEMAP_URL`, `CITRIX_SECURITY_INDEX_URL`, `CITRIX_SECURITY_DETAIL_URLS`, or optional `CITRIX_CSAF_URLS` |
| Chrome | [Official release blog](https://chromereleases.googleblog.com/) is public and the adapter follows release posts; structured documents remain an optional override. | `CHROME_CSAF_URLS` |

Configured URLs must be official allowed HTTPS hosts. Existing placeholder environment variables are not proof that a vendor sells or supplies such a feed. Do not put portal passwords or browser cookies in these variables.

## Resuming bounded updates

`scripts/sync-expansion.mjs` accepts `SOURCE_ID`, `INGEST_MODE`, `CHECKPOINT_ID`, `MAX_ATTEMPTS` (1–50), `SOURCE_MAX_DURATION_MS` (default 600000), and optional `SINCE`/`UNTIL`; vendor batches contain one advisory. Its `API_ORIGIN` must point to the private API and `INGEST_SECRET` must be supplied through the operator environment, never printed.

Use the same explicit checkpoint ID across sessions to resume historical work. A validation run does not enable automatic production scheduling. Source readiness stays independent of the most recent successful batch.

## Official HTML paths

Public HTML adapters retain the original source IDs and preserve configured CSAF overrides. Broadcom follows its official JSON index to HTML details; Fortinet follows the PSIRT HTML index; Ivanti follows RSS links to individual support advisories; Citrix traverses the official sitemap; SAP traverses public monthly/archive pages and fetches entitled notes. Citrix supports `CITRIX_SECURITY_INDEX_URL`, `CITRIX_SECURITY_SITEMAP_URL`, and `CITRIX_SECURITY_DETAIL_URLS`; SAP supports `SAP_SECURITY_INDEX_URL` and `SAP_SECURITY_DETAIL_URLS`. Explicit detail lists are useful for validation but cannot prove a six-month backfill. No portal password, browser cookie, paid subscription, or invented token service is required or introduced.

Adobe, Apple, Chrome, Fortinet, Broadcom and Ivanti use public official pages where available. Public indexes and details still undergo completeness and provenance validation before promotion. SAP detailed notes remain dependent on existing authorized access. VulnCheck still requires the free Community token; NVD works without a key at its existing slower pace.
