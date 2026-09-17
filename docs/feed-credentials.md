# Feed access and credentials

Verified 2026-09-17. These are server-side ingestion settings. Adding a vendor account does not establish that its public advisory feed has complete structured data.

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

## Sources needing feeds rather than a generic API key

| Vendor | Verified public source / next step | Configuration only after verification |
| --- | --- | --- |
| Broadcom | [Official JSON API instructions](https://knowledge.broadcom.com/external/article/408302/json-api-for-product-security-advisories.html). The POST endpoint now works without credentials. Its index truncates product names and omits fixed versions, so the adapter records advisory/CVE identity only and coverage remains gated. | Optional `BROADCOM_CSAF_URLS` override for complete official CSAF documents |
| Adobe | [Security bulletins](https://www.adobe.com/trust/security.html). No complete official structured endpoint was verified in this pass. | `ADOBE_SECURITY_INDEX_URL`, optional vendor-provided `ADOBE_SECURITY_AUTHORIZATION` |
| Fortinet | [FortiGuard PSIRT](https://www.fortiguard.com/psirt). RSS discovery alone does not establish complete remediation mappings. Confirm an accessible official structured export. | `FORTINET_CSAF_URL_TEMPLATE`, optional vendor-provided `FORTINET_CSAF_AUTHORIZATION` |
| Ivanti | Public advisory discovery remains incomplete; obtain a verified structured source. | `IVANTI_CSAF_URLS` |
| Apple | [Apple security releases](https://support.apple.com/100100) are public. No complete CSAF source was verified. | `APPLE_CSAF_URLS`; `APPLE_CSAF_TOKEN` is an adapter option, not evidence that Apple offers a token service |
| SAP | [SAP Security Notes](https://support.sap.com/en/my-support/knowledge-base/security-notes-news.html). Ask the organization's SAP administrator to establish appropriate support access and an authorized machine-readable export. | `SAP_CSAF_URLS`; `SAP_CSAF_TOKEN` requires a verified feed-specific authentication mechanism |
| Citrix / NetScaler | [Security bulletin notifications](https://www.citrix.com/blogs/2020/06/16/keep-up-to-date-with-the-citrix-trust-center/) provide discovery. Full structured product/fix coverage still needs verification. | `CITRIX_CSAF_URLS` |
| Chrome | [Official release blog](https://chromereleases.googleblog.com/) is public; the current adapter requires verified structured documents. A Google account key does not supply those documents. | `CHROME_CSAF_URLS` |

Configured URLs must be official allowed HTTPS hosts. Existing placeholder environment variables are not proof that a vendor sells or supplies such a feed. Do not put portal passwords or browser cookies in these variables.

## Resuming bounded updates

`scripts/sync-expansion.mjs` accepts `SOURCE_ID`, `INGEST_MODE`, `CHECKPOINT_ID`, `MAX_ATTEMPTS` (1–50) and `BATCH_SIZE` (1–12; default 1). Its `API_ORIGIN` must point to the private API and `INGEST_SECRET` must be supplied through the operator environment, never printed.

Use the same explicit checkpoint ID across sessions to resume historical work. A validation run does not enable automatic production scheduling. Source readiness stays independent of the most recent successful batch.
