# Native rollback for the initial cutover

The operator confirmed D1 limit exhaustion as the known cause of the legacy API outage on September 12, 2026. Cloudflare rollback is unavailable until its limits reset or capacity increases. The operator explicitly accepted that limitation and authorized protected native cutover once native readiness and recovery checks pass. Do not treat the retained Cloudflare configuration as a working rollback target or switch visitors back to an API returning 503.

## Prepare and verify the recovery assets

Run the reviewed `ops/prepare-native-rollback.sh` as administrator before deploying the cutover release. It takes a current custom-format PostgreSQL backup, checks its SHA-256, restores into a uniquely named disposable database with the installed restore helper, verifies the CVE and migration tables, and removes the disposable database. A second bounded restore of that exact dump asserts nonempty CVEs, migrations and dashboard facts, published projection status, matching state count, and all 12 actual projection aggregates matching the saved canonical and projected parity metrics. It also requires the candidate and retained PostgreSQL migration files to match exactly. Safe counts, hashes and verification outcomes are retained in the manifest; the second temporary database is removed in cleanup. It copies the exact restored dump into `/Library/PatchIntelligence/rollback/<UTC timestamp>` outside automatic 14-day backup cleanup and writes a manifest containing the checksum and current application release. The release must be root-owned, read-only and complete. Retain both the referenced release directory and backup directory through the seven-day observation and subsequent rollback window.

The initial retained release is `134425effcefd2f8fc30af7ac7cfb4e8fa980444`. Record its live public dashboard response before replacement. Compare its PostgreSQL migration directory with the candidate; application-only rollback is accepted only when the restored release can use the candidate schema. A successful dump restore verifies recoverability of database contents; it does not prove that the complete live recovery procedure has been executed.

```sh
sudo bash "/Users/helper_heavy/Documents/New project/patch-intelligence-dashboard/ops/prepare-native-rollback.sh"
```

This command changes no live application pointer or production database contents. It creates a backup and a temporary restore database, using the installed root-owned helpers. Preserve the sanitized manifest with cutover evidence. Never print service credentials.

## Application-only rollback

Pause GitHub ingestion and deployment dispatches and confirm no ingestion is active. Keep `DATABASE_BACKEND=postgres` and the Funnel origin. Select the exact retained SHA from the verified manifest, validate it resolves under `/Library/PatchIntelligence/releases`, then atomically replace `current` with a symlink to that release and restart `system/com.patch.api`. The installed deployment helper already performs this application-only switch automatically if new-release readiness fails; its schema remains forward migrated.

For a later manual rollback, an administrator performs the switch from the saved manifest, retaining the failed release for inspection. Update `/Library/PatchIntelligence/deployed-sha` only after readiness passes. Verify public core data, internal-route 404, authenticated private health, projection parity, and schema compatibility before resuming ingestion. If the frontend needs rollback, deploy a retained compatible native Pages build using the Funnel API, never the unavailable Worker origin. Preserve the native Pages artifact/run identity after its successful protected deployment.

## Database recovery

Pause ingestion and API writes. Verify the retained dump's checksum, and restore it into a new uniquely named recovery database, never over the existing production database. Reapply the reviewed `patch_owner`, `patch_writer`, and `patch_reader` ownership and grants; the dump intentionally omits owners and ACLs. Test the retained application's API against that recovered database with bounded isolated listeners and no production scheduling. Verify counts, projection parity, response contracts and least-privilege roles before changing any live database connection settings.

Only after those checks pass, atomically update the root-managed connection configuration to the recovered database and restart the API. Retain the failed database untouched for investigation. Re-run complete cutover readiness and public browser smoke tests before resuming schedules. Records written after the recovery dump are absent unless recovered separately; record the actual recovery-point timestamp. Do not run reverse migrations blindly or overwrite the existing database. Local backups do not protect against loss of this Mac.
