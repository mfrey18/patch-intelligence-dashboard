# Cisco scheduled ingestion

The daily Cisco workflow sends one advisory per ingestion batch and allows up to 50 batches or 10 minutes per scheduled invocation, whichever limit is reached first. The request carries `scheduled: true` and a date-pinned identifier such as `daily:cisco-psirt-csaf:2026-09-22`. Existing native OpenVuln request pacing remains at least 2.2 seconds, and a longer upstream `Retry-After` takes precedence.

The API selects the oldest unfinished scheduled Cisco checkpoint before it creates a new daily range. A request that crosses UTC midnight keeps the date and identifier captured when the run started. When an old checkpoint completes, the next request continues until a fresh range reaches the invocation start time, with a three-day overlap for revised advisories. Larger coverage gaps are split into bounded windows. Cleanup retains the latest completed scheduled coverage boundary, including after a long outage. A completed checkpoint is therefore not reused as a permanent daily result.

If the batch or time budget ends while the checkpoint is advancing, the runner writes `daily_status=pending`, `daily_complete=false`, `daily_pending=true`, and `daily_alert=false` to `GITHUB_OUTPUT`, then records the same state in the step summary. The workflow invocation can finish successfully because the work is resumable, but the Cisco completion marker step and the separate `Daily cycle complete` job are skipped; operators and downstream orchestration must use that job, which consumes `needs.cisco.outputs.daily_complete`, rather than the overall workflow conclusion to identify a completed daily cycle. A pending response caused by an active Cisco lease is handled the same way.

The runner raises an alert for a repeated checkpoint position, a non-retryable request failure, an upstream request failure that later recovers, or backlog coverage more than 36 hours old. The monitor separately checks completed coverage freshness, checkpoints incomplete for more than 36 hours, and repeated or prolonged lack of progress on the oldest checkpoint. A cooldown that extends beyond the remaining budget is pending and is not retried early. If a request fails after the final allowed batch, the runner preserves the checkpoint without sleeping. In-flight API work may finish after the client deadline; its saved checkpoint and batch keys allow the next invocation to recover its result.

Validation commands:

```sh
pnpm typecheck
pnpm lint
pnpm test
```
