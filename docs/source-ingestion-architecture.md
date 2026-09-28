# Source ingestion completion architecture

This is the implemented shape as of 2026-09-28. `server/api.ts` is the
execution boundary: it validates one source request, acquires the source lease,
runs the bounded operation, and releases the lease. `orchestration.ts` owns
scheduled checkpoint selection and advancement. `source-execution.ts` owns the
deadline, abort signal, and lease-fenced writes. `source-completion.ts` and
`enrichment-cycles.ts` provide immutable completion evidence and enrichment
membership state. Vendor HTML parsers remain private to their adapters.

# Candidate A: extend existing durability, certify completion

## Problem

Source runs prove batches, vendor checkpoints prove ranges, and enrichment queue timestamps currently prove neither a fixed membership nor fresh upstream coverage. Extend these existing owners rather than migrate all work into a second scheduler. Preserve source/advisory/checkpoint identity, frozen pages, manual replay, current production sources, six-month semantics and official provenance. User approval permits vendor-specific official HTML and free/existing access; missing access/history remains explicit.

## Usage (caller's view)

The internal API parses existing JSON into a source command, acquires the source lease, and runs the operation through `runSourceOperation(...)` with a lease-fenced database wrapper. Scheduled commands need only source and invocation start; orchestration chooses oldest work, checkpoint identity, enrichment membership and the one-item vendor policy. Legacy manual clients retain their mode/range/checkpoint fields and response fields. New `progress` adds pending reason, durable position, coverage target and retry time.

`scripts/daily-ingestion.mjs` calls the internal API for one source at a time and reports `complete | pending | failed`, capped at 50 calls/10 minutes. A final projection job runs after all source jobs regardless of their outcomes. The readiness CLI calls `setSourceReadiness(db, sourceId, 'production')`; its unchanged caller delegates to evidence-based eligibility and cannot promote on batch success.

## Shape

**Chosen alternative A1 — existing work owners plus immutable completion evidence.** Keep vendor `ingestion_checkpoints` authoritative for work and cursor. Add `scheduled` metadata and a selected plan policy; keep legacy IDs. Extend enrichment's existing update state with immutable cycle target, captured membership and per-member requirement/satisfaction. Add `source_completion_evidence` referencing completed vendor checkpoints or enrichment cycles (unique owner/type); this is a certificate, never a second mutable work cursor. One scheduler-facing function owns lease, plan, execution and completion. The runner only owns a bounded invocation and transport retries. This is deeper than exposing prepare/start/advance/finish methods to API clients (boundary-discipline, single-source-of-truth).

Module map: `orchestration.ts` handles source planning and vendor completion; `source-execution.ts` handles the one-source leased operation; `enrichments/cve.ts` and `enrichment-cycles.ts` own membership/cursor evidence; `source-completion.ts` records immutable certificates and eligibility SQL; `adapters/html.ts` supplies bounded DOM primitives and private vendor parsers; `daily-ingestion.mjs` provides the bounded runner. No generic connector framework.

Data access is explicit: oldest unfinished work index `(source_id, scheduled, created_at, id)`; certificates `(source_id, kind, completed_at)` with UTC completion date; cycle member PK `(cycle_id,cve_id)` plus unmet index; existing source/run/advisory uniqueness remains. Vendor complete certificate is inserted in the same transaction as final checkpoint advancement; enrichment certificate is inserted with cycle closure after no unmet captured members or update pages remain. Completion target is fixed at cycle creation. A retry returns the existing certificate. New CVEs join the next cycle, not an unbounded moving target; eligibility additionally verifies initial membership completion and no older unresolved work. Failed item requirements remain unmet (encode-lessons-in-structure).

Official HTML parsing uses Cheerio DOM primitives without executing page JavaScript. Adobe APSB, Fortinet FG-IR, Citrix CTX, Apple article IDs, Chrome stable post IDs and SAP note IDs must come from document assertions or verified index identity. Vendor row/group mapping remains private. Oracle/Red Hat/Atlassian keep their adapters; Broadcom index rows gain official detail parsing only where identity and product/fix relationships are established; Ivanti RSS is discovery, with vendor detail mapping. SAP uses existing entitled access only if available. Accessible shell pages, 403s or missing six-month archives produce blocked validation results, never empty success claims.

## Alternative sketches

**A1:** API lease and deadline boundary → existing vendor checkpoint or enrichment cycle state → idempotent records → immutable certificate. Monitor queries certificates plus each owner's progress. Complexity hidden: resumptions, fresh planning, retries, idempotency, certification. Exposed: source intent and durable outcome. Migration adds metadata and enrichment-specific state, preserving current readers.

**A2 — new durable source-cycle/work coordinator:** `coordinator.advance(sourceId, budget)` creates `source_cycles` and `source_work_items` for every source; vendor checkpoints become imported compatibility views/pointers; enrichments become work items. Coordinator claims work with leases, drives adapter actions, and closes cycles. This hides more workflow variety behind one interface, but duplicates vendor checkpoint/discovery cursor state unless those owners are replaced. Full replacement requires migrating active continuation and replay generations, redefining all manual request semantics, and maintaining compatibility views. A2 is structurally stronger for new multi-stage sources but unnecessarily risky here. The sketch file includes its domain shape to make the comparison concrete.

## Synthesis decision

Candidate A selects A1 locally. Arena's cross-candidate synthesis remains root-owned; no claim is made about other candidates. Do not graft A2's generic work-item table into A1: that recreates dual mutable cursors. The certificate table may unify **reads**, not own execution.

## Tradeoffs accepted

- We accept vendor and enrichment-specific work tables in exchange for retaining their existing durable semantics; a single read model hides their difference from monitor/promotion.
- We accept new explicit scheduled metadata and conservative legacy evidence treatment in exchange for not inferring coverage from historical batch records.
- We accept a captured cycle membership plus subsequent admission cycle in exchange for deterministic completion despite concurrent new CVEs; eligibility reports later backlog separately.
- We accept source-specific DOM parsers in exchange for auditable relationships and fail-closed drift handling.

## Failure, deadline and migration policy

Backfill migration adds nullable scheduled metadata, then marks legacy Cisco daily IDs and verified expansion/daily delta namespaces without renaming rows. Do not mark manual delta IDs scheduled merely because mode is delta. Older completed checkpoints remain usable operational history, but do not generate new promotion certificates without validating range/membership evidence. Any new columns preserve existing query shapes and enum values. Keep API results/checkpoint fields; map new domain pending into HTTP 202 and real failures into 207.

Each batch gets a deadline shorter than remaining source invocation time and shorter than its lease. Signal reaches discovery/fetch/retry sleeps; lease renewal/fencing guards long writes. Before any commit/advance check holder and unexpired lease in the same transaction. Cancellation before completion leaves cursor unchanged; committed records may be replayed by hash. If cancellation occurs after final advancement/certificate commit, next request returns that completion. Do not mark failed only because the client disconnected. RetryAfter persisted in sources prevents another job's early request; pending budget/cooldown is not failure, but an observed parser/upstream failure remains recorded and alerted even when later retry is pending.

Old incomplete windows that have aged outside six months are explicitly retired as expired, without a completion certificate, and followed by a new six-month reconciliation; use nullable retired_at/reason rather than changing old status enums. Frozen discovery of retained ranges remains intact. Oracle/Atlassian scheduled planning keeps six-month reconciliation instead of blindly switching to three-day overlap. Completed historical work is followed until a certificate covers invocation start; midnight never changes an active generation.

## Rollout and verification

First add additive schema and back-compatible serializers; use current production IDs as regression fixtures. Then generalize Cisco behavior under one-source execution with one advisory batch, monitor, and runner. Then enrichments and promotion certificates; finally vendor DOM adapters behind validating readiness. Hourly matrix selects enabled production sources (and explicit validation jobs separately), max-parallel 3, per-source concurrency, fail-fast false. Avoid duplicate daily/hourly jobs for the same source; retain manual Patch Tuesday independently under source lease. Projection fan-in always runs and preserves parity/last-known-good; source completion is independent of projection success but promotion additionally requires a passing current projection/representative validation.

Tests: crash before/after record commit and final cursor commit; same key on both sides of midnight; oldest backlog before fresh range; same-range new replay generation; one-item vendor bound; lease loss/deadline fencing; deferred all-members enrichment; update pagination lag; new CVE arriving mid-cycle; idempotent replay preserving bound state; initial queue completion; two UTC dates of real certificates; empty cycles cannot establish usable coverage; expired backlog never certifies; unrelated failing source does not starve others. Parser fixtures prove positive/negative assertions and correct table/group relationships; live probes validate official access/history, never automatically promote. No paid service or new credentials introduced.

## Open questions and risks

- Which SAP entitlement or existing official export is actually present? Until verified, keep SAP access-blocked with a precise reason.
- Which Adobe/Fortinet/Citrix index path supplies complete six-month history under existing access? Detail accessibility alone does not answer this.
- Can an existing operational certificate be safely reconstructed for each current production source? If not, leave current readiness unchanged and start collecting new evidence; never auto-demote current six solely for schema rollout.

## Red-flag screen and next step

No caller coordinates internal lifecycle methods; HTML semantics remain vendor-owned; no transport types enter domain functions; certificates do not duplicate mutable cursors. The single execution boundary replaces existing orchestration branches rather than forwarding them. Implement additive completion/membership schema and atomic final checkpoint certification first.


# Architecture arena review

Date: 2026-09-22

## Decision

Use Candidate A1, “existing work owners plus immutable completion evidence,” as
the base. It keeps the vendor checkpoint, frozen discovery generation, source
lease, advisory identity, and enrichment owner responsible for the state each
already understands. `source_completion_evidence` is an append-only certificate
for reads and promotion; it does not become another cursor. This is the safest
shape for the current production sources, legacy IDs, and the Cisco
resume-before-fresh-window requirement.

Candidate B has useful vocabulary for budgets, pending reasons, failure codes,
and operational health, but its `scheduled_cycles` ledger still introduces a
second mutable owner beside `ingestion_checkpoints`. Its compatibility columns
and projection language do not remove the dual-write and cutover problem. The
alternative durable work coordinator in B is a future option only if a source
demonstrates independent item retry volume that the existing owners cannot
handle.

## Rubric scores

Scores are 0–5; higher is better.

| Criterion | A | B | Assessment |
| --- | ---: | ---: | --- |
| Durable correctness | 5 | 3 | A preserves the existing cursor and frozen discovery as the authority and atomically adds a completion certificate. B makes cycle and checkpoint progress agree through a new ledger and compatibility bridge. |
| Domain/provenance correctness | 5 | 4 | Both correctly require explicit IDs, guarded official HTML, known unknowns, and fail-closed remediation relationships. B’s broad policy table risks making unvalidated source coverage look uniformly ready. |
| Interface depth | 5 | 3 | A has one scheduled execution boundary with policy hidden behind it. B’s coordinator, cycle repository, cycle evidence, compatibility projection, and adapter registry spread the same decisions across several surfaces. |
| Compatibility/operability | 4 | 3 | A is additive around current IDs, manual replay, leases, and source isolation. B can preserve callers, but migration must synchronize two state models and establish which one monitoring trusts. |
| Verifiability and implementation cost | 4 | 2 | A’s certificates, owner-finalization transactions, and focused adapter fixtures are bounded increments. B requires a central schema, policy catalog, projections, and bidirectional migration before its claims are testable. |
| **Total** | **23/25** | **15/25** | A has the stronger implementation path and fewer irreversible state decisions. |

## Red-flag screen

Candidate A passes the key architect checks when implemented as A1:

- It is a deep execution boundary: the caller supplies source intent and a
  budget, while planning, lease fencing, resume selection, pacing, idempotency,
  and certification stay inside the owner.
- It avoids temporal decomposition by keeping cursor decisions with the
  checkpoint owner and completion proof with the owner-finalization transaction.
- It keeps vendor selectors and wire formats private to each adapter; the HTML
  primitive layer returns bounded domain inputs rather than Cheerio or vendor
  rows.
- It avoids a pass-through coordinator and does not expose prepare/advance/
  finish lifecycle methods to callers.

Candidate B’s main red flag is duplicate mutable state. A cycle row that owns
window status, retry time, progress, and completion while a checkpoint owns the
discovery continuation creates two answers to “what resumes next?” The proposed
compatibility projection is an information-leakage and temporal-decomposition
risk unless every write is permanently dual-written. B’s public shape is also
at risk of becoming a shallow facade over the existing orchestration methods.

## Grafts from B

Take these pieces only where they strengthen A without creating a second work
authority:

1. Adopt typed pending reasons and failure codes for the scheduled result and
   monitor (`budget`, persisted `retry-after`, lease contention, queue work,
   request/parse/validation/persistence failure). Derive them from the owning
   checkpoint/source/enrichment rows.
2. Keep B’s explicit `TimeBudget`, abort propagation, source pacing, and
   `Retry-After` precedence as execution policy. A’s one-advisory Cisco bound
   and ten-minute/50-batch cap remain source policy, not a generic work queue.
3. Reuse B’s operational health fields—latest completed coverage boundary,
   oldest incomplete age, last progress, retry time, and failure—through a read
   model over existing owners plus immutable certificates.
4. Use B’s acceptance vocabulary for cycle evidence, but write evidence only
   when the existing checkpoint or enrichment owner closes its fixed target.
   Enrichment may retain a cycle-member table because queue membership is a
   genuine domain owner; it must not become a vendor cursor.
5. Keep B’s explicit HTML boundary and source-specific parser rule. Enable a
   source only after its real official access, stable IDs, and affected/fixed
   assertions have fixtures and readiness evidence; do not seed an unverified
   14-source production policy table.

## Rejections and constraints

- Reject `scheduled_cycles` as the authoritative mutable ledger and reject a
  generic `source_work_items` replacement during this rollout.
- Reject compatibility “views/pointers” that allow both a cycle and a
  checkpoint to claim ownership of continuation, retry, or completion.
- Reject a new cycle identity as the source of batch idempotency. Batch keys,
  discovery generation, and legacy scheduled IDs must resolve to the saved
  checkpoint identity; explicit replay remains isolated.
- Reject promotion from a source-run count, an empty page, a title/URL-derived
  ID, or a successful invocation without fixed-range evidence. Official HTML
  access does not prove six-month coverage or remediation semantics.
- Reject generic parser and adapter framework work until one vendor’s positive
  and negative fixtures prove the abstraction hides real policy rather than
  forwarding vendor wire data.

## Implementation gate

Implement A1 in this order: additive scheduled metadata and immutable evidence;
atomic owner-finalization certificates; read-only completion/health queries;
the bounded scheduled runner and Cisco resume tests; then one official HTML
adapter with drift and missing-assertion fixtures. Add further adapters only
after each source meets the same provenance and access gates. The required
cross-midnight, cooldown, lease contention, completion-then-fresh-window, and
manual-isolation cases should be acceptance tests of the owner transactions,
not tests of a second scheduler ledger.
