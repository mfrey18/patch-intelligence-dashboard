# Feed validation — September 17, 2026

Live updates used the existing private native API. Credentials were read in memory from the existing operator bootstrap export and were not printed or copied into the repository.

| Source | Observed result | Remaining gate |
| --- | --- | --- |
| Oracle | Six-month backfill complete: six advisory documents inserted. First delta cycle complete: all six unchanged. | Second complete delta on a distinct day and promotion review |
| Red Hat | Nine historical and 30 recent advisory documents inserted without failures. Historical and recent checkpoints remain resumable. | Large backlog: recent discovery alone returned 4,582 revised advisory references; complete replay/cycles still required |
| CVE Program | 1,100 tracked CVEs enriched successfully | Initial queue and distinct-day cycles incomplete |
| NVD | 16 tracked CVEs enriched successfully without an API key | Initial queue incomplete; optional key improves throughput |
| Broadcom | Documented POST index now accessible; all seven pages parsed (341 index entries, four references in the requested six-month window). Two normalized samples contain two and five CVEs. | Product names in the index are truncated and fixed-version details absent; complete coverage remains gated |
| Atlassian | CVE endpoint returned HTTP 200 with an empty body; product endpoint timed out | Upstream usable responses required; API is public, not missing credentials |
| VulnCheck | Existing readiness is pending credentials; no token was supplied in this task | Community token and first live snapshot validation |
| Remaining configured vendors | No complete structured feed verified | See feed-credentials.md; account keys alone do not close these gaps |

EPSS membership was refreshed after the admitted advisories: 11,399 observations were inserted for the published dataset. The refreshed dashboard projection contained 11,435 CVEs; canonical/projection parity passed.

Checkpoints to resume: `validation:oracle-cpu-csaf:backfill:2026-09-17`, `validation:red-hat-csaf:backfill:2026-09-17`, and `validation:red-hat-csaf:delta:2026-09-17`. For a new day's completed Oracle delta, use a new dated delta checkpoint rather than reusing the completed September 17 checkpoint.

No source was automatically promoted during this pass. Successful sample ingestion and partial updates do not prove complete ongoing coverage.

Code validation: 143 tests passed, four environment-dependent tests skipped. TypeScript and ESLint passed. Broadcom regression tests cover pagination, provenance, malformed identifiers, historical CVE separator variants, untrusted origins and unknown product/remediation/per-CVE assessments.
