# Source expansion interface review

Full mode, scoped to changed dashboard filters, coverage states, comparison assessments and CVE detail sections. React with the existing shared CSS system. No redesign of unchanged charts or navigation.

| Category | Evidence inspected | Result |
| --- | --- | --- |
| Typography | CVE detail screenshot at 320 px; enrichment styles and comparison code | Fixed long-vector wrapping, spacing and assessment consistency |
| Surfaces | Coverage panel and source-health readiness styles | Pending sources use neutral states; existing panel tokens retained |
| Animations | Changed components and CSS | No new animation; existing reduced-motion behavior retained |
| Icons | Changed filter and detail controls | Existing text/native select and link conventions retained |
| Performance | Production bundle, canonical/projection queries, browser console | Build passed; no browser errors; extra row assertions loaded after pagination |

| Severity | Location | Before | After | Why |
| --- | --- | --- | --- | --- |
| MEDIUM | app/DashboardClient.tsx:351 | No way to separate exploitation catalogs | Labelled VulnCheck and exploitation-source selects, distinct membership badge | Explicit state avoids confusing independent assertions |
| MEDIUM | app/DashboardClient.tsx:213, app/SourceHealthClient.tsx:16 | Unconfigured sources resemble failed production feeds | Readiness labels/reasons, neutral pending states, production-only freshness denominator | Status should reflect what is actually operational |
| MEDIUM | app/cve/[id]/CveDetailClient.tsx:53, app/globals.css:744 | New enrichment paragraphs lacked shared spacing and could overflow | Shared typography, wrapping, tabular scores and 44 px source links | Readability and target sizing at phone widths |
| MEDIUM | app/cve/[id]/CveDetailClient.tsx:49, app/CveComparisonClient.tsx:28 | Snapshot/comparison could show unknown despite canonical fallback | Use the same assessment precedence as dashboard priority | Consistent representations prevent misleading assessment differences |

Considered: additional hover/motion on enrichment panels was rejected because static evidence panels need no animation. Stronger shadows were rejected because existing panel depth already separates records.

Verification: `pnpm lint`, `pnpm typecheck`, `pnpm test`, production `pnpm pages:build`; Playwright expansion checks at 1440, 390 and 320 px, filter interactions, detail navigation, no horizontal overflow or JavaScript errors. Inspected generated detail screenshot. Full keyboard/screen-reader audit and upstream-populated production detail states are not verified by this scoped check.

Verdict: Approve for the reviewed scope; the two broader checks above remain unverified.
