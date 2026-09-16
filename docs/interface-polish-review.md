# Dashboard interface polish

Applied on September 16, 2026 using [make-interfaces-feel-better](https://github.com/jakubkrehel/make-interfaces-feel-better), installed at `/Users/helper_heavy/.codex/skills/make-interfaces-feel-better`.

**Mode: full.** Scope: the main Vulnerability Intelligence dashboard, including navigation, search, lenses, metrics, priority/change lists, analytics, release context, filters, table actions, pagination, and source disclosures. Framework: React 19. Styling: existing plain CSS, scoped to `.dashboardShell` in `app/globals.css`; the existing Tailwind import is retained. No new UI or animation dependency.

Review boundary: CVE details, vendor details, comparison, archive, and source-administration routes were not redesigned or reviewed. Browser checks use invented representative API fixtures on a local preview, not production vulnerability evidence. No deployment was performed.

| Category | Evidence inspected | Result |
| --- | --- | --- |
| Typography | Metrics, charts, table labels, source metadata, heading/paragraph wrapping; `app/globals.css:435` | 2 findings fixed |
| Surfaces | Nested search/filter corners, panel boundaries, keyboard focus, expanded filters, desktop/mobile navigation and hit areas | 4 findings fixed |
| Animations | Hover, press, copy/check transitions, idle hero, reduced motion; copy feedback inspected at 10% playback speed | 2 findings fixed |
| Icons | Search, quick actions, row arrows, exports, comparison, reset, retry, copy/check; `app/DashboardClient.tsx:282` | 1 finding fixed |
| Performance | Property-specific transitions, panel blur/shadow behavior, redundant filter requests | 1 finding fixed |

Two additional state-consistency findings were fixed alongside those visual categories. Font smoothing was already present and retained. Images are not present in the reviewed dashboard, so image outlines do not apply.

**Typography and numeric stability**

| Severity | Location | Before | After | Why |
| --- | --- | --- | --- | --- |
| MEDIUM | `app/globals.css:441`, `:487`, `:530`, `:546`, `:559`, `:574`, `:638`, `:652` | Supporting information often used 7–10px muted text; headings and long descriptions wrapped without guidance; search text had 3.65:1 contrast against its button background. | Supporting text generally uses 11–13px; headings balance and descriptions wrap prettily; clearer muted colors and severity colors; search button text contrast is 5.19:1 normally and 4.70:1 on hover. | Readability and text wrapping: users can scan evidence, counts, and controls with less effort. Compact table/chart headings retain their distinct hierarchy. |
| LOW | `app/globals.css:435` | Numeric stability depended on scattered monospace declarations. | Dashboard-wide `font-variant-numeric: tabular-nums`. | Tabular numbers: changing scores, totals, dates, and filter counts keep consistent digit widths. |

**Surface hierarchy, geometry, and hit areas**

| Severity | Location | Before | After | Why |
| --- | --- | --- | --- | --- |
| MEDIUM | `app/globals.css:443`, `:448`, `:480`, `:488`, `:503`, `:620` | Many controls were 28–38px high; focus was faint; nested search/filter corners used unrelated radii. | Controls prefer 40px on desktop and 44px on phones; stronger focus indicators, search focus-within ring, inset row focus; search has a 16px radius around its 10px button plus 6px inset; search card uses 36px = 20px padding + 16px search radius; advanced filters use 28px = 18px + 10px. | Minimum hit area, optical alignment, concentric radius: controls are easier to target and visually coherent. Mobile equivalents preserve the inset relationship. |
| LOW | `app/globals.css:457`, `:520`, `:541` | Layered dark shadows, decorative borders, and hover elevation made stationary metrics/cards appear interactive. | Subtle neutral white surface rings; structural dividers and selection borders retained; decorative card blur and hover elevation removed. | Shadows for elevation, borders for structure: data surfaces stay quiet while controls carry interaction cues. |
| MEDIUM | `app/globals.css:448`, `:457`, `:675`, `:687`, `:696` | Brand and navigation crowded intermediate widths; large hero typography dominated the viewport; action rows and dense charts had little room at narrow widths. | Navigation moves to its own scrollable row below 900px; compact responsive hero; wrapping headings/actions, two-column mobile toolbar/filter layout, readable mover rows and source cards; table scroll remains contained. | Optical alignment and responsive geometry: related information remains aligned without horizontal page overflow. |
| HIGH | `app/DashboardClient.tsx:354`, `app/globals.css:594` | More filters opened an absolute/fixed layer inside a clipping panel, potentially hiding its controls. | The disclosure expands within the filter grid; its fields stay in document flow, with a visible chevron and open-state border. | Accessible surfaces: every advanced filter stays reachable on desktop and phones. |

**Motion restraint and local feedback**

| Severity | Location | Before | After | Why |
| --- | --- | --- | --- | --- |
| MEDIUM | `app/globals.css:466`, `:541`, `:551`, `:735` | Continuous hero effects, card lift, row translation, and repeated navigation movement competed with analytical content. | Static hero, stable cards and rows, at most 120ms color feedback for frequent interactions; explicit reduced-motion rules remove transitions and press scaling. | Motion restraint: scanning and repeated filtering do not trigger distracting movement. |
| LOW | `app/DashboardClient.tsx:225`, `app/globals.css:495`, `:669` | Buttons had inconsistent tactile feedback; copy success only swapped its label. | Opt-in action press scale is exactly 0.96, with a `data-static` escape hatch; persistent copy/check SVG layers crossfade using opacity 0↔1, scale .25↔1, blur 4px↔0, and a 300ms non-bouncy easing; stable copy button width and text/live feedback accompany the transition. | Interruptible transitions and contextual icons: feedback stays local, reversible, and understandable without motion. |

**Icons and state consistency**

| Severity | Location | Before | After | Why |
| --- | --- | --- | --- | --- |
| LOW | `app/DashboardClient.tsx:141`, `:149`, `:175`, `:213`, `:222`, `:282`; `app/globals.css:667` | Unicode search/arrows and text-only actions had inconsistent visual weight. | A small dependency-free SVG set uses `currentColor`, a shared 24px grid, consistent outline style, 1.5px stroke beside regular text and 2px beside semibold buttons; decorative icons are hidden from assistive technology. | Match icon stroke to text; recolor one SVG per state rather than swapping decorative assets. |
| MEDIUM | `app/DashboardClient.tsx:76`, `:123`, `:141`, `:152`, `:175`, `:220` | Copy/reset lacked complete pending/disabled feedback; failed refresh had no direct retry; an empty table lacked a recovery message; priority selection and table relationships were incomplete for assistive technology. | Explicit pending/success/error labels, clipboard guidance and timer cleanup, retry action, disabled pristine reset and loading pagination, filter-count/status text, accessible search/table headers, selected priority pills, and an actionable empty state below the horizontally scrolling table. | Static feedback accompanies animation; loading, failure, and no-results states explain what happened and what the user can do. |
| MEDIUM | `app/DashboardClient.tsx:341`, `:369` | Uncontrolled filter values could stay visible after clearing/back navigation; Enter did not apply typed filters. | Inputs remount from their applied URL value when it changes; Enter commits through blur; clear and history restore displayed values. | State consistency: visible controls agree with the applied query. |

**Performance**

| Severity | Location | Before | After | Why |
| --- | --- | --- | --- | --- |
| LOW | `app/DashboardClient.tsx:88`, `app/globals.css:435` | Blurring an unchanged input refetched all dashboard panels; ornamental surface transitions and blur added work. | Unchanged filters return early; transitions name their properties; stationary panels remove animation/backdrop blur; no `will-change` promotion or new animation dependency. | Transition specificity and restrained compositing reduce work without changing the API/data contracts. |

**Considered but rejected**

| Location | Candidate | Rejected because |
| --- | --- | --- |
| `app/DashboardClient.tsx` | Add Motion/Framer Motion for icon feedback | Two persistent CSS layers provide the required transition without another runtime dependency. |
| `app/globals.css` | Stagger metric/chart entrance and animate filter results | This is a frequently refreshed operational dashboard; repeated entrances would compete with reading data. |
| `app/globals.css` | Replace the established dark-blue visual design or restyle every route | The request is to apply polish to this dashboard; scoped refinements preserve its identity and avoid unrelated screens. |
| `app/globals.css` | Replace native selects and date inputs with custom popovers | Native keyboard/date behavior is already appropriate; improving sizing, focus, and disclosure containment resolves the observed problems. |

**Verification**

Validation results and screenshots are saved in `work/interface-polish/`. Browser fixtures are deliberately invented and must not be presented as real vulnerability intelligence.

- `pnpm lint`: passed.
- `node --import tsx --test tests/rendered-html.test.mjs tests/vulnerability-intelligence-analytics.test.mjs tests/production-readiness.test.mjs`: 29 tests passed.
- `VITE_API_BASE_URL=https://example.ts.net pnpm pages:build`: production client build passed.
- `VITE_API_BASE_URL=https://example.ts.net pnpm test:pages`: 2 artifact checks passed. `example.ts.net` is a build-validation placeholder, not a deployment target.
- `pnpm exec tsc --project work/interface-polish/tsconfig.current.json --incremental false`: passed. This temporary configuration extends the real configuration and excludes archived `work/` files.
- `pnpm run typecheck`: blocked by pre-existing archived Cloudflare/D1 rollback-source errors under `work/native-setup/rollback-candidate-20260912`; no project TypeScript configuration was changed.
- Browser script: `node --import tsx work/interface-polish/browser-check.mjs final`: **22/22 checks passed**. Checks cover populated/empty/loading/failure states, 1440/390/320px layouts, expanded filters, URL persistence/history, reset and Enter behavior, clipboard pending/success/failure/retry, hover/keyboard focus/press, 10% motion playback, reduced motion, touch targets, pagination, and runtime errors. Zero runtime errors; eight expected HTTP 503 console messages came from the deliberate failure fixture. See `work/interface-polish/final-report.json` for individual outcomes.
- Visually inspected full-page and viewport screenshots at desktop and mobile sizes. Readable previews: `work/interface-polish/final-1440-viewport.png` and `work/interface-polish/final-390-viewport.png`.

**Verdict: Approve for the reviewed local dashboard scope.** No actionable interface-polish findings remain in the inspected states. Unverified: production end-to-end connectivity, other dashboard routes, real-device Safari/Firefox, and physical screen-reader testing. The standard unfiltered TypeScript command remains affected by the archived rollback files described above.
