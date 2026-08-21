"use client";

import { useEffect, useMemo, useState } from "react";
import type { CveDetailResponse } from "../lib/api/contracts";
import { parseComparisonCves } from "../lib/domain/routes";

interface ComparisonResult { cveId: string; detail: CveDetailResponse | null; error: string | null; }

export function CveComparisonClient({ cveIds, apiBaseUrl = "", backHref = "/", cvePathPrefix = "/cve/" }: { cveIds?: string[]; apiBaseUrl?: string; backHref?: string; cvePathPrefix?: string }) {
  const ids = useMemo(() => cveIds ? parseComparisonCves(cveIds.join(",")) : parseComparisonCves(typeof window === "undefined" ? "" : new URLSearchParams(window.location.search).get("cves")), [cveIds]);
  const [results, setResults] = useState<ComparisonResult[]>([]);
  const [status, setStatus] = useState<"loading" | "ready" | "invalid">(ids.length >= 2 ? "loading" : "invalid");

  useEffect(() => {
    if (ids.length < 2) return;
    const controller = new AbortController();
    Promise.all(ids.map(async (cveId): Promise<ComparisonResult> => {
      try { const response = await fetch(`${apiBaseUrl}/api/cves/${encodeURIComponent(cveId)}`, { headers: { accept: "application/json" }, signal: controller.signal }); if (!response.ok) return { cveId, detail: null, error: response.status === 404 ? "Not in the rolling six-month dataset" : `API returned ${response.status}` }; return { cveId, detail: await response.json() as CveDetailResponse, error: null }; }
      catch (error: unknown) { return { cveId, detail: null, error: (error as { name?: string }).name === "AbortError" ? "Request cancelled" : "Intelligence unavailable" }; }
    })).then((values) => { if (!controller.signal.aborted) { setResults(values); setStatus("ready"); } });
    return () => controller.abort();
  }, [apiBaseUrl, ids]);

  if (ids.length < 2 || status === "invalid") return <ComparisonState backHref={backHref} title="Choose two or three CVEs" message="Comparison URLs accept two or three unique CVE identifiers in the cves query parameter." />;
  if (status === "loading") return <ComparisonState backHref={backHref} title="Loading comparison" message={`Retrieving authoritative intelligence for ${ids.join(", ")}.`} />;

  return <main className="detailShell comparisonShell">
    <header className="detailTop"><a className="brand" href={backHref}><span className="brandMark">VI</span><span><strong>Vulnerability Intelligence</strong><small>Cross-vendor vulnerability and threat intelligence</small></span></a><a className="backLink" href={backHref}>← Dashboard</a></header>
    <section className="comparisonHero"><p className="eyebrow">Read-only · URL-shareable</p><h1>Vulnerability comparison</h1><p>Side-by-side canonical and source-specific intelligence. Missing assertions stay visibly unknown.</p></section>
    <section className="panel comparisonPanel"><div className="tableWrap"><table><thead><tr><th>Intelligence field</th>{results.map((result) => <th key={result.cveId}><a href={`${cvePathPrefix}${encodeURIComponent(result.cveId)}`}>{result.cveId}</a></th>)}</tr></thead><tbody>
      <ComparisonRow label="Status" results={results} value={(detail, result) => result.error ?? (detail ? "Available" : "Unavailable")} />
      <ComparisonRow label="Priority" results={results} value={(detail) => detail ? `${detail.priority.level} — ${priorityLabel(detail.priority.level)} · ${detail.priority.reasons.join(" · ")}` : "—"} />
      <ComparisonRow label="Severity" results={results} value={(detail) => detail ? highestSeverity(detail) : "—"} />
      <ComparisonRow label="CVSS" results={results} value={(detail) => detail ? score(detail.canonical.cvss ?? highestVendorCvss(detail)) : "—"} />
      <ComparisonRow label="EPSS" results={results} value={(detail) => detail?.epss.current ? `${(detail.epss.current.score * 100).toFixed(2)}% · ${Math.round(detail.epss.current.percentile * 100)}th percentile` : "Not observed"} />
      <ComparisonRow label="Known exploitation" results={results} value={(detail) => detail?.exploitation.knownExploited ? "Confirmed by authoritative evidence" : "Not confirmed"} threat />
      <ComparisonRow label="CISA KEV" results={results} value={(detail) => detail?.kev?.active ? `Active · added ${date(detail.kev.dateAdded)}${detail.kev.dueDate ? ` · due ${date(detail.kev.dueDate)}` : ""}` : "Not listed"} threat />
      <ComparisonRow label="Zero-day" results={results} value={(detail) => detail?.exploitation.zeroDay ? "Confirmed by authoritative evidence" : "Not confirmed"} threat />
      <ComparisonRow label="Vendor advisories" results={results} value={(detail) => detail ? unique(detail.advisories.map((item) => `${item.vendor}: ${item.vendorAdvisoryId}`)).join(" · ") || "Not observed" : "—"} />
      <ComparisonRow label="Affected products" results={results} value={(detail) => detail ? unique(detail.affectedProducts.map((item) => `${item.vendor}: ${item.product}`)).join(" · ") || "Not specified" : "—"} />
      <ComparisonRow label="Published / modified" results={results} value={(detail) => detail ? `${date(detail.canonical.publishedAt)} / ${date(detail.canonical.modifiedAt)}` : "—"} />
      <ComparisonRow label="Authoritative sources" results={results} value={(detail) => detail ? `${detail.sourceLinks.length} linked source${detail.sourceLinks.length === 1 ? "" : "s"}` : "—"} />
    </tbody></table></div></section>
    <section className="comparisonSources">{results.map((result) => <article className="panel" key={result.cveId}><div className="panelHead"><div><p className="eyebrow">Source correlation</p><h2>{result.cveId}</h2></div></div>{result.detail?.sourceLinks.length ? <ul>{result.detail.sourceLinks.map((source) => <li key={source.url}><a href={source.url} target="_blank" rel="noreferrer">{source.label} ↗</a></li>)}</ul> : <p className="emptyState">{result.error ?? "No source links available."}</p>}</article>)}</section>
  </main>;
}

function ComparisonRow({ label, results, value, threat = false }: { label: string; results: ComparisonResult[]; value: (detail: CveDetailResponse | null, result: ComparisonResult) => string; threat?: boolean }) { return <tr><th scope="row">{label}</th>{results.map((result) => <td className={threat && /Confirmed|Active/.test(value(result.detail, result)) ? "comparisonThreat" : ""} key={result.cveId}>{value(result.detail, result)}</td>)}</tr>; }
function ComparisonState({ backHref, title, message }: { backHref: string; title: string; message: string }) { return <main className="detailState"><a href={backHref}>← Vulnerability Intelligence</a><h1>{title}</h1><p>{message}</p></main>; }
function unique(values: string[]) { return [...new Set(values)]; }
function score(value: number | null) { return value == null ? "Not stated" : value.toFixed(1); }
function date(value: string | null) { return value ? new Intl.DateTimeFormat("en", { dateStyle: "medium", timeZone: "UTC" }).format(new Date(value)) : "Not stated"; }
function priorityLabel(value: CveDetailResponse["priority"]["level"]) { return value === "P1" ? "Active Threat" : value === "P2" ? "Elevated Intelligence" : "Monitored"; }
function highestSeverity(detail: CveDetailResponse) { const order = ["critical", "high", "medium", "low", "unknown"]; const severity = [...detail.advisories].sort((a, b) => order.indexOf(a.normalizedSeverity) - order.indexOf(b.normalizedSeverity))[0]?.normalizedSeverity; return severity ? severity[0].toUpperCase() + severity.slice(1) : "Not stated"; }
function highestVendorCvss(detail: CveDetailResponse) { const scores = detail.advisories.map((item) => item.vendorCvss).filter((item): item is number => item != null); return scores.length ? Math.max(...scores) : null; }
