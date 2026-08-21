"use client";

import { useCallback, useEffect, useState } from "react";
import type { DashboardResponse } from "../lib/api/contracts";

export function DashboardClient({ initialData, apiBaseUrl = "", cvePathPrefix = "/cve/" }: { initialData: DashboardResponse; apiBaseUrl?: string; cvePathPrefix?: string }) {
  const [data, setData] = useState(initialData);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [filters, setFilters] = useState<Record<string, string>>({});

  const load = useCallback(async (search = window.location.search) => {
    const params = new URLSearchParams(search);
    setFilters(Object.fromEntries(params.entries()));
    setQuery(params.get("q") ?? "");
    setLoading(true); setError(null);
    try {
      const response = await fetch(`${apiBaseUrl}/api/dashboard${search}`, { headers: { accept: "application/json" } });
      if (!response.ok) throw new Error(`Dashboard returned ${response.status}`);
      setData(await response.json() as DashboardResponse);
    } catch { setError("Live intelligence could not be refreshed. The last available snapshot remains visible."); }
    finally { setLoading(false); }
  }, [apiBaseUrl]);

  const cveHref = (cveId: string) => `${cvePathPrefix}${encodeURIComponent(cveId)}`;

  useEffect(() => {
    const initialRefresh = window.setTimeout(() => void load(), 0);
    const pop = () => void load();
    window.addEventListener("popstate", pop);
    return () => { window.clearTimeout(initialRefresh); window.removeEventListener("popstate", pop); };
  }, [load]);

  const setFilter = (key: string, value: string) => {
    const params = new URLSearchParams(window.location.search);
    if (value) params.set(key, value); else params.delete(key);
    if (key !== "cursor") params.delete("cursor");
    const search = params.size ? `?${params}` : "";
    window.history.pushState({}, "", `${window.location.pathname}${search}`);
    void load(search);
  };

  const sourceHealthy = data.sourceHealth.filter((source) => source.freshness === "fresh" && source.result !== "failed").length;
  const topPriority = data.rows.slice(0, 5);
  const changeLabels: Record<string, string> = { KEV_ADDED: "KEV added", FIXED_VERSION_CHANGED: "Fixed version", SEVERITY_CHANGED: "Severity changed", WORKAROUND_ADDED: "Workaround added", MITIGATION_ADDED: "Mitigation added", EXPLOITATION_STATUS_CHANGED: "Exploitation changed", ADVISORY_REVISED: "Advisory revised", REMEDIATION_CHANGED: "Remediation changed" };

  return (
    <main className="shell">
      <header className="topbar">
        <a className="brand" href="#top"><span className="brandMark">PI</span><span><strong>Patch Intelligence</strong><small>Operational vulnerability intelligence</small></span></a>
        <nav aria-label="Primary navigation"><a className="active" href="#overview">Overview</a><a href="#patch-tuesday">Patch Tuesday</a><a href="#sources">Sources</a></nav>
        <div className="health"><i className={sourceHealthy < data.sourceHealth.length ? "warn" : ""} /><span><strong>{sourceHealthy}/{data.sourceHealth.length || 4} sources healthy</strong><small>{data.demo ? "Representative preview data" : `Updated ${timeAgo(data.generatedAt)}`}</small></span></div>
      </header>

      <section className="hero" id="top">
        <div><p className="eyebrow">Rolling 6 months · {formatDate(data.generatedAt)}</p><h1>What needs attention now</h1><p>A prioritized view of new vulnerabilities, advisory revisions, exploitation evidence, and available remediation.</p></div>
        <form className="search" onSubmit={(event) => { event.preventDefault(); setFilter("q", query); }}><span>⌕</span><input aria-label="Search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search CVE, vendor, or product" /></form>
      </section>

      {error && <div className="notice" role="status">{error}</div>}
      <section className="since" id="overview" aria-busy={loading}>
        <div className="sectionTitle"><span><i /><h2>Since last refresh</h2></span><small>{data.changes.since ? `Changes observed since ${formatDateTime(data.changes.since)}` : "Awaiting a second successful ingestion"}</small></div>
        <div className="metrics">
          <Metric label="New CVEs" value={data.changes.newCves} detail="Newly published" />
          <Metric label="New Critical" value={data.changes.newCritical} detail="Vendor severity" tone="red" />
          <Metric label="Newly exploited" value={data.changes.newlyKnownExploited} detail="Authoritative evidence" tone="red" />
          <Metric label="New CISA KEV" value={data.changes.newKev} detail="CISA-confirmed" tone="orange" />
          <Metric label="Revised advisories" value={data.changes.revisedAdvisories} detail="Meaningful revisions" />
          <Metric label="New remediation" value={data.changes.newRemediation} detail="Patch, fix, or workaround" tone="green" />
        </div>
      </section>

      <section className="grid">
        <article className="panel queuePanel">
          <div className="panelHead"><div><p className="eyebrow">Operational triage</p><h2>Priority queue</h2></div><div className="pills"><button type="button" className="p1" onClick={() => setFilter("priority", "P1")}>P1 <b>{data.priorityDistribution.P1}</b></button><button type="button" className="p2" onClick={() => setFilter("priority", "P2")}>P2 <b>{data.priorityDistribution.P2}</b></button><button type="button" onClick={() => setFilter("priority", "P3")}>P3 <b>{data.priorityDistribution.P3}</b></button></div></div>
          {topPriority.length ? topPriority.map((item) => <a className="queueRow" href={cveHref(item.cveId)} key={item.cveId}><span className={`badge ${item.priority.level.toLowerCase()}`}>{item.priority.level}</span><span className="queueCopy"><small>{item.vendor} · {item.cveId}</small><strong>{item.title}</strong><em>{item.priority.reasons.join(" · ")}</em></span><span className="fix">{item.patchAvailable ? "✓ Patch available" : item.workaroundAvailable ? "◇ Workaround" : "Review advisory"}</span><span className="arrow">→</span></a>) : <EmptyState message="No vulnerabilities match the active filters." />}
          <a className="viewAll" href="#vulnerabilities">Review full intelligence table →</a>
        </article>

        <aside className="panel">
          <div className="panelHead"><div><p className="eyebrow">Revision intelligence</p><h2>Meaningful changes</h2></div></div>
          {data.recentChanges.length ? data.recentChanges.slice(0, 6).map((change) => <a className="change" href={change.cveId ? cveHref(change.cveId) : "#vulnerabilities"} key={`${change.changeType}-${change.observedAt}-${change.cveId}`}><i /><span><small>{changeLabels[change.changeType] ?? titleCase(change.changeType)} · {timeAgo(change.observedAt)}</small><strong>{change.cveId ?? "Vendor advisory"}</strong><em>{change.summary}</em></span></a>) : <EmptyState message="No material revisions in this interval." />}
        </aside>
      </section>

      <section className="analyticsGrid">
        <article className="panel chartPanel"><div className="panelHead"><div><p className="eyebrow">Current filtered set</p><h2>Severity distribution</h2></div></div><BarList values={data.severitySeries} /></article>
        <article className="panel chartPanel"><div className="panelHead"><div><p className="eyebrow">Current filtered set</p><h2>Vendor volume</h2></div></div><BarList values={data.vendorSeries.slice(0, 6)} /></article>
      </section>

      {data.latestReleaseEvent && <section className="panel patchEvent" id="patch-tuesday">
        <div className="panelHead"><div><p className="eyebrow">{data.latestReleaseEvent.eventDate} release event</p><h2>{data.latestReleaseEvent.label}</h2></div><small>{data.latestReleaseEvent.comparison ? `Compared with ${data.latestReleaseEvent.comparison.label}` : "First comparable release event"}</small></div>
        <div className="eventStats"><EventStat value={data.latestReleaseEvent.total} label="Total CVEs" delta={data.latestReleaseEvent.comparison?.totalDelta} /><EventStat value={data.latestReleaseEvent.critical} label="Critical" delta={data.latestReleaseEvent.comparison?.criticalDelta} /><EventStat value={data.latestReleaseEvent.knownExploited} label="Known exploited" delta={data.latestReleaseEvent.comparison?.knownExploitedDelta} /><EventStat value={data.latestReleaseEvent.zeroDay} label="Zero-days" delta={data.latestReleaseEvent.comparison?.zeroDayDelta} /></div>
        <BarList values={data.latestReleaseEvent.productFamilies} />
      </section>}

      <section className="panel tablePanel" id="vulnerabilities">
        <div className="panelHead tableHeading"><div><p className="eyebrow">{data.metrics.total} matching records</p><h2>Vulnerability intelligence</h2></div><button type="button" onClick={() => clearFilters(load)}>Clear filters</button></div>
        <FilterBar filters={filters} setFilter={setFilter} />
        <div className="tableWrap"><table><thead><tr><th>Priority / CVE</th><th>Vendor & product</th><th>Severity</th><th>CVSS</th><th>EPSS</th><th>Intelligence</th><th>Remediation</th><th>Modified</th></tr></thead><tbody>{data.rows.map((item) => <tr key={item.cveId}><td><span className={`badge ${item.priority.level.toLowerCase()}`}>{item.priority.level}</span><a href={cveHref(item.cveId)}><strong>{item.cveId}</strong></a></td><td><strong>{item.vendor}</strong><small>{item.product ?? "Product not specified"}</small></td><td><span className={`severity ${item.severity}`}>{titleCase(item.severity)}</span></td><td><strong>{item.cvss?.toFixed(1) ?? "—"}</strong></td><td><strong>{item.epssPercentile == null ? "—" : `${Math.round(item.epssPercentile * 100)}th`}</strong><small>{item.epss == null ? "No current score" : `${(item.epss * 100).toFixed(1)}% probability`}</small></td><td><span className="tags">{item.kev && <b>KEV</b>}{item.knownExploited && <b>Exploited</b>}{item.zeroDay && <b>Zero-day</b>}</span></td><td><span className={item.patchAvailable ? "fix" : "muted"}>{item.patchAvailable ? "✓ Patch" : item.mitigationAvailable ? "Mitigation" : item.workaroundAvailable ? "Workaround" : "Not stated"}</span></td><td><strong>{item.modifiedAt ? timeAgo(item.modifiedAt) : "—"}</strong><small>{item.modifiedAt ? formatDate(item.modifiedAt) : "No modification date"}</small></td></tr>)}</tbody></table></div>
        {data.nextCursor && <button className="loadMore" type="button" onClick={() => setFilter("cursor", data.nextCursor!)}>Load more vulnerabilities</button>}
      </section>

      <section className="panel sourcePanel" id="sources"><div className="panelHead"><div><p className="eyebrow">Ingestion operations</p><h2>Source health</h2></div></div><div className="sourceGrid">{data.sourceHealth.map((source) => <article key={source.sourceId}><span className={`sourceState ${source.result === "failed" || source.freshness === "stale" ? "failed" : ""}`} /><div><strong>{source.name}</strong><small>{source.result ?? "Not run"}{source.mode ? ` · ${source.mode}` : ""}{source.lastAttempt ? ` · attempted ${timeAgo(source.lastAttempt)}` : ""} · {source.lastSuccess ? `last success ${timeAgo(source.lastSuccess)}` : "awaiting first run"}{source.durationMs != null ? ` · ${source.durationMs} ms` : ""}</small></div><dl><div><dt>Discovered</dt><dd>{source.discovered}</dd></div><div><dt>Inserted</dt><dd>{source.inserted}</dd></div><div><dt>Changed</dt><dd>{source.changed}</dd></div><div><dt>Unchanged</dt><dd>{source.unchanged}</dd></div><div><dt>Failed</dt><dd>{source.failed}</dd></div></dl>{source.lastFailure && <p>Last failed attempt {timeAgo(source.lastFailure)}.</p>}{source.boundHit && <p>Configured Free-plan batch bound reached; continuation is preserved.</p>}{source.lease.active && <p>Ingestion lease active until {formatDateTime(source.lease.expiresAt!)}</p>}{source.checkpoint && <p>{titleCase(source.checkpoint.status)} checkpoint · {formatDate(source.checkpoint.windowStart)} through {formatDate(source.checkpoint.windowEnd)}</p>}{source.errorSummary && <p>{source.errorSummary}</p>}</article>)}</div></section>
    </main>
  );
}

function Metric({ label, value, detail, tone = "" }: { label: string; value: number; detail: string; tone?: string }) { return <article><span>{label}</span><strong className={tone}>{value}</strong><small>{detail}</small></article>; }
function EventStat({ value, label, delta }: { value: number; label: string; delta?: number }) { return <div><strong>{value}</strong><span>{label}</span><small>{delta == null ? "Authoritative source data" : `${delta > 0 ? "+" : ""}${delta} vs prior event`}</small></div>; }
function EmptyState({ message }: { message: string }) { return <p className="emptyState">{message}</p>; }
function BarList({ values }: { values: Array<{ label: string; value: number }> }) { const max = Math.max(1, ...values.map((item) => item.value)); return <div className="barList">{values.map((item) => <div key={item.label}><span>{item.label}</span><i><b style={{ width: `${(item.value / max) * 100}%` }} /></i><strong>{item.value}</strong></div>)}</div>; }
function FilterBar({ filters, setFilter }: { filters: Record<string, string>; setFilter: (key: string, value: string) => void }) {
  const vendors = ["microsoft", "cisco", "adobe", "fortinet", "palo-alto", "ivanti", "vmware-broadcom", "citrix", "chrome", "mozilla", "apple", "oracle", "atlassian", "sap"];
  return <div className="filters">
    <select aria-label="Vendor" value={filters.vendor ?? ""} onChange={(event) => setFilter("vendor", event.target.value)}><option value="">All vendors</option>{vendors.map((vendor) => <option key={vendor} value={vendor}>{titleCase(vendor)}</option>)}</select>
    <select aria-label="Severity" value={filters.severity ?? ""} onChange={(event) => setFilter("severity", event.target.value)}><option value="">All severities</option>{["critical", "high", "medium", "low"].map((value) => <option key={value} value={value}>{titleCase(value)}</option>)}</select>
    <select aria-label="Priority" value={filters.priority ?? ""} onChange={(event) => setFilter("priority", event.target.value)}><option value="">All priorities</option><option>P1</option><option>P2</option><option>P3</option></select>
    <select aria-label="Exploitation" value={filters.exploited ?? ""} onChange={(event) => setFilter("exploited", event.target.value)}><option value="">Any exploitation</option><option value="true">Known exploited</option><option value="false">Not known exploited</option></select>
    <select aria-label="CISA KEV" value={filters.kev ?? ""} onChange={(event) => setFilter("kev", event.target.value)}><option value="">Any KEV state</option><option value="true">In CISA KEV</option><option value="false">Not in CISA KEV</option></select>
    <select aria-label="Patch availability" value={filters.patchAvailable ?? ""} onChange={(event) => setFilter("patchAvailable", event.target.value)}><option value="">Any patch state</option><option value="true">Patch available</option><option value="false">No patch stated</option></select>
    <select aria-label="Sort vulnerabilities" value={filters.sort ?? ""} onChange={(event) => setFilter("sort", event.target.value)}><option value="">Operational priority</option><option value="epss">EPSS percentile</option><option value="cvss">CVSS</option><option value="modified">Last modified</option><option value="published">Publication date</option></select>
    <details><summary>More filters</summary><div className="moreFilters">
      <label>Product<input defaultValue={filters.product ?? ""} onBlur={(event) => setFilter("product", event.target.value)} /></label>
      <label>Minimum CVSS<input type="number" min="0" max="10" step="0.1" defaultValue={filters.cvssMin ?? ""} onBlur={(event) => setFilter("cvssMin", event.target.value)} /></label>
      <label>Maximum CVSS<input type="number" min="0" max="10" step="0.1" defaultValue={filters.cvssMax ?? ""} onBlur={(event) => setFilter("cvssMax", event.target.value)} /></label>
      <label>Minimum EPSS score<input type="number" min="0" max="1" step="0.01" defaultValue={filters.epssMin ?? ""} onBlur={(event) => setFilter("epssMin", event.target.value)} /></label>
      <label>Minimum EPSS percentile<input type="number" min="0" max="1" step="0.01" defaultValue={filters.epssPercentileMin ?? ""} onBlur={(event) => setFilter("epssPercentileMin", event.target.value)} /></label>
      <label>Published from<input type="date" defaultValue={filters.publishedFrom ?? ""} onBlur={(event) => setFilter("publishedFrom", event.target.value)} /></label>
      <label>Published through<input type="date" defaultValue={filters.publishedTo ?? ""} onBlur={(event) => setFilter("publishedTo", event.target.value)} /></label>
      <label>Modified from<input type="date" defaultValue={filters.modifiedFrom ?? ""} onBlur={(event) => setFilter("modifiedFrom", event.target.value)} /></label>
      <label>Modified through<input type="date" defaultValue={filters.modifiedTo ?? ""} onBlur={(event) => setFilter("modifiedTo", event.target.value)} /></label>
      <label>Zero-day<select value={filters.zeroDay ?? ""} onChange={(event) => setFilter("zeroDay", event.target.value)}><option value="">Any</option><option value="true">Confirmed</option><option value="false">Not confirmed</option></select></label>
      <label>Mitigation<select value={filters.mitigationAvailable ?? ""} onChange={(event) => setFilter("mitigationAvailable", event.target.value)}><option value="">Any</option><option value="true">Available</option><option value="false">Not stated</option></select></label>
      <label>Workaround<select value={filters.workaroundAvailable ?? ""} onChange={(event) => setFilter("workaroundAvailable", event.target.value)}><option value="">Any</option><option value="true">Available</option><option value="false">Not stated</option></select></label>
    </div></details>
  </div>;
}
function clearFilters(load: (search?: string) => Promise<void>) { window.history.pushState({}, "", window.location.pathname); void load(""); }
function formatDate(value: string) { return new Intl.DateTimeFormat("en", { month: "short", day: "numeric", year: "numeric", timeZone: "UTC" }).format(new Date(value)); }
function formatDateTime(value: string) { return new Intl.DateTimeFormat("en", { month: "short", day: "numeric", hour: "numeric", minute: "2-digit", timeZone: "UTC" }).format(new Date(value)); }
function timeAgo(value: string) { const seconds = Math.max(0, Math.round((Date.now() - new Date(value).getTime()) / 1000)); if (seconds < 60) return `${seconds}s ago`; if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`; if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`; return `${Math.floor(seconds / 86400)}d ago`; }
function titleCase(value: string) { return value.replaceAll("_", " ").replaceAll("-", " ").replace(/\b\w/g, (letter) => letter.toUpperCase()); }
