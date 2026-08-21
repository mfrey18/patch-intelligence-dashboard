"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import type { DashboardResponse } from "../lib/api/contracts";
import type { DashboardVulnerabilityRow } from "../lib/domain/types";

export function DashboardClient({ initialData, apiBaseUrl = "", cvePathPrefix = "/cve/", vendorPathPrefix = "/vendor/", comparePathPrefix = "/compare?cves=" }: { initialData: DashboardResponse; apiBaseUrl?: string; cvePathPrefix?: string; vendorPathPrefix?: string; comparePathPrefix?: string }) {
  const [data, setData] = useState(initialData);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [filters, setFilters] = useState<Record<string, string>>({});
  const [shareStatus, setShareStatus] = useState("Copy view URL");

  const load = useCallback(async (search = window.location.search) => {
    const params = new URLSearchParams(search);
    setFilters(Object.fromEntries(params.entries()));
    setQuery(params.get("q") ?? "");
    setLoading(true);
    setError(null);
    try {
      const response = await fetch(`${apiBaseUrl}/api/dashboard${search}`, { headers: { accept: "application/json" } });
      if (!response.ok) throw new Error(`Dashboard returned ${response.status}`);
      setData(await response.json() as DashboardResponse);
    } catch {
      setError("Live intelligence could not be refreshed. The last available snapshot remains visible.");
    } finally {
      setLoading(false);
    }
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
    window.history.pushState({}, "", `${window.location.pathname}${search}${window.location.hash}`);
    void load(search);
  };

  const applyLens = (lens: "all" | "urgent" | "exploited" | "remediation") => {
    const params = new URLSearchParams(window.location.search);
    for (const key of ["priority", "exploited", "patchAvailable", "cursor"]) params.delete(key);
    if (lens === "urgent") params.set("priority", "P1");
    if (lens === "exploited") params.set("exploited", "true");
    if (lens === "remediation") params.set("patchAvailable", "true");
    const search = params.size ? `?${params}` : "";
    window.history.pushState({}, "", `${window.location.pathname}${search}${window.location.hash}`);
    void load(search);
  };

  const sourceHealthy = data.sourceHealth.filter((source) => source.freshness === "fresh" && source.result !== "failed").length;
  const topPriority = data.rows.slice(0, 5);
  const activeLens = filters.priority === "P1" ? "urgent" : filters.exploited === "true" ? "exploited" : filters.patchAvailable === "true" ? "remediation" : "all";
  const orderedChanges = useMemo(() => [...data.recentChanges].sort((a, b) => changeWeight(b.changeType) - changeWeight(a.changeType) || Date.parse(b.observedAt) - Date.parse(a.observedAt)), [data.recentChanges]);

  return (
    <main className="shell">
      <header className="topbar">
        <a className="brand" href="#top"><span className="brandMark">VI</span><span><strong>Vulnerability Intelligence</strong><small>Cross-vendor vulnerability and threat intelligence</small></span></a>
        <nav aria-label="Primary navigation"><a className="active" href="#overview">Overview</a><a href="#threats">Threats</a><a href="#vulnerabilities">Vulnerabilities</a><a href="#sources">Sources</a></nav>
        <div className="health"><i className={sourceHealthy < data.sourceHealth.length ? "warn" : ""} /><span><strong>{sourceHealthy}/{data.sourceHealth.length || 4} sources fresh</strong><small>{data.demo ? "Representative preview data" : `Updated ${timeAgo(data.generatedAt)}`}</small></span></div>
      </header>

      <section className="hero" id="top">
        <div className="heroGlow" aria-hidden="true" />
        <div className="heroCopy"><p className="eyebrow">Rolling 6 months · {formatDate(data.generatedAt)}</p><h1 aria-label="Vulnerability Intelligence Dashboard: See the threat. Know what changed.">See the threat.<br /><span>Know what changed.</span></h1><p>Authoritative vulnerability intelligence turns vendor advisories, exploitation evidence, CISA KEV, and EPSS into a clear operational picture.</p>
          <div className="heroActions" aria-label="Intelligence lenses">
            <button type="button" aria-pressed={activeLens === "all"} onClick={() => applyLens("all")}><span>All intelligence</span><b>{data.metrics.total}</b></button>
            <button type="button" aria-pressed={activeLens === "urgent"} onClick={() => applyLens("urgent")}><span>Immediate attention</span><b>{data.priorityDistribution.P1}</b></button>
            <button type="button" aria-pressed={activeLens === "exploited"} onClick={() => applyLens("exploited")}><span>Known exploited</span><b>{data.metrics.knownExploited}</b></button>
            <button type="button" aria-pressed={activeLens === "remediation"} onClick={() => applyLens("remediation")}><span>Patch available</span><b>{data.metrics.patchAvailable}</b></button>
          </div>
        </div>
        <div className="heroTools"><p>Search the intelligence record</p><form className="search" onSubmit={(event) => { event.preventDefault(); setFilter("q", query); }}><span aria-hidden="true">⌕</span><input aria-label="Search CVE, vendor, or product" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="CVE, vendor, or product" /><button type="submit">Search</button></form><small>{loading ? "Refreshing intelligence…" : `${sourceHealthy}/${data.sourceHealth.length || 4} sources fresh · updated ${timeAgo(data.generatedAt)}`}</small></div>
      </section>

      {error && <div className="notice" role="status">{error}</div>}
      <section className="summary" id="overview" aria-busy={loading}>
        <div className="sectionTitle"><span><i /><h2>Current vulnerability intelligence</h2></span><small>Filtered six-month view · refreshed {formatDateTime(data.generatedAt)}</small></div>
        <div className="metrics">
          <Metric label="Total Vulnerabilities" value={data.metrics.total} detail="Current filtered set" />
          <Metric label="Critical" value={data.metrics.critical} detail="Authoritative vendor severity" tone="red" />
          <Metric label="High" value={data.metrics.high} detail="Authoritative vendor severity" tone="orange" />
          <Metric label="Known Exploited" value={data.metrics.knownExploited} detail="Authoritative evidence" tone="red" />
          <Metric label="CISA KEV" value={data.metrics.kev} detail="Active catalog entries" tone="orange" />
          <Metric label="Zero-Days" value={data.metrics.zeroDay} detail="Authoritative evidence" tone="red" />
        </div>
        <div className="changeStrip" aria-label="Intelligence changes since last refresh">
          <div><span>Since last refresh</span><small>{data.changes.since ? `Since ${formatDateTime(data.changes.since)}` : "Awaiting a second successful ingestion"}</small></div>
          <ChangeMetric label="New vulnerabilities" value={data.changes.newCves} />
          <ChangeMetric label="New Critical" value={data.changes.newCritical} />
          <ChangeMetric label="Newly exploited" value={data.changes.newlyKnownExploited} threat />
          <ChangeMetric label="New CISA KEV" value={data.changes.newKev} threat />
          <ChangeMetric label="Revised advisories" value={data.changes.revisedAdvisories} />
        </div>
      </section>

      <section className="grid" id="threats">
        <article className="panel queuePanel">
          <div className="panelHead"><div><p className="eyebrow">Intelligence prioritization</p><h2>Highest-priority vulnerabilities</h2></div><div className="pills"><button type="button" className="p1" title="P1 — Active Threat" onClick={() => setFilter("priority", "P1")}>P1 <b>{data.priorityDistribution.P1}</b></button><button type="button" className="p2" title="P2 — Elevated Intelligence" onClick={() => setFilter("priority", "P2")}>P2 <b>{data.priorityDistribution.P2}</b></button><button type="button" title="P3 — Monitored" onClick={() => setFilter("priority", "P3")}>P3 <b>{data.priorityDistribution.P3}</b></button></div></div>
          <div className="tierLegend"><span><b>P1</b> Active Threat</span><span><b>P2</b> Elevated Intelligence</span><span><b>P3</b> Monitored</span></div>
          {topPriority.length ? topPriority.map((item) => <a className="queueRow" href={cveHref(item.cveId)} key={item.cveId}><span className={`badge ${item.priority.level.toLowerCase()}`}>{item.priority.level}</span><span className="queueCopy"><small>{item.vendor} · {item.cveId}</small><strong>{item.title}</strong><em>{item.priority.reasons.join(" · ")}</em></span><ThreatTags item={item} /><span className="arrow">→</span></a>) : <EmptyState message="No vulnerabilities match the active filters." />}
          <a className="viewAll" href="#vulnerabilities">Review full vulnerability intelligence →</a>
        </article>

        <aside className="panel changesPanel" id="changes">
          <div className="panelHead"><div><p className="eyebrow">Evidence and assessment revisions</p><h2>Intelligence Changes</h2></div></div>
          <div className="changeCounters"><span><b>{data.changeCategoryCounts.threat}</b> Threat</span><span><b>{data.changeCategoryCounts.assessment}</b> Assessment</span><span><b>{data.changeCategoryCounts.advisory}</b> Advisory</span><span><b>{data.changeCategoryCounts.remediation}</b> Remediation</span></div>
          {orderedChanges.length ? orderedChanges.slice(0, 7).map((change) => <a className={`change ${changeCategory(change.changeType)}`} href={change.cveId ? cveHref(change.cveId) : "#vulnerabilities"} key={`${change.changeType}-${change.observedAt}-${change.cveId}`}><i /><span><small>{changeLabel(change.changeType)} · {timeAgo(change.observedAt)}</small><strong>{change.cveId ?? "Vendor advisory"}</strong><em>{change.summary}</em></span></a>) : <EmptyState message="No material intelligence changes in this interval." />}
        </aside>
      </section>

      <section className="analyticsGrid" aria-label="Six-month vulnerability activity">
        <article className="panel chartPanel"><div className="panelHead"><div><p className="eyebrow">Rolling six-month disclosures</p><h2>Vulnerability activity</h2></div></div><ActivityChart values={data.vulnerabilityActivity} /></article>
        <article className="panel chartPanel"><div className="panelHead"><div><p className="eyebrow">Independent current signals by disclosure month</p><h2>Threat-signal activity</h2></div><small>High EPSS = {`≥90th percentile`} · predictive only</small></div><ThreatActivityChart values={data.threatSignalActivity} /></article>
      </section>

      <section className="analyticsGrid" aria-label="Emerging vulnerability intelligence">
        <article className="panel emergingPanel"><div className="panelHead"><div><p className="eyebrow">Transparent signal inclusion</p><h2>Emerging Vulnerabilities</h2></div></div>{data.emergingVulnerabilities.length ? data.emergingVulnerabilities.slice(0, 6).map((item) => <a className="emergingRow" href={cveHref(item.vulnerability.cveId)} key={item.vulnerability.cveId}><span className={`badge ${item.vulnerability.priority.level.toLowerCase()}`}>{item.vulnerability.priority.level}</span><span><strong>{item.vulnerability.cveId}</strong><small>{item.vulnerability.vendor} · {item.reasons.join(" · ")}</small></span><span className="arrow">→</span></a>) : <EmptyState message="No vulnerabilities meet the emerging-intelligence criteria for this filtered set." />}</article>
        <article className="panel moversPanel"><div className="panelHead"><div><p className="eyebrow">Seven-day, same-model comparison</p><h2>Rising Exploitation Likelihood</h2></div><small>FIRST EPSS predictive enrichment</small></div>{data.epssMovers.length ? data.epssMovers.slice(0, 6).map((item) => <a className="moverRow" href={cveHref(item.cveId)} key={item.cveId}><span><strong>{item.cveId}</strong><small>{item.vendor}{item.product ? ` · ${item.product}` : ""}</small></span><span title={`${item.previousScoreDate} to ${item.scoreDate} · model ${item.modelVersion ?? "not stated"}`}><b>{(item.previousScore * 100).toFixed(2)}% · {ordinalPercentile(item.previousPercentile)}</b><i>→</i><b>{(item.score * 100).toFixed(2)}% · {ordinalPercentile(item.percentile)}</b></span><em>+{Math.round(item.percentileDelta * 100)} pts</em></a>) : <EmptyState message="At least two same-model observations around seven days apart are required before movers are shown." />}</article>
      </section>

      <section className="analyticsGrid" aria-label="Vendor and weakness intelligence">
        <article className="panel chartPanel"><div className="panelHead"><div><p className="eyebrow">Current filtered set</p><h2>Severity distribution</h2></div></div><BarList values={data.severitySeries} /></article>
        <article className="panel chartPanel"><div className="panelHead"><div><p className="eyebrow">Observed intelligence, not a security rating</p><h2>Threat Signals by Vendor</h2></div></div><VendorThreatChart values={data.vendorThreatSeries.slice(0, 8)} vendorPathPrefix={vendorPathPrefix} /></article>
      </section>

      <section className="panel cwePanel" aria-label="Weakness intelligence">
        <div className="panelHead"><div><p className="eyebrow">Canonical CVE enrichment</p><h2>Weakness intelligence</h2></div><small>{data.cweAnalytics.knownCoverage} of {data.cweAnalytics.total} matching CVEs include CWE data</small></div>
        <p className="panelNote">Counts reflect only CVEs with an authoritative canonical CWE. Missing CWE values are excluded and coverage is not presented as complete.</p>
        <CweChart values={data.cweAnalytics.series} />
      </section>

      {data.latestReleaseEvent && <section className="panel patchEvent" id="release-intelligence">
        <div className="panelHead"><div><p className="eyebrow">Vendor release intelligence · {data.latestReleaseEvent.eventDate}</p><h2>{data.latestReleaseEvent.label}</h2></div><small>{data.latestReleaseEvent.comparison ? `Compared with ${data.latestReleaseEvent.comparison.label}` : "First comparable release event"}</small></div>
        <div className="eventStats"><EventStat value={data.latestReleaseEvent.total} label="Total CVEs" delta={data.latestReleaseEvent.comparison?.totalDelta} /><EventStat value={data.latestReleaseEvent.critical} label="Critical" delta={data.latestReleaseEvent.comparison?.criticalDelta} /><EventStat value={data.latestReleaseEvent.knownExploited} label="Known exploited" delta={data.latestReleaseEvent.comparison?.knownExploitedDelta} /><EventStat value={data.latestReleaseEvent.zeroDay} label="Zero-days" delta={data.latestReleaseEvent.comparison?.zeroDayDelta} /></div>
        <BarList values={data.latestReleaseEvent.productFamilies} />
      </section>}

      <section className="panel tablePanel" id="vulnerabilities">
        <div className="panelHead tableHeading"><div><p className="eyebrow">{data.metrics.total} matching records</p><h2>Vulnerability intelligence</h2></div><div className="tableActions">{data.rows.length >= 2 && <a href={`${comparePathPrefix}${data.rows.slice(0, 3).map((item) => item.cveId).join(",")}`}>Compare top {Math.min(3, data.rows.length)}</a>}<button type="button" onClick={() => void copyCurrentView(setShareStatus)}>{shareStatus}</button><button type="button" onClick={() => clearFilters(load)}>Clear filters</button></div></div>
        <FilterBar filters={filters} setFilter={setFilter} />
        <div className="tableWrap"><table><thead><tr><th>Intelligence Priority / CVE</th><th>Vendor / Product</th><th>Severity</th><th>CVSS</th><th>EPSS</th><th>Threat Signals</th><th>Published</th><th>Modified</th></tr></thead><tbody>{data.rows.map((item) => <tr key={item.cveId}><td><span className={`badge ${item.priority.level.toLowerCase()}`}>{item.priority.level}</span><a href={cveHref(item.cveId)}><strong>{item.cveId}</strong></a></td><td><strong>{item.vendor}</strong><small>{item.product ?? "Product not specified"}</small></td><td><span className={`severity ${item.severity}`}>{titleCase(item.severity)}</span></td><td><strong>{item.cvss?.toFixed(1) ?? "—"}</strong></td><td><strong>{item.epssPercentile == null ? "—" : ordinalPercentile(item.epssPercentile)}</strong><small>{item.epss == null ? "No current score" : `${(item.epss * 100).toFixed(1)}% probability`}</small></td><td><ThreatTags item={item} emptyLabel="None confirmed" /></td><td><strong>{item.publishedAt ? formatDate(item.publishedAt) : "—"}</strong><small>{item.publishedAt ? timeAgo(item.publishedAt) : "Not stated"}</small></td><td><strong>{item.modifiedAt ? formatDate(item.modifiedAt) : "—"}</strong><small>{item.modifiedAt ? timeAgo(item.modifiedAt) : "Not stated"}</small></td></tr>)}</tbody></table></div>
        {data.nextCursor && <button className="loadMore" type="button" onClick={() => setFilter("cursor", data.nextCursor!)}>Load more vulnerabilities</button>}
      </section>

      <section className="panel sourcePanel" id="sources"><div className="panelHead"><div><p className="eyebrow">Authoritative-source visibility</p><h2>Coverage &amp; Freshness</h2></div><small>Operational ingestion detail remains available per source.</small></div><div className="sourceGrid">{data.sourceHealth.map((source) => <article key={source.sourceId}><span className={`sourceState ${source.freshness !== "fresh" || source.result === "failed" ? "failed" : ""}`} /><div><strong>{source.name}</strong><small>{titleCase(source.freshness)} · {source.lastSuccess ? `last successful update ${timeAgo(source.lastSuccess)}` : "awaiting first successful update"}</small></div><details><summary>Operator details</summary><div className="sourceOps"><p>{source.result ?? "Not run"}{source.mode ? ` · ${source.mode}` : ""}{source.lastAttempt ? ` · attempted ${timeAgo(source.lastAttempt)}` : ""}{source.durationMs != null ? ` · ${source.durationMs} ms` : ""}</p><dl><div><dt>Discovered</dt><dd>{source.discovered}</dd></div><div><dt>Inserted</dt><dd>{source.inserted}</dd></div><div><dt>Changed</dt><dd>{source.changed}</dd></div><div><dt>Unchanged</dt><dd>{source.unchanged}</dd></div><div><dt>Failed</dt><dd>{source.failed}</dd></div></dl>{source.lastFailure && <p>Last failed attempt {timeAgo(source.lastFailure)}.</p>}{source.boundHit && <p>Configured Free-plan batch bound reached; continuation is preserved.</p>}{source.lease.active && <p>Ingestion lease active until {formatDateTime(source.lease.expiresAt!)}</p>}{source.checkpoint && <p>{titleCase(source.checkpoint.status)} checkpoint · {formatDate(source.checkpoint.windowStart)} through {formatDate(source.checkpoint.windowEnd)}</p>}{source.errorSummary && <p>{source.errorSummary}</p>}</div></details></article>)}</div></section>
    </main>
  );
}

function Metric({ label, value, detail, tone = "" }: { label: string; value: number; detail: string; tone?: string }) { return <article><span>{label}</span><strong className={tone}>{value}</strong><small>{detail}</small></article>; }
function ChangeMetric({ label, value, threat = false }: { label: string; value: number; threat?: boolean }) { return <div className={threat ? "threat" : ""}><strong>{value}</strong><span>{label}</span></div>; }
function EventStat({ value, label, delta }: { value: number; label: string; delta?: number }) { return <div><strong>{value}</strong><span>{label}</span><small>{delta == null ? "Authoritative source data" : `${delta > 0 ? "+" : ""}${delta} vs prior event`}</small></div>; }
function EmptyState({ message }: { message: string }) { return <p className="emptyState">{message}</p>; }
function BarList({ values }: { values: Array<{ label: string; value: number }> }) { const max = Math.max(1, ...values.map((item) => item.value)); return <div className="barList">{values.map((item) => <div key={item.label}><span>{item.label}</span><i><b style={{ width: `${(item.value / max) * 100}%` }} /></i><strong>{item.value}</strong></div>)}</div>; }
function ThreatTags({ item, emptyLabel }: { item: DashboardVulnerabilityRow; emptyLabel?: string }) { const present = item.kev || item.knownExploited || item.zeroDay; return <span className="tags">{item.knownExploited && <b>Exploited</b>}{item.kev && <b>KEV</b>}{item.zeroDay && <b>Zero-Day</b>}{!present && emptyLabel && <small className="muted">{emptyLabel}</small>}</span>; }

function ActivityChart({ values }: { values: DashboardResponse["vulnerabilityActivity"] }) {
  const max = Math.max(1, ...values.map((item) => item.critical + item.high + item.medium + item.low));
  return <div className="activityChart" role="img" aria-label="Monthly vulnerability disclosures split by critical, high, medium, and low severity">
    <ChartLegend values={[["Critical", "critical"], ["High", "high"], ["Medium", "medium"], ["Low", "low"]]} />
    <div className="activityPlot">{values.map((item) => {
      const total = item.critical + item.high + item.medium + item.low;
      return <div className="activityColumn" key={item.bucket} title={`${item.label}: ${total} vulnerabilities — ${item.critical} critical, ${item.high} high, ${item.medium} medium, ${item.low} low`}><strong>{total}</strong><div className="activityBar" style={{ height: `${Math.max(4, (total / max) * 100)}%` }}><i className="critical" style={{ flex: item.critical }} /><i className="high" style={{ flex: item.high }} /><i className="medium" style={{ flex: item.medium }} /><i className="low" style={{ flex: item.low }} /></div><small>{item.label}</small></div>;
    })}</div>
  </div>;
}

function ThreatActivityChart({ values }: { values: DashboardResponse["threatSignalActivity"] }) {
  const max = Math.max(1, ...values.flatMap((item) => [item.knownExploited, item.kev, item.zeroDay, item.highEpss]));
  return <div className="threatActivityChart" role="img" aria-label="Monthly counts of known exploited, CISA KEV, zero-day, and high EPSS vulnerabilities">
    <ChartLegend values={[["Known exploited", "exploited"], ["CISA KEV", "kev"], ["Zero-day", "zeroDay"], ["High EPSS", "highEpss"]]} />
    <div className="threatPlot">{values.map((item) => <div className="threatColumn" key={item.bucket} title={`${item.label}: ${item.knownExploited} known exploited, ${item.kev} KEV, ${item.zeroDay} zero-day, ${item.highEpss} high EPSS`}><div><i className="exploited" style={{ height: `${Math.max(3, item.knownExploited / max * 100)}%` }} /><i className="kev" style={{ height: `${Math.max(3, item.kev / max * 100)}%` }} /><i className="zeroDay" style={{ height: `${Math.max(3, item.zeroDay / max * 100)}%` }} /><i className="highEpss" style={{ height: `${Math.max(3, item.highEpss / max * 100)}%` }} /></div><small>{item.label}</small></div>)}</div>
  </div>;
}

function ChartLegend({ values }: { values: Array<[string, string]> }) { return <div className="chartLegend" aria-hidden="true">{values.map(([label, className]) => <span key={label}><i className={className} />{label}</span>)}</div>; }

function VendorThreatChart({ values, vendorPathPrefix }: { values: DashboardResponse["vendorThreatSeries"]; vendorPathPrefix: string }) {
  if (!values.length) return <EmptyState message="No vendor threat signals match the active filters." />;
  return <div className="vendorThreatChart"><div className="vendorThreatHead"><span>Vendor</span><span>Exploited</span><span>KEV</span><span>Zero-day</span><span>High EPSS</span></div>{values.map((item) => <div className="vendorThreatRow" key={item.label}><span><a href={`${vendorPathPrefix}${vendorIdFromLabel(item.label)}`}><strong>{item.label}</strong></a><small>{item.total} observed CVEs</small></span><b className={item.knownExploited ? "active" : ""}>{item.knownExploited}</b><b className={item.kev ? "active" : ""}>{item.kev}</b><b className={item.zeroDay ? "active" : ""}>{item.zeroDay}</b><b className={item.highEpss ? "predictive" : ""}>{item.highEpss}</b></div>)}</div>;
}

function CweChart({ values }: { values: DashboardResponse["cweAnalytics"]["series"] }) {
  if (!values.length) return <EmptyState message="No canonical CWE observations are available for this filtered set." />;
  const max = Math.max(1, ...values.map((item) => item.value));
  return <div className="cweChart">{values.map((item) => <div key={item.label}><span><strong>{item.label}</strong><small>{item.critical} critical · {item.exploited} exploited</small></span><i><b style={{ width: `${item.value / max * 100}%` }} /></i><em>{item.value}</em></div>)}</div>;
}

function FilterBar({ filters, setFilter }: { filters: Record<string, string>; setFilter: (key: string, value: string) => void }) {
  const vendors = ["microsoft", "cisco", "adobe", "fortinet", "palo-alto", "ivanti", "vmware-broadcom", "citrix", "chrome", "mozilla", "apple", "oracle", "atlassian", "sap"];
  return <div className="filters">
    <select aria-label="Vendor" value={filters.vendor ?? ""} onChange={(event) => setFilter("vendor", event.target.value)}><option value="">All vendors</option>{vendors.map((vendor) => <option key={vendor} value={vendor}>{titleCase(vendor)}</option>)}</select>
    <input aria-label="Product" placeholder="Product" defaultValue={filters.product ?? ""} onBlur={(event) => setFilter("product", event.target.value)} />
    <select aria-label="Severity" value={filters.severity ?? ""} onChange={(event) => setFilter("severity", event.target.value)}><option value="">All severities</option>{["critical", "high", "medium", "low"].map((value) => <option key={value} value={value}>{titleCase(value)}</option>)}</select>
    <select aria-label="Intelligence priority" value={filters.priority ?? ""} onChange={(event) => setFilter("priority", event.target.value)}><option value="">All priorities</option><option value="P1">P1 — Active Threat</option><option value="P2">P2 — Elevated</option><option value="P3">P3 — Monitored</option></select>
    <select aria-label="Known exploited" value={filters.exploited ?? ""} onChange={(event) => setFilter("exploited", event.target.value)}><option value="">Any exploitation state</option><option value="true">Known exploited</option><option value="false">Not known exploited</option></select>
    <select aria-label="CISA KEV" value={filters.kev ?? ""} onChange={(event) => setFilter("kev", event.target.value)}><option value="">Any KEV state</option><option value="true">In CISA KEV</option><option value="false">Not in CISA KEV</option></select>
    <select aria-label="Zero-day" value={filters.zeroDay ?? ""} onChange={(event) => setFilter("zeroDay", event.target.value)}><option value="">Any zero-day state</option><option value="true">Confirmed zero-day</option><option value="false">Not confirmed</option></select>
    <select aria-label="EPSS percentile" value={filters.epssPercentileMin ?? ""} onChange={(event) => setFilter("epssPercentileMin", event.target.value)}><option value="">Any EPSS percentile</option><option value="0.7">70th percentile+</option><option value="0.9">90th percentile+</option><option value="0.95">95th percentile+</option></select>
    <input aria-label="Published from" title="Published from" type="date" defaultValue={filters.publishedFrom ?? ""} onBlur={(event) => setFilter("publishedFrom", event.target.value)} />
    <select aria-label="Sort vulnerabilities" value={filters.sort ?? ""} onChange={(event) => setFilter("sort", event.target.value)}><option value="">Intelligence priority</option><option value="epss">EPSS percentile</option><option value="cvss">CVSS</option><option value="modified">Last modified</option><option value="published">Publication date</option></select>
    <details><summary>More filters</summary><div className="moreFilters">
      <label>Minimum CVSS<input type="number" min="0" max="10" step="0.1" defaultValue={filters.cvssMin ?? ""} onBlur={(event) => setFilter("cvssMin", event.target.value)} /></label>
      <label>Maximum CVSS<input type="number" min="0" max="10" step="0.1" defaultValue={filters.cvssMax ?? ""} onBlur={(event) => setFilter("cvssMax", event.target.value)} /></label>
      <label>Minimum EPSS score<input type="number" min="0" max="1" step="0.01" defaultValue={filters.epssMin ?? ""} onBlur={(event) => setFilter("epssMin", event.target.value)} /></label>
      <label>Published through<input type="date" defaultValue={filters.publishedTo ?? ""} onBlur={(event) => setFilter("publishedTo", event.target.value)} /></label>
      <label>Modified from<input type="date" defaultValue={filters.modifiedFrom ?? ""} onBlur={(event) => setFilter("modifiedFrom", event.target.value)} /></label>
      <label>Modified through<input type="date" defaultValue={filters.modifiedTo ?? ""} onBlur={(event) => setFilter("modifiedTo", event.target.value)} /></label>
      <label>Patch availability<select value={filters.patchAvailable ?? ""} onChange={(event) => setFilter("patchAvailable", event.target.value)}><option value="">Any</option><option value="true">Available</option><option value="false">Not stated</option></select></label>
      <label>Mitigation<select value={filters.mitigationAvailable ?? ""} onChange={(event) => setFilter("mitigationAvailable", event.target.value)}><option value="">Any</option><option value="true">Available</option><option value="false">Not stated</option></select></label>
      <label>Workaround<select value={filters.workaroundAvailable ?? ""} onChange={(event) => setFilter("workaroundAvailable", event.target.value)}><option value="">Any</option><option value="true">Available</option><option value="false">Not stated</option></select></label>
    </div></details>
  </div>;
}

function clearFilters(load: (search?: string) => Promise<void>) { window.history.pushState({}, "", `${window.location.pathname}${window.location.hash}`); void load(""); }
async function copyCurrentView(setStatus: (value: string) => void) { try { await navigator.clipboard.writeText(window.location.href); setStatus("Copied"); window.setTimeout(() => setStatus("Copy view URL"), 1800); } catch { setStatus("Copy unavailable"); } }
function vendorIdFromLabel(label: string) { const normalized = label.toLowerCase(); if (normalized.includes("palo alto")) return "palo-alto"; if (normalized.includes("vmware") || normalized.includes("broadcom")) return "vmware-broadcom"; if (normalized.includes("google chrome")) return "chrome"; return normalized.replace(/\s*\/\s*/g, "-").replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, ""); }
function changeLabel(value: string) { const labels: Record<string, string> = { EXPLOITATION_STATUS_CHANGED: "Exploitation status changed", KEV_ADDED: "CISA KEV added", KEV_REMOVED: "CISA KEV removed", KEV_DEADLINE_CHANGED: "KEV deadline changed", ZERO_DAY_STATUS_CHANGED: "Zero-day status changed", SEVERITY_CHANGED: "Severity changed", CVSS_CHANGED: "CVSS changed", ADVISORY_REVISED: "Advisory revised", SOURCE_MODIFIED: "Source advisory modified", FIXED_VERSION_CHANGED: "Fixed version changed", WORKAROUND_ADDED: "Workaround added", MITIGATION_ADDED: "Mitigation added", REMEDIATION_CHANGED: "Remediation changed", NEW_CVE: "New vulnerability", NEW_ADVISORY: "New advisory" }; return labels[value] ?? titleCase(value); }
function changeCategory(value: string) { if (["EXPLOITATION_STATUS_CHANGED", "KEV_ADDED", "KEV_REMOVED", "ZERO_DAY_STATUS_CHANGED"].includes(value)) return "threatChange"; if (["SEVERITY_CHANGED", "CVSS_CHANGED"].includes(value)) return "assessmentChange"; if (["REMEDIATION_CHANGED", "FIXED_VERSION_CHANGED", "MITIGATION_ADDED", "WORKAROUND_ADDED"].includes(value)) return "remediationChange"; return "advisoryChange"; }
function changeWeight(value: string) { const category = changeCategory(value); return category === "threatChange" ? 4 : category === "assessmentChange" ? 3 : category === "advisoryChange" ? 2 : 1; }
function formatDate(value: string) { return new Intl.DateTimeFormat("en", { month: "short", day: "numeric", year: "numeric", timeZone: "UTC" }).format(new Date(value)); }
function formatDateTime(value: string) { return new Intl.DateTimeFormat("en", { month: "short", day: "numeric", hour: "numeric", minute: "2-digit", timeZone: "UTC" }).format(new Date(value)); }
function timeAgo(value: string) { const seconds = Math.max(0, Math.round((Date.now() - new Date(value).getTime()) / 1000)); if (seconds < 60) return `${seconds}s ago`; if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`; if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`; return `${Math.floor(seconds / 86400)}d ago`; }
function titleCase(value: string) { return value.replaceAll("_", " ").replaceAll("-", " ").replace(/\b\w/g, (letter) => letter.toUpperCase()); }
function ordinalPercentile(fraction: number) { const value = Math.round(fraction * 100); const suffix = value % 10 === 1 && value % 100 !== 11 ? "st" : value % 10 === 2 && value % 100 !== 12 ? "nd" : value % 10 === 3 && value % 100 !== 13 ? "rd" : "th"; return `${value}${suffix}`; }
