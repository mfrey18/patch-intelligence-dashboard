"use client";

import { useEffect, useMemo, useState } from "react";
import type { DashboardResponse } from "../lib/api/contracts";
import { isVendorId, vendorLabel } from "../lib/domain/routes";

export function VendorIntelligenceClient({ vendorId, apiBaseUrl = "", backHref = "/", cvePathPrefix = "/cve/" }: { vendorId: string; apiBaseUrl?: string; backHref?: string; cvePathPrefix?: string }) {
  const validVendor = isVendorId(vendorId) ? vendorId : null;
  const [data, setData] = useState<DashboardResponse | null>(null);
  const [status, setStatus] = useState<"loading" | "ready" | "invalid" | "error">(validVendor ? "loading" : "invalid");

  useEffect(() => {
    if (!validVendor) return;
    const controller = new AbortController();
    const params = new URLSearchParams(window.location.search);
    params.set("vendor", validVendor); params.set("limit", "100"); params.delete("cursor");
    fetch(`${apiBaseUrl}/api/dashboard?${params}`, { headers: { accept: "application/json" }, signal: controller.signal })
      .then(async (response) => { if (!response.ok) throw new Error(`Vendor intelligence returned ${response.status}`); setData(await response.json() as DashboardResponse); setStatus("ready"); })
      .catch((error: unknown) => { if ((error as { name?: string }).name !== "AbortError") setStatus("error"); });
    return () => controller.abort();
  }, [apiBaseUrl, validVendor]);

  const highEpss = useMemo(() => data?.vendorThreatSeries.find((item) => item.label === (validVendor ? vendorLabel(validVendor) : ""))?.highEpss ?? 0, [data, validVendor]);
  if (!validVendor || status === "invalid") return <VendorState backHref={backHref} title="Vendor not found" message="This vendor identifier is not in the authoritative ingestion allowlist." />;
  if (status === "loading") return <VendorState backHref={backHref} title="Loading vendor intelligence" message={`Retrieving the current observed intelligence for ${vendorLabel(validVendor)}.`} />;
  if (status === "error" || !data) return <VendorState backHref={backHref} title="Vendor intelligence unavailable" message="The filtered last-known-good view could not be loaded." />;

  const label = vendorLabel(validVendor);
  return <main className="detailShell vendorShell">
    <header className="detailTop"><a className="brand" href={backHref}><span className="brandMark">VI</span><span><strong>Vulnerability Intelligence</strong><small>Cross-vendor vulnerability and threat intelligence</small></span></a><a className="backLink" href={backHref}>← Dashboard</a></header>
    <section className="vendorHero"><div><p className="eyebrow">Observed vendor intelligence · rolling six months</p><h1>{label}</h1><p>Authoritative disclosed vulnerability and threat-signal counts. These observations are not a vendor security rating.</p></div><small>Refreshed {formatDateTime(data.generatedAt)}</small></section>
    <section className="vendorMetrics"><VendorMetric label="Vulnerabilities" value={data.metrics.total} /><VendorMetric label="Critical" value={data.metrics.critical} threat /><VendorMetric label="Known exploited" value={data.metrics.knownExploited} threat /><VendorMetric label="CISA KEV" value={data.metrics.kev} threat /><VendorMetric label="Zero-days" value={data.metrics.zeroDay} threat /><VendorMetric label="High EPSS" value={highEpss} predictive /></section>

    <section className="analyticsGrid">
      <article className="panel"><PanelTitle eyebrow="Current filtered set" title="Severity distribution" /><Bars values={data.severitySeries} /></article>
      <article className="panel"><PanelTitle eyebrow="Canonical product families where supplied" title="Affected product families" /><Bars values={data.productSeries} empty="No canonical product-family assertions are available." /></article>
    </section>
    <section className="analyticsGrid">
      <article className="panel"><PanelTitle eyebrow="Latest material observations" title="Recent intelligence changes" />{data.recentChanges.length ? data.recentChanges.slice(0, 8).map((change) => <a className="vendorChange" href={change.cveId ? `${cvePathPrefix}${encodeURIComponent(change.cveId)}` : "#vendor-vulnerabilities"} key={`${change.changeType}-${change.observedAt}-${change.cveId}`}><span><strong>{change.cveId ?? "Vendor advisory"}</strong><small>{humanize(change.changeType)} · {formatDateTime(change.observedAt)}</small></span><em>{change.summary}</em></a>) : <Empty message="No recent material changes match this vendor view." />}</article>
      <article className="panel"><PanelTitle eyebrow="Coverage is explicit" title="Weakness observations" /><p className="coverageCallout"><strong>{data.cweAnalytics.knownCoverage}</strong> of {data.cweAnalytics.total} matching CVEs include canonical CWE data.</p><Bars values={data.cweAnalytics.series.slice(0, 6)} empty="No canonical CWE observations are available." /></article>
    </section>

    <section className="panel tablePanel" id="vendor-vulnerabilities"><PanelTitle eyebrow={`${data.metrics.total} matching records`} title="Vendor vulnerability intelligence" /><div className="tableWrap"><table><thead><tr><th>Priority / CVE</th><th>Product</th><th>Severity</th><th>CVSS</th><th>EPSS</th><th>Threat signals</th><th>Published</th><th>Modified</th></tr></thead><tbody>{data.rows.map((item) => <tr key={item.cveId}><td><span className={`badge ${item.priority.level.toLowerCase()}`}>{item.priority.level}</span><a href={`${cvePathPrefix}${encodeURIComponent(item.cveId)}`}><strong>{item.cveId}</strong></a></td><td>{item.product ?? "Not specified"}</td><td><span className={`severity ${item.severity}`}>{humanize(item.severity)}</span></td><td>{item.cvss?.toFixed(1) ?? "—"}</td><td>{item.epssPercentile == null ? "—" : `${Math.round(item.epssPercentile * 100)}th percentile`}</td><td><span className="tags">{item.knownExploited && <b>Exploited</b>}{item.kev && <b>KEV</b>}{item.zeroDay && <b>Zero-day</b>}</span></td><td>{formatDate(item.publishedAt)}</td><td>{formatDate(item.modifiedAt)}</td></tr>)}</tbody></table></div>{data.nextCursor && <p className="panelNote">This bounded page shows the first 100 matching CVEs. Open the dashboard vendor filter to continue through cursor-paginated results.</p>}</section>
  </main>;
}

function VendorState({ backHref, title, message }: { backHref: string; title: string; message: string }) { return <main className="detailState"><a href={backHref}>← Vulnerability Intelligence</a><h1>{title}</h1><p>{message}</p></main>; }
function PanelTitle({ eyebrow, title }: { eyebrow: string; title: string }) { return <div className="panelHead"><div><p className="eyebrow">{eyebrow}</p><h2>{title}</h2></div></div>; }
function VendorMetric({ label, value, threat = false, predictive = false }: { label: string; value: number; threat?: boolean; predictive?: boolean }) { return <article><span>{label}</span><strong className={threat ? "threat" : predictive ? "predictive" : ""}>{value}</strong></article>; }
function Bars({ values, empty }: { values: Array<{ label: string; value: number }>; empty?: string }) { if (!values.length) return <Empty message={empty ?? "No matching observations."} />; const max = Math.max(1, ...values.map((item) => item.value)); return <div className="barList vendorBars">{values.map((item) => <div key={item.label}><span>{item.label}</span><i><b style={{ width: `${item.value / max * 100}%` }} /></i><strong>{item.value}</strong></div>)}</div>; }
function Empty({ message }: { message: string }) { return <p className="emptyState">{message}</p>; }
function humanize(value: string) { return value.replaceAll("_", " ").replaceAll("-", " ").replace(/\b\w/g, (letter) => letter.toUpperCase()); }
function formatDate(value: string | null) { return value ? new Intl.DateTimeFormat("en", { dateStyle: "medium", timeZone: "UTC" }).format(new Date(value)) : "—"; }
function formatDateTime(value: string) { return new Intl.DateTimeFormat("en", { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" }).format(new Date(value)); }
