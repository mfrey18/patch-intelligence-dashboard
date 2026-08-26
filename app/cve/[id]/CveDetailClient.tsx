"use client";

import { useEffect, useState } from "react";
import type { CveDetailResponse } from "../../../lib/api/contracts";

export function CveDetailClient({ cveId, apiBaseUrl = "", backHref = "/" }: { cveId: string; apiBaseUrl?: string; backHref?: string }) {
  const [detail, setDetail] = useState<CveDetailResponse | null>(null);
  const [status, setStatus] = useState<"loading" | "ready" | "missing" | "error">("loading");

  useEffect(() => {
    const controller = new AbortController();
    fetch(`${apiBaseUrl}/api/cves/${encodeURIComponent(cveId)}`, { headers: { accept: "application/json" }, signal: controller.signal })
      .then(async (response) => {
        if (response.status === 404) { setStatus("missing"); return; }
        if (!response.ok) throw new Error(`CVE detail returned ${response.status}`);
        setDetail(await response.json() as CveDetailResponse);
        setStatus("ready");
      })
      .catch((error: unknown) => { if ((error as { name?: string }).name !== "AbortError") setStatus("error"); });
    return () => controller.abort();
  }, [apiBaseUrl, cveId]);

  if (status === "loading") return <DetailState backHref={backHref} title="Loading intelligence" message={`Retrieving the latest validated record for ${cveId}.`} />;
  if (status === "missing") return <DetailState backHref={backHref} title="CVE not found" message={`${cveId} is not in the rolling six-month dataset.`} />;
  if (status === "error" || !detail) return <DetailState backHref={backHref} title="Intelligence unavailable" message="The last-known-good detail could not be loaded." />;

  const description = detail.canonical.description ?? "A canonical description has not been ingested; authoritative vendor assertions are shown below.";
  const snapshotSeverity = highestSeverity(detail);
  const snapshotCvss = detail.canonical.cvss ?? highestVendorCvss(detail);

  return <main className="detailShell">
    <header className="detailTop"><a className="brand" href={backHref}><span className="brandMark">VI</span><span><strong>Vulnerability Intelligence</strong><small>Cross-vendor vulnerability and threat intelligence</small></span></a><a className="backLink" href={backHref}>← Dashboard</a></header>
    <section className="detailHero">
      <div><p className="eyebrow">Vulnerability intelligence record</p><h1>{detail.canonical.cveId}</h1><p>{description}</p></div>
      <div className="priorityCard"><span className={`badge ${detail.priority.level.toLowerCase()}`}>{detail.priority.level}</span><div><strong>{priorityLabel(detail.priority.level)}</strong><p>{detail.priority.reasons.join(" · ")}</p></div></div>
    </section>

    <section className="detailGrid">
      <article className="panel detailPanel"><SectionTitle eyebrow="Canonical vulnerability data" title="Vulnerability Identity" /><dl className="factGrid"><Fact label="CVSS" value={number(detail.canonical.cvss)} /><Fact label="Vector" value={detail.canonical.cvssVector} /><Fact label="CWE" value={detail.canonical.cwe} /><Fact label="Published" value={date(detail.canonical.publishedAt)} /><Fact label="Modified" value={date(detail.canonical.modifiedAt)} /><Fact label="Canonical source" value={detail.canonical.sourceUrl ? "Available" : "Not ingested"} /></dl></article>
      <article className="panel detailPanel"><SectionTitle eyebrow="Current validated assessment" title="Intelligence Snapshot" /><div className="snapshotGrid"><Snapshot label="Priority" value={`${detail.priority.level} — ${priorityLabel(detail.priority.level)}`} tone={detail.priority.level === "P1" ? "threat" : ""} /><Snapshot label="Severity" value={snapshotSeverity} /><Snapshot label="CVSS" value={number(snapshotCvss) ?? "Not stated"} /><Snapshot label="EPSS" value={detail.epss.current ? `${ordinalPercentile(detail.epss.current.percentile)} · ${(detail.epss.current.score * 100).toFixed(2)}%` : "No current observation"} /><Snapshot label="Known exploitation" value={detail.exploitation.knownExploited ? "Confirmed" : "Not confirmed"} tone={detail.exploitation.knownExploited ? "threat" : ""} /><Snapshot label="CISA KEV" value={detail.kev?.active ? "Active entry" : "Not listed"} tone={detail.kev?.active ? "threat" : ""} /><Snapshot label="Zero-day" value={detail.exploitation.zeroDay ? "Confirmed" : "Not confirmed"} tone={detail.exploitation.zeroDay ? "threat" : ""} /><Snapshot label="Evidence sources" value={`${detail.sourceLinks.length} authoritative link${detail.sourceLinks.length === 1 ? "" : "s"}`} /></div></article>
    </section>

    <section className="detailGrid">
      <article className="panel detailPanel"><SectionTitle eyebrow="Authoritative threat assertions" title="Exploitation Evidence" />{detail.exploitation.evidence.length ? <div className="evidenceList">{detail.exploitation.evidence.map((item, index) => <article key={`${item.type}-${item.url}-${index}`}><i /><div><strong>{titleCase(item.type)} · {titleCase(item.status)}</strong><small>{item.source} ({item.sourceId}){item.date ? ` · evidence ${date(item.date)}` : ""} · observed {dateTime(item.observedAt)}</small><p>{item.summary ?? "Authoritative source assertion."}</p><a href={item.url} target="_blank" rel="noreferrer">Evidence source ↗</a></div></article>)}</div> : <Empty message="No authoritative exploitation evidence is present." />}{detail.kev && <div className="kevEvidence"><strong>CISA KEV · {detail.kev.active ? "Active" : "Removed"}</strong><small>Added {date(detail.kev.dateAdded)}{detail.kev.dueDate ? ` · due ${date(detail.kev.dueDate)}` : ""} · observed {dateTime(detail.kev.observedAt)}</small>{detail.kev.requiredAction && <p>{detail.kev.requiredAction}</p>}<a href={detail.kev.sourceUrl} target="_blank" rel="noreferrer">CISA evidence source ↗</a></div>}</article>
      <article className="panel detailPanel"><SectionTitle eyebrow="FIRST predictive enrichment" title="EPSS Trend" />{detail.epss.history.length ? <><EpssGraph history={detail.epss.history} /><small className="panelNote">FIRST EPSS · current dataset observed {dateTime(detail.epss.history.at(-1)!.observedAt)} · predictive enrichment, not exploitation evidence</small></> : <Empty message="No EPSS observations are available for this CVE." />}</article>
    </section>

    <section className="panel detailPanel fullPanel"><SectionTitle eyebrow="Vendor-specific assertions" title="Vendor Advisories & Affected Products" />
      <div className="assertionList">{detail.advisories.map((advisory) => <article key={advisory.id}><div><span className={`severity ${advisory.normalizedSeverity}`}>{titleCase(advisory.normalizedSeverity)}</span><strong>{advisory.vendor} · {advisory.vendorAdvisoryId}</strong><p>{advisory.title}</p><small>{advisory.sourceId} · observed {dateTime(advisory.observedAt)}</small></div><dl><Fact label="Vendor CVSS" value={number(advisory.vendorCvss)} /><Fact label="Modified" value={date(advisory.modifiedAt)} /></dl><a href={advisory.sourceUrl} target="_blank" rel="noreferrer">Open advisory ↗</a></article>)}</div>
      {detail.affectedProducts.length ? <div className="tableWrap"><table><thead><tr><th>Vendor</th><th>Product</th><th>Status</th><th>Affected version</th><th>Fixed version</th><th>Evidence</th></tr></thead><tbody>{detail.affectedProducts.map((product, index) => <tr key={`${product.vendor}-${product.product}-${product.affectedVersion}-${index}`}><td>{product.vendor}</td><td>{product.product}</td><td>{titleCase(product.status)}</td><td>{product.affectedVersion ?? "Not specified"}</td><td>{product.fixedVersion ?? "Not specified"}</td><td><a href={product.sourceUrl} target="_blank" rel="noreferrer">{product.sourceId} · {date(product.observedAt)} ↗</a></td></tr>)}</tbody></table></div> : <Empty message="No authoritative affected-product assertions were supplied." />}
    </section>

    <section className="panel detailPanel fullPanel"><SectionTitle eyebrow="Independent authoritative records linked by CVE identity" title="Authoritative Source Correlation" />{detail.sourceLinks.length ? <div className="correlationGrid">{detail.sourceLinks.map((source) => <a href={source.url} target="_blank" rel="noreferrer" key={source.url}><strong>{source.label}</strong><small>Open authoritative source ↗</small></a>)}</div> : <Empty message="No authoritative source links are available." />}<small className="panelNote">Vendor assertions, exploitation evidence, KEV, and EPSS remain independent. Their source identifiers and observed timestamps are shown with each assertion above.</small></section>

    <section className="panel detailPanel fullPanel"><SectionTitle eyebrow="Meaningful assessment and advisory history" title="Intelligence Timeline" />{detail.timeline.length ? <ol className="timeline">{detail.timeline.map((item, index) => <li className={timelineCategory(item.changeType)} key={`${item.observedAt}-${item.changeType}-${index}`}><time>{dateTime(item.observedAt)}</time><strong>{titleCase(item.changeType)}</strong><p>{item.summary}</p></li>)}</ol> : <Empty message="No revision events have been observed yet." />}</section>

    <section className="panel detailPanel fullPanel"><SectionTitle eyebrow="Component-level advisory history" title="Advisory Revision Comparison" />{detail.advisoryRevisions.length ? <div className="revisionList">{detail.advisoryRevisions.map((revision, index) => <article key={`${revision.advisoryId}-${revision.observedAt}-${index}`}><div><strong>{revision.vendor} · {revision.vendorAdvisoryId}</strong><small>{revision.sourceId} · observed {dateTime(revision.observedAt)}{revision.sourceUpdatedAt ? ` · source modified ${dateTime(revision.sourceUpdatedAt)}` : ""}</small></div><span>{revision.changeTypes.length ? revision.changeTypes.map(titleCase).join(" · ") : "Initial observed revision"}</span><dl><RevisionFlag label="Source content" changed={revision.sourceContentChanged} /><RevisionFlag label="Affected products" changed={revision.affectedProductsChanged} /><RevisionFlag label="Remediation" changed={revision.remediationChanged} /></dl><a href={revision.sourceUrl} target="_blank" rel="noreferrer">Source ↗</a></article>)}</div> : <Empty message="No advisory revision snapshots are available." />}</section>

    <section className="panel detailPanel fullPanel"><SectionTitle eyebrow="Supporting vendor context" title="Vendor Remediation Information" />{detail.remediations.length ? <div className="remediationList">{detail.remediations.map((item, index) => <article key={`${item.vendor}-${item.kind}-${index}`}><span>{titleCase(item.kind)}</span><strong>{item.vendor}{item.fixedVersion ? ` · Fixed in ${item.fixedVersion}` : ""}</strong><p>{item.action ?? "Refer to the authoritative source for action details."}</p><small>{item.patchAvailable === true ? "Patch explicitly available" : item.patchAvailable === false ? "Patch explicitly unavailable" : "Patch availability not stated"}{item.rebootRequired === true ? " · Reboot required" : ""} · {item.sourceId} · observed {dateTime(item.observedAt)}</small><a href={item.sourceUrl} target="_blank" rel="noreferrer">Source ↗</a></article>)}</div> : <Empty message="No structured vendor remediation information is currently available." />}</section>
  </main>;
}

function DetailState({ title, message, backHref }: { title: string; message: string; backHref: string }) { return <main className="detailState"><a href={backHref}>← Vulnerability Intelligence</a><h1>{title}</h1><p>{message}</p></main>; }
function SectionTitle({ eyebrow, title }: { eyebrow: string; title: string }) { return <div className="panelHead"><div><p className="eyebrow">{eyebrow}</p><h2>{title}</h2></div></div>; }
function Fact({ label, value }: { label: string; value: string | null }) { return <div><dt>{label}</dt><dd>{value ?? "Not stated"}</dd></div>; }
function Snapshot({ label, value, tone = "" }: { label: string; value: string; tone?: string }) { return <div className={tone}><span>{label}</span><strong>{value}</strong></div>; }
function RevisionFlag({ label, changed }: { label: string; changed: boolean | null }) { return <div><dt>{label}</dt><dd>{changed == null ? "Baseline" : changed ? "Changed" : "Unchanged"}</dd></div>; }
function Empty({ message }: { message: string }) { return <p className="emptyState">{message}</p>; }
function EpssGraph({ history }: { history: CveDetailResponse["epss"]["history"] }) { const shown = history.slice(-60); const modelChanges = shown.filter((item, index) => index > 0 && item.modelVersion !== shown[index - 1].modelVersion).length; return <div className="epssBlock"><div className="epssGraph" role="img" aria-label={`EPSS score history over ${shown.length} observations`}>{shown.map((item) => <i key={item.scoreDate} title={`${item.scoreDate}: ${(item.score * 100).toFixed(2)}%`}><b style={{ height: `${Math.max(2, item.score * 100)}%` }} /></i>)}</div><div className="graphLegend"><span>{shown[0]?.scoreDate}</span><span>EPSS probability · {modelChanges} model change{modelChanges === 1 ? "" : "s"}</span><span>{shown.at(-1)?.scoreDate}</span></div></div>; }
function highestSeverity(detail: CveDetailResponse) { const order = ["critical", "high", "medium", "low", "unknown"]; const value = [...detail.advisories].sort((a, b) => order.indexOf(a.normalizedSeverity) - order.indexOf(b.normalizedSeverity))[0]?.normalizedSeverity; return value ? titleCase(value) : "Not stated"; }
function highestVendorCvss(detail: CveDetailResponse) { return Math.max(...detail.advisories.map((item) => item.vendorCvss ?? -1), -1) >= 0 ? Math.max(...detail.advisories.map((item) => item.vendorCvss ?? -1)) : null; }
function number(value: number | null) { return value == null ? null : value.toFixed(1); }
function date(value: string | null) { return value ? new Intl.DateTimeFormat("en", { dateStyle: "medium", timeZone: "UTC" }).format(new Date(value)) : null; }
function dateTime(value: string) { return new Intl.DateTimeFormat("en", { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" }).format(new Date(value)); }
function titleCase(value: string) { return value.replaceAll("_", " ").replaceAll("-", " ").replace(/\b\w/g, (letter) => letter.toUpperCase()); }
function priorityLabel(value: CveDetailResponse["priority"]["level"]) { return value === "P1" ? "Active Threat" : value === "P2" ? "Elevated Intelligence" : "Monitored"; }
function ordinalPercentile(fraction: number) { const value = Math.round(fraction * 100); return `${value}${value % 10 === 1 && value % 100 !== 11 ? "st" : value % 10 === 2 && value % 100 !== 12 ? "nd" : value % 10 === 3 && value % 100 !== 13 ? "rd" : "th"} percentile`; }
function timelineCategory(value: string) { return ["EXPLOITATION_STATUS_CHANGED", "KEV_ADDED", "KEV_REMOVED", "ZERO_DAY_STATUS_CHANGED"].includes(value) ? "threat" : ["SEVERITY_CHANGED", "CVSS_CHANGED"].includes(value) ? "assessment" : ["REMEDIATION_CHANGED", "FIXED_VERSION_CHANGED", "MITIGATION_ADDED", "WORKAROUND_ADDED"].includes(value) ? "remediation" : "advisory"; }
