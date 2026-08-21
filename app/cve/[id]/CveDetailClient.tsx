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
  if (status === "missing") return <DetailState backHref={backHref} title="CVE not found" message={`${cveId} is not in the rolling dataset.`} />;
  if (status === "error" || !detail) return <DetailState backHref={backHref} title="Intelligence unavailable" message="The last-known-good detail could not be loaded." />;

  const description = detail.canonical.description ?? "A canonical description has not been ingested; authoritative vendor assertions are shown below.";
  return <main className="detailShell">
    <header className="detailTop"><a className="brand" href={backHref}><span className="brandMark">PI</span><span><strong>Patch Intelligence</strong><small>Back to operational dashboard</small></span></a><a className="backLink" href={backHref}>← Dashboard</a></header>
    <section className="detailHero">
      <div><p className="eyebrow">Vulnerability intelligence</p><h1>{detail.canonical.cveId}</h1><p>{description}</p></div>
      <div className="priorityCard"><span className={`badge ${detail.priority.level.toLowerCase()}`}>{detail.priority.level}</span><div><strong>{priorityLabel(detail.priority.level)}</strong><p>{detail.priority.reasons.join(" · ")}</p></div></div>
    </section>

    <section className="detailGrid">
      <article className="panel detailPanel"><SectionTitle eyebrow="Canonical vulnerability data" title="Vulnerability identity" /><dl className="factGrid"><Fact label="CVSS" value={number(detail.canonical.cvss)} /><Fact label="Vector" value={detail.canonical.cvssVector} /><Fact label="CWE" value={detail.canonical.cwe} /><Fact label="Published" value={date(detail.canonical.publishedAt)} /><Fact label="Modified" value={date(detail.canonical.modifiedAt)} /><Fact label="Canonical source" value={detail.canonical.sourceUrl ? "Available" : "Not ingested"} /></dl></article>
      <article className="panel detailPanel"><SectionTitle eyebrow="Independent intelligence signals" title="Exploitation & likelihood" /><div className="signalGrid"><Signal active={detail.exploitation.knownExploited} label="Known exploited" source="Authoritative evidence only" /><Signal active={Boolean(detail.kev?.active)} label="CISA KEV" source={detail.kev?.dueDate ? `Due ${date(detail.kev.dueDate)}` : "Not currently listed"} /><Signal active={detail.exploitation.zeroDay} label="Zero-day" source="Authoritative evidence only" /><Signal active={detail.epss.current !== null} label={detail.epss.current ? `${Math.round(detail.epss.current.percentile * 100)}th percentile` : "No current EPSS"} source={detail.epss.current ? `${(detail.epss.current.score * 100).toFixed(2)}% · ${detail.epss.current.scoreDate}` : "Predictive score only"} /></div></article>
    </section>

    <section className="panel detailPanel fullPanel"><SectionTitle eyebrow="Vendor-specific assertions" title="Advisories, products, and fixed releases" />
      <div className="assertionList">{detail.advisories.map((advisory) => <article key={advisory.id}><div><span className={`severity ${advisory.normalizedSeverity}`}>{titleCase(advisory.normalizedSeverity)}</span><strong>{advisory.vendor} · {advisory.vendorAdvisoryId}</strong><p>{advisory.title}</p></div><dl><Fact label="Vendor CVSS" value={number(advisory.vendorCvss)} /><Fact label="Modified" value={date(advisory.modifiedAt)} /></dl><a href={advisory.sourceUrl} target="_blank" rel="noreferrer">Open advisory ↗</a></article>)}</div>
      {detail.affectedProducts.length ? <div className="tableWrap"><table><thead><tr><th>Vendor</th><th>Product</th><th>Status</th><th>Affected version</th><th>Fixed version</th></tr></thead><tbody>{detail.affectedProducts.map((product, index) => <tr key={`${product.vendor}-${product.product}-${product.affectedVersion}-${index}`}><td>{product.vendor}</td><td>{product.product}</td><td>{titleCase(product.status)}</td><td>{product.affectedVersion ?? "Not specified"}</td><td>{product.fixedVersion ?? "Not specified"}</td></tr>)}</tbody></table></div> : <Empty message="No authoritative affected-product assertions were supplied." />}
    </section>

    <section className="detailGrid">
      <article className="panel detailPanel"><SectionTitle eyebrow="First-class remediation" title="Actions and workarounds" />{detail.remediations.length ? <div className="remediationList">{detail.remediations.map((item, index) => <article key={`${item.vendor}-${item.kind}-${index}`}><span>{titleCase(item.kind)}</span><strong>{item.vendor}{item.fixedVersion ? ` · Fixed in ${item.fixedVersion}` : ""}</strong><p>{item.action ?? "Refer to the authoritative source for action details."}</p><small>{item.patchAvailable === true ? "Patch explicitly available" : item.patchAvailable === false ? "Patch explicitly unavailable" : "Patch availability not stated"}{item.rebootRequired === true ? " · Reboot required" : ""}</small><a href={item.sourceUrl} target="_blank" rel="noreferrer">Source ↗</a></article>)}</div> : <Empty message="No structured remediation is currently available." />}</article>
      <article className="panel detailPanel"><SectionTitle eyebrow="FIRST predictive enrichment" title="EPSS history" />{detail.epss.history.length ? <EpssGraph history={detail.epss.history} /> : <Empty message="No EPSS observations are available for this CVE." />}</article>
    </section>

    <section className="detailGrid">
      <article className="panel detailPanel"><SectionTitle eyebrow="Evidence with provenance" title="Exploitation evidence" />{detail.exploitation.evidence.length ? <div className="evidenceList">{detail.exploitation.evidence.map((item, index) => <article key={`${item.type}-${item.url}-${index}`}><i /><div><strong>{titleCase(item.type)} · {titleCase(item.status)}</strong><small>{item.source}{item.date ? ` · ${date(item.date)}` : ""}</small><p>{item.summary ?? "Authoritative source assertion."}</p><a href={item.url} target="_blank" rel="noreferrer">Evidence source ↗</a></div></article>)}</div> : <Empty message="No authoritative exploitation evidence is present." />}</article>
      <article className="panel detailPanel"><SectionTitle eyebrow="Meaningful change history" title="Timeline" />{detail.timeline.length ? <ol className="timeline">{detail.timeline.map((item, index) => <li key={`${item.observedAt}-${item.changeType}-${index}`}><time>{dateTime(item.observedAt)}</time><strong>{titleCase(item.changeType)}</strong><p>{item.summary}</p></li>)}</ol> : <Empty message="No revision events have been observed yet." />}</article>
    </section>
  </main>;
}

function DetailState({ title, message, backHref }: { title: string; message: string; backHref: string }) { return <main className="detailState"><a href={backHref}>← Patch Intelligence</a><h1>{title}</h1><p>{message}</p></main>; }
function SectionTitle({ eyebrow, title }: { eyebrow: string; title: string }) { return <div className="panelHead"><div><p className="eyebrow">{eyebrow}</p><h2>{title}</h2></div></div>; }
function Fact({ label, value }: { label: string; value: string | null }) { return <div><dt>{label}</dt><dd>{value ?? "Not stated"}</dd></div>; }
function Signal({ active, label, source }: { active: boolean; label: string; source: string }) { return <div className={active ? "active" : ""}><i /><strong>{label}</strong><small>{source}</small></div>; }
function Empty({ message }: { message: string }) { return <p className="emptyState">{message}</p>; }
function EpssGraph({ history }: { history: CveDetailResponse["epss"]["history"] }) { const shown = history.slice(-60); const modelChanges = shown.filter((item, index) => index > 0 && item.modelVersion !== shown[index - 1].modelVersion).length; return <div className="epssBlock"><div className="epssGraph" role="img" aria-label={`EPSS score history over ${shown.length} observations`} >{shown.map((item) => <i key={item.scoreDate} title={`${item.scoreDate}: ${(item.score * 100).toFixed(2)}%`}><b style={{ height: `${Math.max(2, item.score * 100)}%` }} /></i>)}</div><div className="graphLegend"><span>{shown[0]?.scoreDate}</span><span>EPSS probability · {modelChanges} model change{modelChanges === 1 ? "" : "s"}</span><span>{shown.at(-1)?.scoreDate}</span></div></div>; }
function number(value: number | null) { return value == null ? null : value.toFixed(1); }
function date(value: string | null) { return value ? new Intl.DateTimeFormat("en", { dateStyle: "medium", timeZone: "UTC" }).format(new Date(value)) : null; }
function dateTime(value: string) { return new Intl.DateTimeFormat("en", { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" }).format(new Date(value)); }
function titleCase(value: string) { return value.replaceAll("_", " ").replaceAll("-", " ").replace(/\b\w/g, (letter) => letter.toUpperCase()); }
function priorityLabel(value: CveDetailResponse["priority"]["level"]) { return value === "P1" ? "Immediate" : value === "P2" ? "Elevated" : "Routine"; }
