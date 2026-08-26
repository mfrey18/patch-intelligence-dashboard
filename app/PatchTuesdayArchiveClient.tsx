"use client";

import { useEffect, useState } from "react";
import type { DashboardAnalyticsResponse, PatchTuesdayReleaseEvent } from "../lib/api/contracts";

export function PatchTuesdayArchiveClient({ apiBaseUrl, backHref = "/" }: { apiBaseUrl: string; backHref?: string }) {
  const [events, setEvents] = useState<PatchTuesdayReleaseEvent[]>([]);
  const [status, setStatus] = useState<"loading" | "ready" | "error">("loading");
  useEffect(() => {
    const controller = new AbortController();
    fetch(`${apiBaseUrl}/api/dashboard/analytics/patch-tuesday`, { headers: { accept: "application/json" }, signal: controller.signal })
      .then(async (response) => { if (!response.ok) throw new Error(String(response.status)); const body = await response.json() as DashboardAnalyticsResponse; setEvents(body.releaseEvents ?? []); setStatus("ready"); })
      .catch((error: unknown) => { if ((error as { name?: string }).name !== "AbortError") setStatus("error"); });
    return () => controller.abort();
  }, [apiBaseUrl]);
  return <main className="detailShell operationalShell">
    <header className="detailTop"><a className="brand" href={backHref}><span className="brandMark">VI</span><span><strong>Vulnerability Intelligence</strong><small>Microsoft release-event reconciliation</small></span></a><a className="backLink" href={backHref}>← Dashboard</a></header>
    <section className="detailHero"><div><p className="eyebrow">Release-event intelligence</p><h1>Patch Tuesday archive</h1><p>Microsoft’s authoritative reported total remains distinct from CVEs successfully linked to advisory assertions in D1. Severity, exploitation, KEV, zero-day, and product metrics use linked CVEs only.</p></div></section>
    {status === "loading" && <p className="notice">Loading independently cached Patch Tuesday analytics…</p>}
    {status === "error" && <p className="notice">Patch Tuesday analytics are temporarily unavailable.</p>}
    {status === "ready" && !events.length && <p className="emptyState">No Microsoft Patch Tuesday release events have been validated.</p>}
    <section className="releaseArchive">{events.map((event) => <article className="panel" key={event.id}><div className="panelHead"><div><p className="eyebrow">{event.eventDate} · {label(event.reconciliationStatus)}</p><h2>{event.label}</h2></div>{event.totalSourceUrl && <a href={event.totalSourceUrl} target="_blank" rel="noreferrer">Microsoft source ↗</a>}</div><div className="releaseReconciliation"><Stat label="Microsoft reported" value={event.totalBasis === "vendor_reported" ? event.total : null} /><Stat label="Linked in D1" value={event.linkedTotal} /><Stat label="Coverage" value={event.linkCoveragePercent == null ? null : `${event.linkCoveragePercent}%`} /><Stat label="Critical" value={event.critical} /><Stat label="High" value={event.high} /><Stat label="Known exploited" value={event.knownExploited} /><Stat label="Zero-days" value={event.zeroDay} /><Stat label="CISA KEV" value={event.kev} /></div>{event.comparison && <p className="eventProvenance">Versus {event.comparison.label}: reported {signed(event.comparison.totalDelta)} · linked {signed(event.comparison.linkedTotalDelta)} · Critical {signed(event.comparison.criticalDelta)} · High {signed(event.comparison.highDelta)} · exploited {signed(event.comparison.knownExploitedDelta)}.</p>}<div className="archiveProducts">{event.productFamilies.map((product) => <span key={product.label}><strong>{product.value}</strong>{product.label}</span>)}</div></article>)}</section>
  </main>;
}

function Stat({ label: name, value }: { label: string; value: number | string | null }) { return <div><span>{name}</span><strong>{value ?? "Not reported"}</strong></div>; }
function signed(value: number) { return `${value > 0 ? "+" : ""}${value}`; }
function label(value: string) { return value === "matched" ? "Reported and linked totals match" : value === "partial" ? "Partial D1 linkage" : value === "overlinked" ? "Linked count exceeds reported total" : "Microsoft total not captured"; }
