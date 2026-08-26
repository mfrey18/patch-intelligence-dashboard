"use client";

import { useEffect, useState } from "react";
import type { DashboardResponse, SourceHealth } from "../lib/api/contracts";

export function SourceHealthClient({ apiBaseUrl, backHref = "/" }: { apiBaseUrl: string; backHref?: string }) {
  const [sources, setSources] = useState<SourceHealth[]>([]);
  const [status, setStatus] = useState<"loading" | "ready" | "error">("loading");
  useEffect(() => {
    const controller = new AbortController();
    fetch(`${apiBaseUrl}/api/dashboard?include=core&limit=1`, { headers: { accept: "application/json" }, signal: controller.signal })
      .then(async (response) => { if (!response.ok) throw new Error(String(response.status)); setSources(((await response.json()) as DashboardResponse).sourceHealth); setStatus("ready"); })
      .catch((error: unknown) => { if ((error as { name?: string }).name !== "AbortError") setStatus("error"); });
    return () => controller.abort();
  }, [apiBaseUrl]);
  return <main className="detailShell operationalShell"><header className="detailTop"><a className="brand" href={backHref}><span className="brandMark">VI</span><span><strong>Vulnerability Intelligence</strong><small>Authoritative source operations</small></span></a><a className="backLink" href={backHref}>← Dashboard</a></header><section className="detailHero"><div><p className="eyebrow">Public read-only operations</p><h1>Source health</h1><p>Freshness, result counts, continuation state, and lease visibility remain isolated per authoritative source. Private monitor details and credentials are never exposed here.</p></div></section>{status === "loading" && <p className="notice">Loading source health…</p>}{status === "error" && <p className="notice">Source health is temporarily unavailable.</p>}<section className="sourceAdminGrid">{sources.map((source) => <article className="panel" key={source.sourceId}><div className="panelHead"><div><p className="eyebrow">{source.sourceId}</p><h2>{source.name}</h2></div><span className={`sourceAdminState ${source.freshness !== "fresh" || source.result === "failed" ? "failed" : ""}`}>{source.freshness}</span></div><dl><Fact label="Latest result" value={source.result ?? "Not run"} /><Fact label="Last success" value={source.lastSuccess ? format(source.lastSuccess) : "Never"} /><Fact label="Last failure" value={source.lastFailure ? format(source.lastFailure) : "None"} /><Fact label="Duration" value={source.durationMs == null ? "—" : `${source.durationMs} ms`} /><Fact label="Discovered" value={source.discovered} /><Fact label="Inserted / changed" value={`${source.inserted} / ${source.changed}`} /><Fact label="Unchanged" value={source.unchanged} /><Fact label="Failed" value={source.failed} /></dl>{source.boundHit && <p className="eventProvenance">Free-plan batch bound reached; continuation is preserved.</p>}{source.checkpoint && <p className="eventProvenance">{source.checkpoint.status} checkpoint · {source.checkpoint.windowStart.slice(0, 10)} through {source.checkpoint.windowEnd.slice(0, 10)}</p>}{source.lease.active && <p className="eventProvenance">Lease active until {format(source.lease.expiresAt!)}</p>}{source.errorSummary && <p className="eventProvenance">{source.errorSummary}</p>}</article>)}</section></main>;
}

function Fact({ label, value }: { label: string; value: string | number }) { return <div><dt>{label}</dt><dd>{value}</dd></div>; }
function format(value: string) { return new Intl.DateTimeFormat("en", { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" }).format(new Date(value)); }
