import { useEffect, useMemo, useState } from "react";
import { DashboardClient } from "../app/DashboardClient";
import { CveDetailClient } from "../app/cve/[id]/CveDetailClient";
import { CveComparisonClient } from "../app/CveComparisonClient";
import { VendorIntelligenceClient } from "../app/VendorIntelligenceClient";
import { PatchTuesdayArchiveClient } from "../app/PatchTuesdayArchiveClient";
import { SourceHealthClient } from "../app/SourceHealthClient";
import { demoDashboard } from "../lib/demo-data";
import { isVendorId, parseComparisonCves, vendorLabel } from "../lib/domain/routes";

const configuredApiBase = (import.meta.env.VITE_API_BASE_URL as string | undefined)?.replace(/\/$/, "") ?? "";
const apiBaseUrl = configuredApiBase || (import.meta.env.DEV ? "http://localhost:3000" : "");

export function App() {
  const [hash, setHash] = useState(() => window.location.hash);
  useEffect(() => {
    const onHashChange = () => setHash(window.location.hash);
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  const cveId = useMemo(() => {
    const match = /^#\/cve\/(CVE-\d{4}-\d{4,})$/i.exec(hash);
    return match?.[1].toUpperCase() ?? null;
  }, [hash]);
  const vendorId = useMemo(() => { const match = /^#\/vendor\/([a-z0-9-]+)$/i.exec(hash); const value = match?.[1].toLowerCase() ?? ""; return isVendorId(value) ? value : null; }, [hash]);
  const comparisonCves = useMemo(() => { const match = /^#\/compare\/(.+)$/i.exec(hash); return parseComparisonCves(match?.[1]); }, [hash]);
  const patchTuesdayArchive = /^#\/patch-tuesday\/?$/i.test(hash);
  const sourceHealth = /^#\/operations\/?$/i.test(hash);

  useEffect(() => {
    document.title = cveId ? `${cveId} · Vulnerability Intelligence` : vendorId ? `${vendorLabel(vendorId)} · Vulnerability Intelligence` : comparisonCves.length >= 2 ? "Compare vulnerabilities · Vulnerability Intelligence" : patchTuesdayArchive ? "Patch Tuesday archive · Vulnerability Intelligence" : sourceHealth ? "Source health · Vulnerability Intelligence" : "Vulnerability Intelligence";
  }, [comparisonCves, cveId, patchTuesdayArchive, sourceHealth, vendorId]);

  if (!apiBaseUrl) {
    return <main className="detailState"><h1>API configuration required</h1><p>Set the GitHub repository variable PUBLIC_API_BASE_URL to the deployed Cloudflare Worker origin, then run the Pages workflow again.</p></main>;
  }

  if (cveId) return <CveDetailClient cveId={cveId} apiBaseUrl={apiBaseUrl} backHref="#/" />;
  if (vendorId) return <VendorIntelligenceClient vendorId={vendorId} apiBaseUrl={apiBaseUrl} backHref="#/" cvePathPrefix="#/cve/" />;
  if (comparisonCves.length >= 2) return <CveComparisonClient cveIds={comparisonCves} apiBaseUrl={apiBaseUrl} backHref="#/" cvePathPrefix="#/cve/" />;
  if (patchTuesdayArchive) return <PatchTuesdayArchiveClient apiBaseUrl={apiBaseUrl} backHref="#/" />;
  if (sourceHealth) return <SourceHealthClient apiBaseUrl={apiBaseUrl} backHref="#/" />;
  return <DashboardClient initialData={demoDashboard} apiBaseUrl={apiBaseUrl} cvePathPrefix="#/cve/" vendorPathPrefix="#/vendor/" comparePathPrefix="#/compare/" />;
}
