import { useEffect, useMemo, useState } from "react";
import { DashboardClient } from "../app/DashboardClient";
import { CveDetailClient } from "../app/cve/[id]/CveDetailClient";
import { demoDashboard } from "../lib/demo-data";

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

  useEffect(() => {
    document.title = cveId ? `${cveId} · Patch Intelligence` : "Patch Intelligence";
  }, [cveId]);

  if (!apiBaseUrl) {
    return <main className="detailState"><h1>API configuration required</h1><p>Set the GitHub repository variable PUBLIC_API_BASE_URL to the deployed Cloudflare Worker origin, then run the Pages workflow again.</p></main>;
  }

  return cveId
    ? <CveDetailClient cveId={cveId} apiBaseUrl={apiBaseUrl} backHref="#/" />
    : <DashboardClient initialData={demoDashboard} apiBaseUrl={apiBaseUrl} cvePathPrefix="#/cve/" />;
}
