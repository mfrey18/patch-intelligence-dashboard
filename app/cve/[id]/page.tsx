import type { Metadata } from "next";
import { CveDetailClient } from "./CveDetailClient";

export async function generateMetadata({ params }: { params: Promise<{ id: string }> }): Promise<Metadata> {
  const { id } = await params;
  const cveId = decodeURIComponent(id).toUpperCase();
  return { title: `${cveId} · Vulnerability Intelligence`, description: `Canonical vulnerability data, authoritative threat evidence, EPSS history, vendor assertions, revision timeline, and supporting remediation context for ${cveId}.` };
}

export default async function CvePage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return <CveDetailClient cveId={decodeURIComponent(id).toUpperCase()} />;
}
