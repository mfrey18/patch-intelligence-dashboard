import type { Metadata } from "next";
import { VendorIntelligenceClient } from "../../VendorIntelligenceClient";
import { isVendorId, vendorLabel } from "../../../lib/domain/routes";

export async function generateMetadata({ params }: { params: Promise<{ vendor: string }> }): Promise<Metadata> {
  const { vendor } = await params; const decoded = decodeURIComponent(vendor);
  const label = isVendorId(decoded) ? vendorLabel(decoded) : "Vendor";
  return { title: `${label} · Vulnerability Intelligence`, description: `Observed vulnerability, exploitation, KEV, zero-day, EPSS, change, product-family, and weakness intelligence for ${label}.` };
}

export default async function VendorPage({ params }: { params: Promise<{ vendor: string }> }) { const { vendor } = await params; return <VendorIntelligenceClient vendorId={decodeURIComponent(vendor)} />; }
