import { VENDOR_IDS, type VendorId } from "./types";

const VENDOR_LABELS: Record<VendorId, string> = {
  microsoft: "Microsoft", cisco: "Cisco", adobe: "Adobe", fortinet: "Fortinet", "palo-alto": "Palo Alto Networks", ivanti: "Ivanti", "vmware-broadcom": "VMware / Broadcom", citrix: "Citrix", chrome: "Google Chrome", mozilla: "Mozilla", apple: "Apple", oracle: "Oracle", atlassian: "Atlassian", sap: "SAP",
};

export function isVendorId(value: string): value is VendorId { return (VENDOR_IDS as readonly string[]).includes(value); }
export function vendorLabel(value: VendorId): string { return VENDOR_LABELS[value]; }

export function parseComparisonCves(value: string | null | undefined): string[] {
  if (!value) return [];
  const unique = [...new Set(safeDecode(value).split(",").map((item) => item.trim().toUpperCase()).filter((item) => /^CVE-\d{4}-\d{4,}$/.test(item)))];
  return unique.slice(0, 3);
}

/** Product routes stay disabled until a vendor-scoped, persistent canonical slug exists. */
export function canonicalProductRoute(): null { return null; }
function safeDecode(value: string): string { try { return decodeURIComponent(value); } catch { return ""; } }
