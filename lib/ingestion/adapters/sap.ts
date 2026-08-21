import type { NormalizedAdvisory } from "../../domain/types";
import type { RawAdvisory, VendorAdapter } from "../contracts";
import { normalizeCsaf } from "./csaf";
import { createConfiguredCsafAdapter } from "./configured-csaf";

export interface SapAdapterOptions {
  /** Explicit SAP-hosted CSAF JSON documents available to the customer's SAP account. */
  csafUrls?: string[];
  bearerToken?: string;
}

export function createSapAdapter(options: SapAdapterOptions = {}): VendorAdapter {
  return createConfiguredCsafAdapter({
    vendor: "sap",
    sourceId: "sap-configured-csaf",
    urls: options.csafUrls,
    bearerToken: options.bearerToken,
    allowedHosts: ["sap.com"],
    missingConfigurationMessage: "SAP Security Notes require SAP for Me entitlement; configure SAP_CSAF_URLS and SAP_CSAF_TOKEN with SAP-hosted machine-readable documents",
  });
}

export const sapAdapter = createSapAdapter();

export function normalizeSapCsaf(raw: RawAdvisory, sanitize: (value: unknown) => string | undefined): NormalizedAdvisory {
  return normalizeCsaf(raw, sanitize, { vendor: "sap", sourceId: "sap-configured-csaf" })[0];
}
