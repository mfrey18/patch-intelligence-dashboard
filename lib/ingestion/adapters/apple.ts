import type { NormalizedAdvisory } from "../../domain/types";
import type { RawAdvisory, VendorAdapter } from "../contracts";
import { normalizeCsaf } from "./csaf";
import { createConfiguredCsafAdapter } from "./configured-csaf";

export interface AppleAdapterOptions {
  /** Explicit Apple-hosted CSAF JSON documents supplied by an enterprise feed. */
  csafUrls?: string[];
  bearerToken?: string;
}

export function createAppleAdapter(options: AppleAdapterOptions = {}): VendorAdapter {
  return createConfiguredCsafAdapter({
    vendor: "apple",
    sourceId: "apple-configured-csaf",
    urls: options.csafUrls,
    bearerToken: options.bearerToken,
    allowedHosts: ["apple.com"],
    missingConfigurationMessage: "Apple does not expose a verified public machine-readable security-advisory feed; configure APPLE_CSAF_URLS with Apple-hosted CSAF JSON documents",
  });
}

export const appleAdapter = createAppleAdapter();

export function normalizeAppleCsaf(raw: RawAdvisory, sanitize: (value: unknown) => string | undefined): NormalizedAdvisory {
  return normalizeCsaf(raw, sanitize, { vendor: "apple", sourceId: "apple-configured-csaf" })[0];
}
