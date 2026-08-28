import type { VendorAdapter } from "./contracts";
import { microsoftAdapter } from "./adapters/microsoft";
import { createCiscoAdapter } from "./adapters/cisco";
import { createAdobeAdapter } from "./adapters/adobe";
import { createFortinetAdapter } from "./adapters/fortinet";
import { paloAltoAdapter } from "./adapters/palo-alto";
import { createIvantiAdapter } from "./adapters/ivanti";
import { mozillaAdapter } from "./adapters/mozilla";
import { oracleAdapter } from "./adapters/oracle";
import { atlassianAdapter } from "./adapters/atlassian";
import { createAppleAdapter } from "./adapters/apple";
import { createSapAdapter } from "./adapters/sap";
import { PRODUCTION_SOURCE_IDS, SOURCE_CATALOG, SOURCE_IDS } from "./source-catalog";

export interface AdapterEnvironment {
  CISCO_CLIENT_ID?: string;
  CISCO_CLIENT_SECRET?: string;
  ADOBE_SECURITY_INDEX_URL?: string;
  ADOBE_SECURITY_AUTHORIZATION?: string;
  FORTINET_CSAF_URL_TEMPLATE?: string;
  FORTINET_CSAF_AUTHORIZATION?: string;
  APPLE_CSAF_URLS?: string;
  APPLE_CSAF_TOKEN?: string;
  SAP_CSAF_URLS?: string;
  SAP_CSAF_TOKEN?: string;
}

export { SOURCE_IDS };

export function defaultSourceIds(env: AdapterEnvironment): string[] {
  return PRODUCTION_SOURCE_IDS
    .map((sourceId) => SOURCE_CATALOG.find((source) => source.id === sourceId))
    .filter((source) => source != null)
    .filter((source) => !("requiresConfiguration" in source) || !source.requiresConfiguration || isConfigured(source.id, env))
    .map((source) => source.id);
}

export function createVendorAdapter(sourceId: string, env: AdapterEnvironment): VendorAdapter | null {
  switch (sourceId) {
    case "microsoft-msrc-csaf": return microsoftAdapter;
    case "cisco-psirt-csaf": return createCiscoAdapter({ clientId: env.CISCO_CLIENT_ID, clientSecret: env.CISCO_CLIENT_SECRET });
    case "adobe-psirt-csaf": return createAdobeAdapter({ indexUrl: env.ADOBE_SECURITY_INDEX_URL, authorization: env.ADOBE_SECURITY_AUTHORIZATION });
    case "fortinet-psirt-csaf": return createFortinetAdapter({ csafUrlTemplate: env.FORTINET_CSAF_URL_TEMPLATE, authorization: env.FORTINET_CSAF_AUTHORIZATION });
    case "palo-alto-psirt-csaf": return paloAltoAdapter;
    case "ivanti-security-advisory-rss": return createIvantiAdapter();
    case "mozilla-mfsa-yaml": return mozillaAdapter;
    case "oracle-cpu-csaf": return oracleAdapter;
    case "atlassian-vulnerability-api": return atlassianAdapter;
    case "apple-configured-csaf": return createAppleAdapter({ csafUrls: parseUrlList(env.APPLE_CSAF_URLS), bearerToken: env.APPLE_CSAF_TOKEN });
    case "sap-configured-csaf": return createSapAdapter({ csafUrls: parseUrlList(env.SAP_CSAF_URLS), bearerToken: env.SAP_CSAF_TOKEN });
    default: return null;
  }
}

function isConfigured(sourceId: string, env: AdapterEnvironment): boolean {
  if (sourceId === "cisco-psirt-csaf") return Boolean(env.CISCO_CLIENT_ID && env.CISCO_CLIENT_SECRET);
  if (sourceId === "adobe-psirt-csaf") return Boolean(env.ADOBE_SECURITY_INDEX_URL);
  if (sourceId === "fortinet-psirt-csaf") return Boolean(env.FORTINET_CSAF_URL_TEMPLATE);
  if (sourceId === "apple-configured-csaf") return parseUrlList(env.APPLE_CSAF_URLS).length > 0;
  if (sourceId === "sap-configured-csaf") return parseUrlList(env.SAP_CSAF_URLS).length > 0;
  return true;
}

function parseUrlList(value?: string): string[] {
  if (!value) return [];
  try {
    const parsed = JSON.parse(value);
    if (Array.isArray(parsed)) return parsed.filter((item): item is string => typeof item === "string" && item.length > 0);
  } catch { /* Accept comma/newline-separated configuration as well as JSON. */ }
  return value.split(/[\r\n,]+/).map((item) => item.trim()).filter(Boolean);
}

if (SOURCE_IDS.size !== SOURCE_CATALOG.length) throw new Error("Duplicate source IDs in the ingestion source catalog");
