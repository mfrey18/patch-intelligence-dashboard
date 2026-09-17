import type { VendorAdapter } from '../contracts';
import { fetchWithPolicy, readJsonLimited, readTextLimited } from '../safety';
import { normalizeCsaf } from './csaf';

const ROOT = 'https://security.access.redhat.com/data/csaf/v2/advisories/';
export const redHatAdapter: VendorAdapter = {
  vendor: 'red-hat', sourceId: 'red-hat-csaf',
  policy: {maxResponseBytes: 32_000_000},
  async discover(ctx) {
    const text = await readTextLimited(await fetchWithPolicy(`${ROOT}changes.csv`,ctx.policy),ctx.policy.maxResponseBytes);
    return parseRedHatChanges(text,ctx.since,ctx.until);
  },
  async fetch(ref,ctx) {
    const response = await fetchWithPolicy(ref.url,ctx.policy);
    return {ref,contentType:'application/json',body:await readJsonLimited(response,ctx.policy.maxResponseBytes),fetchedAt:new Date().toISOString(),resolvedUrl:response.url || ref.url};
  },
  async normalize(raw,ctx) { return normalizeCsaf(raw,ctx.sanitizeText,{vendor:'red-hat',sourceId:'red-hat-csaf'}); },
};
export function parseRedHatChanges(text: string,since?: string,until?: string) {
  return text.trim().split(/\r?\n/).filter(Boolean).map(line=> {
    const match = /^"?(\d{4}\/rh[a-z]{2}-[\w-]+\.json)"?,"?([^"\r\n]+)"?$/.exec(line);
    if (!match || !Number.isFinite(Date.parse(match[2]))) throw new Error('Invalid Red Hat CSAF changes index');
    return {id:match[1],url:new URL(match[1],ROOT).href,sourceUpdatedAt:new Date(match[2]).toISOString()};
  }).filter(ref=>ref.id.split("/")[1].startsWith("rhsa-")).filter(ref=>(!since || ref.sourceUpdatedAt>=since)&&(!until || ref.sourceUpdatedAt<=until));
}
