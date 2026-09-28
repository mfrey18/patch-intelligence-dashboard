import type { DiscoveryPage, VendorAdapter } from '../contracts';
import type { NormalizedAdvisory } from '../../domain/types';
import { fetchWithPolicy, readJsonLimited } from '../safety';
import { record, validCve } from './utils';
import { absoluteOfficialUrl, explicitDate, loadHtml, read, text as htmlText } from './html';

// Official API documented in Broadcom knowledge article 408302. Its index omits
// complete product/version and remediation assertions; never infer them from titles.
export const BROADCOM_INDEX = 'https://support.broadcom.com/web/ecx/security-advisory/-/securityadvisory/getSecurityAdvisoryList';
export interface BroadcomAdapterOptions {
  /** Fetch the linked official detail page after reading the JSON index. */
  fetchDetails?: boolean;
}

export function createBroadcomAdapter(options: BroadcomAdapterOptions = {}): VendorAdapter {
return {
  vendor: 'vmware-broadcom', sourceId: 'vmware-broadcom-json',
  historicalCoverage: options.fetchDetails === false ? undefined : 'complete_index',
  async discover(ctx) { return (await this.discoverPage!(ctx)).refs; },
  async discoverPage(ctx, cursor) {
    const page = cursor == null ? 0 : Number(cursor);
    if (!Number.isSafeInteger(page) || page < 0) throw new Error('Invalid Broadcom cursor');
    const response = await fetchWithPolicy(BROADCOM_INDEX, ctx.policy, {
      method: 'POST', redirect: 'error', headers: {accept:'application/json','content-type':'application/json'},
      body: JSON.stringify({pageNumber:page,pageSize:50,searchVal:'',segment:'VC',sortInfo:{column:'',order:''}}),
    });
    return parseBroadcomPage(await readJsonLimited(response,ctx.policy.maxResponseBytes),page,ctx.since,ctx.until);
  },
  async fetch(ref, ctx) {
    if (!ref.metadata?.indexRecord) throw new Error('Broadcom index record missing');
    const index = JSON.parse(ref.metadata.indexRecord) as unknown;
    if (!ctx || options.fetchDetails === false) return {ref,body:index,contentType:'application/json',fetchedAt:new Date().toISOString(),resolvedUrl:ref.url};
    const detail = await import('./html').then(({ fetchOfficialHtml }) => fetchOfficialHtml(ref.url, ctx, ['support.broadcom.com']));
    return {ref,body:{index,detailHtml:detail.html},contentType:'text/html',fetchedAt:detail.fetchedAt,resolvedUrl:detail.url,etag:detail.etag,lastModified:detail.lastModified};
  },
  async normalize(raw,ctx): Promise<NormalizedAdvisory[]> {
    const envelope = isDetailEnvelope(raw.body) ? raw.body : undefined;
    const row=record(envelope?.index ?? raw.body), ids=cveIds(row.affectedCve), detail=envelope ? parseBroadcomDetail(envelope.detailHtml, raw.resolvedUrl) : undefined;
    const detailIds = detail?.cves ?? [];
    const allIds = [...new Set([...ids, ...detailIds])];
    const title=detail?.title ?? ctx.sanitizeText(row.title);
    if (!title || row.documentId !== raw.ref.id) throw new Error('Invalid Broadcom advisory identity');
    const publishedAt=detail?.publishedAt ?? publicationDate(row.published), sourceUpdatedAt=detail?.sourceUpdatedAt ?? updatedDate(row.updated);
    return [{vendor:'vmware-broadcom',sourceId:'vmware-broadcom-json',vendorAdvisoryId:raw.ref.id,title,
      sourceUrl:detail?.sourceUrl ?? officialUrl(row.notificationUrl),publishedAt,sourceUpdatedAt,
      summary:'Broadcom advisory index. Full product/version and remediation details are available at the linked advisory; this index does not supply them.',
      vendorSeverity:ctx.sanitizeText(row.severity),exploitationStatus:'unknown',zeroDayStatus:'unknown',
      // The index severity is advisory-level, not a separate assessment of every CVE.
      cves:allIds.map(cveId=>({cveId,normalizedSeverity:'unknown',publishedAt,modifiedAt:sourceUpdatedAt})),
      affectedProducts:detail?.affectedProducts ?? [],remediations:detail?.remediations ?? [],exploitEvidence:[]}];
  },
};
}

export const broadcomAdapter: VendorAdapter = createBroadcomAdapter({ fetchDetails: true });

export interface BroadcomDetail {
  title: string;
  sourceUrl: string;
  publishedAt?: string;
  sourceUpdatedAt?: string;
  cves: string[];
  affectedProducts: NormalizedAdvisory['affectedProducts'];
  remediations: NormalizedAdvisory['remediations'];
}

/** Parses only explicit Broadcom detail fields; absent product/fix assertions stay absent. */
export function parseBroadcomDetail(html: string, sourceUrl: string): BroadcomDetail {
  const document = loadHtml(html);
  const body = htmlText(document, 'main') ?? htmlText(document, 'body') ?? '';
  const title = read(document, 'h1') ?? read(document, 'meta[property="og:title"]', 'content') ?? read(document, 'title');
  if (!title) throw new Error('Broadcom detail has no explicit title');
  const pageUrl = absoluteOfficialUrl(sourceUrl, read(document, 'meta[property="og:url"]', 'content') ?? sourceUrl, ['support.broadcom.com']);
  if (!pageUrl) throw new Error('Broadcom detail has no official URL');
  const cves = looseCveIds(body);
  const dates = [...document('time').toArray().map((node) => document(node).attr('datetime') ?? document(node).text()), read(document, 'meta[property="article:published_time"]', 'content'), read(document, 'meta[property="article:modified_time"]', 'content')].map((value) => explicitDate(value ?? undefined) ?? normalizeDate(value ?? undefined)).filter((value): value is string => Boolean(value));
  const publishedAt = dates[0];
  const sourceUpdatedAt = dates[1] ?? publishedAt;
  const rows = broadcomDetailRows(document);
  const affectedProducts: NormalizedAdvisory['affectedProducts'] = [];
  const remediations: NormalizedAdvisory['remediations'] = [];
  for (const row of rows) {
    const headers = row.headers.map((value) => value.toLowerCase());
    if (headers.length > 0 && row.cells.length === headers.length && row.cells.every((value, index) => value.trim().toLowerCase() === headers[index])) continue;
    const productIndex = findColumn(headers, /product|component|platform/);
    const affectedIndex = findColumn(headers, /affected|version|impact/);
    const fixedIndex = findColumn(headers, /fixed|solution|remediat|upgrade|patch/);
    const product = compact(row.cells[productIndex ?? 0]);
    const affected = affectedIndex === undefined ? undefined : compact(row.cells[affectedIndex]);
    const fixed = fixedIndex === undefined ? undefined : compact(row.cells[fixedIndex]);
    if (!product || (!affected && !fixed)) continue;
    const rowCves = looseCveIds(row.cells.join(' '));
    const cveId = rowCves.length === 1 ? rowCves[0] : undefined;
    if (isNegativeAssertion(affected)) {
      affectedProducts.push({ cveId, name: product, status: 'unaffected' });
      continue;
    }
    const fixedVersion = explicitBroadcomFix(fixed);
    affectedProducts.push({ cveId, name: product, affectedVersion: affected, fixedVersion, status: affected ? 'affected' : fixedVersion ? 'fixed' : 'unknown' });
    if (fixedVersion) remediations.push({ cveId, productName: product, kind: 'fixed_version', fixedVersion, patchAvailable: true, action: fixed, sourceUrl: pageUrl, publishedAt, updatedAt: sourceUpdatedAt });
  }
  return { title, sourceUrl: pageUrl, publishedAt, sourceUpdatedAt, cves, affectedProducts, remediations };
}

function isDetailEnvelope(value: unknown): value is { index: unknown; detailHtml: string } {
  return !!value && typeof value === 'object' && typeof (value as { detailHtml?: unknown }).detailHtml === 'string' && 'index' in value;
}

function findColumn(headers: string[], pattern: RegExp): number | undefined { const index = headers.findIndex((value) => pattern.test(value)); return index < 0 ? undefined : index; }
function compact(value: string | undefined): string | undefined { const result = value?.replace(/\s+/g, ' ').trim(); return result || undefined; }
function isNegativeAssertion(value: string | undefined): boolean { return !!value && /^(?:n\/a|na|not\s+(?:affected|applicable)|unaffected|none|unknown|migrate(?:\s+to)?|no\s+fix)$/i.test(value.trim()); }
function explicitBroadcomFix(value: string | undefined): string | undefined { return value && !isNegativeAssertion(value) && /^\d/.test(value) ? value : undefined; }
function broadcomDetailRows(document: ReturnType<typeof loadHtml>): Array<{ cells: string[]; headers: string[] }> {
  const rows: Array<{ cells: string[]; headers: string[] }> = [];
  for (const table of document('table').toArray()) {
    const tableNode = document(table);
    const tableRows = tableNode.find('tr').toArray().map((row) => document(row).find('th,td').toArray().map((cell) => document(cell).text().replace(/\s+/g, ' ').trim())).filter((cells) => cells.length > 0);
    if (tableRows.length < 2) continue;
    const header = tableRows[0];
    if (!header.some((value) => /product|component|platform/i.test(value)) || !header.some((value) => /fixed|solution|remediat|upgrade|patch/i.test(value))) continue;
    for (const cells of tableRows.slice(1)) rows.push({ cells, headers: header });
  }
  return rows;
}
function normalizeDate(value: string | undefined): string | undefined { if (!value) return undefined; const date = new Date(value); return Number.isFinite(date.getTime()) ? date.toISOString() : undefined; }
function looseCveIds(value: string): string[] { return [...new Set([...value.matchAll(/CVE-\d{4}-\d{4,}/gi)].map((match) => match[0].toUpperCase()))]; }
export function parseBroadcomPage(value:unknown,page:number,since?:string,until?:string):DiscoveryPage {
  const root=record(value),data=record(root.data),info=record(data.pageInfo);
  if(root.success!==true || !Array.isArray(data.list) || info.currentPage!==page || !Number.isSafeInteger(info.lastPage) || Number(info.lastPage)<page || !Number.isSafeInteger(info.totalCount)) throw new Error('Invalid Broadcom index page');
  const last=Number(info.lastPage);
  if(page<last && (info.nextPage!==page+1 || !data.list.length))throw new Error('Broadcom pagination did not advance');
  const refs=data.list.map(item=>{
    const row=record(item);
    if(typeof row.documentId!=='string'||!/^VCDSA\d+$/.test(row.documentId))throw new Error('Invalid Broadcom document ID');
    cveIds(row.affectedCve);
    const sourceUpdatedAt=updatedDate(row.updated), publishedAt=publicationDate(row.published);
    return {id:row.documentId,url:officialUrl(row.notificationUrl),sourceUpdatedAt,metadata:{indexRecord:JSON.stringify(row)},publishedAt};
  }).filter(ref=>(!since||ref.sourceUpdatedAt>=since||ref.publishedAt>=since)&&(!until||ref.publishedAt<=until));
  return {refs,nextCursor:page<last?String(page+1):null};
}
function cveIds(value:unknown):string[] {
  if(value==null||value==='')return [];
  if(typeof value!=='string')throw new Error('Invalid Broadcom CVE list');
  const matches=value.match(/CVE-\d{4}-\d{4,}/g)??[];
  const remainder=value.replace(/CVE-\d{4}-\d{4,}/g,'').replace(/\band\b/gi,'').replace(/[,;\s]/g,'');
  const ids=matches.map(validCve);
  if(remainder||ids.some(id=>!id)||!ids.length)throw new Error('Invalid Broadcom CVE identifier');
  return [...new Set(ids as string[])];
}
function officialUrl(value:unknown):string {
  if(typeof value!=='string')throw new Error('Broadcom advisory URL missing');
  const url=new URL(value);
  if(url.protocol!=='https:'||url.hostname!=='support.broadcom.com'||url.username||url.password)throw new Error('Invalid Broadcom advisory origin');
  return url.href;
}
function publicationDate(value:unknown):string {
  if(typeof value!=='string'||!/^\d{2} [A-Za-z]+ \d{4}$/.test(value)||!Number.isFinite(Date.parse(value+' UTC')))throw new Error('Invalid Broadcom publication date');
  return new Date(value+' UTC').toISOString();
}
function updatedDate(value:unknown):string {
  if(typeof value!=='string'||!/^\d{4}-\d{2}-\d{2}T/.test(value))throw new Error('Invalid Broadcom update date');
  // Upstream timestamps omit the offset; interpret offset-less ISO timestamps as UTC for ordering.
  const normalized=/(Z|[+-]\d\d:?\d\d)$/.test(value)?value:value+'Z';
  if(!Number.isFinite(Date.parse(normalized)))throw new Error('Invalid Broadcom update date');
  return new Date(normalized).toISOString();
}
