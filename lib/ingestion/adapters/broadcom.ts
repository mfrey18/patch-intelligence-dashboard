import type { DiscoveryPage, VendorAdapter } from '../contracts';
import type { NormalizedAdvisory } from '../../domain/types';
import { fetchWithPolicy, readJsonLimited } from '../safety';
import { record, validCve } from './utils';

// Official API documented in Broadcom knowledge article 408302. Its index omits
// complete product/version and remediation assertions; never infer them from titles.
export const BROADCOM_INDEX = 'https://support.broadcom.com/web/ecx/security-advisory/-/securityadvisory/getSecurityAdvisoryList';
export const broadcomAdapter: VendorAdapter = {
  vendor: 'vmware-broadcom', sourceId: 'vmware-broadcom-json',
  async discover(ctx) { return (await broadcomAdapter.discoverPage!(ctx)).refs; },
  async discoverPage(ctx, cursor) {
    const page = cursor == null ? 0 : Number(cursor);
    if (!Number.isSafeInteger(page) || page < 0) throw new Error('Invalid Broadcom cursor');
    const response = await fetchWithPolicy(BROADCOM_INDEX, ctx.policy, {
      method: 'POST', redirect: 'error', headers: {accept:'application/json','content-type':'application/json'},
      body: JSON.stringify({pageNumber:page,pageSize:50,searchVal:'',segment:'VC',sortInfo:{column:'',order:''}}),
    });
    return parseBroadcomPage(await readJsonLimited(response,ctx.policy.maxResponseBytes),page,ctx.since,ctx.until);
  },
  async fetch(ref) {
    if (!ref.metadata?.indexRecord) throw new Error('Broadcom index record missing');
    return {ref,body:JSON.parse(ref.metadata.indexRecord),contentType:'application/json',fetchedAt:new Date().toISOString(),resolvedUrl:ref.url};
  },
  async normalize(raw,ctx): Promise<NormalizedAdvisory[]> {
    const row=record(raw.body), ids=cveIds(row.affectedCve), title=ctx.sanitizeText(row.title);
    if (!title || row.documentId !== raw.ref.id) throw new Error('Invalid Broadcom advisory identity');
    const publishedAt=publicationDate(row.published), sourceUpdatedAt=updatedDate(row.updated);
    return [{vendor:'vmware-broadcom',sourceId:'vmware-broadcom-json',vendorAdvisoryId:raw.ref.id,title,
      sourceUrl:officialUrl(row.notificationUrl),publishedAt,sourceUpdatedAt,
      summary:'Broadcom advisory index. Full product/version and remediation details are available at the linked advisory; this index does not supply them.',
      vendorSeverity:ctx.sanitizeText(row.severity),exploitationStatus:'unknown',zeroDayStatus:'unknown',
      // The index severity is advisory-level, not a separate assessment of every CVE.
      cves:ids.map(cveId=>({cveId,normalizedSeverity:'unknown',publishedAt,modifiedAt:sourceUpdatedAt})),
      affectedProducts:[],remediations:[],exploitEvidence:[]}];
  },
};
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
