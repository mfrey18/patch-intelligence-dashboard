import type { Database } from '../../../db/database';
import type { IngestResult } from '../contracts';
import { DEFAULT_SOURCE_POLICY } from '../contracts';
import { PostgresIngestionRepository } from '../postgres-repository';
import { fetchWithPolicy, readJsonLimited, sanitizeText, sourceCooldown } from '../safety';
import { sha256 } from '../hash';
import { record, list, validCve, iso } from '../adapters/utils';

export type EnrichmentSource = 'cve-list-v5' | 'nvd-cve';
export interface Assessment { source: string; version: string; score: number; vector: string | null; }
export interface EnrichmentRecord {
  cveId: string; status: string; description: string | null; publishedAt: string | null; modifiedAt: string | null;
  cwes: string[]; assessments: Assessment[]; references: string[]; affected: unknown[]; sourceUrl: string;
  fieldSources: Record<string,string>;
  cweAssertions?: Array<{id:string;source:string}>;
}
const validUrl = (value: unknown): value is string => typeof value === 'string' && /^https:\/\//i.test(value);
const utc = (value:unknown) => iso(typeof value==='string' && !/(Z|[+-]\d\d:?\d\d)$/.test(value) ? value+'Z' : value);
const scoreOrder = (version: string) => ['4.0','3.1','3.0','2.0'].indexOf(version);
function assessments(value: unknown, source: string): Assessment[] {
  const result: Assessment[] = [];
  for (const metric of list(value).map(record)) {
    for (const key of ['cvssV4_0','cvssV3_1','cvssV3_0','cvssV2_0','cvssData']) {
      const data = record(metric[key]); const score = data.baseScore;
      if (score == null) continue;
      if (typeof score !== 'number' || score<0 || score>10) throw new Error('Invalid CVSS score');
      const version = String(data.version ?? (key === 'cvssV2_0' ? '2.0' : ''));
      if (scoreOrder(version)<0) continue;
      result.push({source,version,score,vector:typeof data.vectorString==='string'?data.vectorString:null});
    }
  }
  return result.sort((a,b)=>scoreOrder(a.version)-scoreOrder(b.version));
}
export function parseCveRecord(value: unknown, sourceUrl: string): EnrichmentRecord {
  const root=record(value), meta=record(root.cveMetadata), containers=record(root.containers), cna=record(containers.cna);
  const cveId=validCve(meta.cveId); if (!cveId || !['PUBLISHED','REJECTED'].includes(String(meta.state))) throw new Error('Invalid CVE record');
  const providers=[cna,...list(containers.adp).map(record)];
  const cnaName=String(record(cna.providerMetadata).shortName ?? 'CNA');
  const cwes=providers.flatMap(p=>list(p.problemTypes).flatMap(v=>list(record(v).descriptions).map(d=>record(d).cweId))).filter((v):v is string=>typeof v==='string'&&/^CWE-\d+$/.test(v));
  const description=list(cna.descriptions).map(record).find(d=>d.lang==='en')?.value;
  return {cveId,status:String(meta.state).toLowerCase(),description:sanitizeText(description)??null,publishedAt:iso(meta.datePublished)??null,modifiedAt:iso(meta.dateUpdated)??null,cwes:[...new Set(cwes)],cweAssertions:providers.flatMap((p,i)=>list(p.problemTypes).flatMap(v=>list(record(v).descriptions).map(d=>record(d).cweId)).filter((v):v is string=>typeof v==='string'&&/^CWE-\d+$/.test(v)).map(id=>({id,source:i===0?`CNA:${cnaName}`:`ADP:${String(record(p.providerMetadata).shortName??'unknown')}`}))),assessments:providers.flatMap((p,i)=>assessments(p.metrics,i===0?`CNA:${cnaName}`:`ADP:${String(record(p.providerMetadata).shortName??'unknown')}`)),references:[...new Set(providers.flatMap(p=>list(p.references).map(r=>record(r).url)).filter(validUrl))],affected:list(cna.affected),sourceUrl,fieldSources:{description:`CNA:${cnaName}`,dates:'CVE Program',cwes:cwes.length?`CNA/ADP:${cnaName}`:'unknown'}};
}
export function parseNvdRecord(value: unknown, sourceUrl: string): EnrichmentRecord {
  const envelope=record(value), rows=list(envelope.vulnerabilities);
  if (rows.length!==1) throw new Error('NVD record missing or ambiguous');
  const cve=record(record(rows[0]).cve), cveId=validCve(cve.id); if (!cveId) throw new Error('Invalid NVD CVE');
  const metrics=record(cve.metrics);
  const result=Object.values(metrics).flatMap(items=>list(items).flatMap(item=>assessments([item],String(record(item).source)==='nvd@nist.gov'?'NVD':`ADP:${String(record(item).source??'unknown')}`)));
  return {cveId,status:cve.vulnStatus==='Rejected'?'rejected':'published',description:sanitizeText(list(cve.descriptions).map(record).find(d=>d.lang==='en')?.value)??null,publishedAt:utc(cve.published)??null,modifiedAt:utc(cve.lastModified)??null,cwes:[...new Set(list(cve.weaknesses).flatMap(w=>list(record(w).description).map(d=>record(d).value)).filter((v):v is string=>typeof v==='string'&&/^CWE-\d+$/.test(v)))],assessments:result,references:list(cve.references).map(r=>record(r).url).filter(validUrl),affected:list(cve.configurations),sourceUrl,fieldSources:{description:'NVD',dates:'NVD',cwes:'NVD'}};
}
export function selectCanonical(records: EnrichmentRecord[]) {
  const cna=records.find(r=>r.sourceUrl.includes('CVEProject')), nvd=records.find(r=>r!==cna);
  const all=records.flatMap(r=>r.assessments).sort((a,b)=> {
    const rank=(s:string)=>s.startsWith('CNA:')?0:s==='NVD'?1:2;
    return rank(a.source)-rank(b.source)||scoreOrder(a.version)-scoreOrder(b.version)||a.source.localeCompare(b.source);
  });
  const primary=cna??nvd;
  const cweAssertions=[...(cna?.cweAssertions??(cna?.cwes??[]).map(id=>({id,source:'CNA'}))),...(nvd?.cwes??[]).map(id=>({id,source:'NVD'}))].sort((a,b)=>{const rank=(s:string)=>s.startsWith('CNA')?0:s==='NVD'?1:2;return rank(a.source)-rank(b.source)||a.id.localeCompare(b.id);});
  return {status:cna?.status??nvd?.status??'unknown',description:cna?.description??nvd?.description??null,cwe:cweAssertions[0]?.id??null,assessment:all[0]??null,publishedAt:cna?.publishedAt??nvd?.publishedAt??null,modifiedAt:cna?.modifiedAt??nvd?.modifiedAt??null,sourceUrl:primary?.sourceUrl??null};
}
export async function saveCveEnrichment(db: Database, sourceId: EnrichmentSource, runId: string, value: EnrichmentRecord): Promise<boolean> {
  return db.transaction(async tx=> {
    await tx.prepare('SELECT pg_advisory_xact_lock(hashtextextended(?,0))').bind(`enrichment:${value.cveId}`).run();
    const previous=await tx.prepare('SELECT content_hash,source_modified_at FROM cve_enrichments WHERE cve_id=? AND source_id=? ORDER BY observed_at DESC LIMIT 1').bind(value.cveId,sourceId).first<{content_hash:string;source_modified_at:string|null}>();
    if(previous?.source_modified_at && value.modifiedAt && value.modifiedAt<previous.source_modified_at) throw new Error('Enrichment source timestamp regressed');
    const hash=await sha256({...value,sourceUrl:sourceId}); const now=new Date().toISOString();
    const changed=previous?.content_hash!==hash;
    await tx.prepare('INSERT INTO cve_enrichments(cve_id,source_id,content_hash,payload,source_url,source_modified_at,observed_at,source_run_id) VALUES (?,?,?,?::jsonb,?,?,?,?) ON CONFLICT(cve_id,source_id,content_hash) DO UPDATE SET observed_at=excluded.observed_at,source_run_id=excluded.source_run_id').bind(value.cveId,sourceId,hash,JSON.stringify(value),value.sourceUrl,value.modifiedAt,now,runId).run();
    const rows=await tx.prepare('SELECT DISTINCT ON(source_id) payload FROM cve_enrichments WHERE cve_id=? ORDER BY source_id,observed_at DESC').bind(value.cveId).all<{payload:string|EnrichmentRecord}>();
    const selected=selectCanonical(rows.results.map(r=>typeof r.payload==='string'?JSON.parse(r.payload):r.payload));
    await tx.prepare('UPDATE cves SET description=?,cwe=?,cvss_score=?,cvss_vector=?,published_at=?,modified_at=?,canonical_source_url=?,record_status=?,assessment_source=?,updated_at=? WHERE id=?').bind(selected.description,selected.cwe,selected.assessment?.score??null,selected.assessment?.vector??null,selected.publishedAt,selected.modifiedAt,selected.sourceUrl,selected.status,selected.assessment?.source??null,now,value.cveId).run();
    if(changed) await tx.prepare("INSERT INTO intelligence_changes(id,source_run_id,entity_type,entity_id,cve_id,change_type,observed_at,summary) VALUES (?,?,'cve',?,?,'CVE_ENRICHMENT_CHANGED',?,?)").bind(crypto.randomUUID(),runId,value.cveId,value.cveId,now,`${value.cveId} canonical enrichment updated (${sourceId})`).run();
    return changed;
  });
}
let revision: {sha:string;expires:number}|undefined;
async function cveRevision() {
  if(revision && revision.expires>Date.now()) return revision.sha;
  const response=await fetchWithPolicy('https://api.github.com/repos/CVEProject/cvelistV5/commits/main',DEFAULT_SOURCE_POLICY,{headers:{accept:'application/vnd.github+json'}});
  const data=record(await readJsonLimited(response,DEFAULT_SOURCE_POLICY.maxResponseBytes));
  if(typeof data.sha!=='string'||!/^[a-f0-9]{40}$/.test(data.sha)) throw new Error('CVE repository revision unavailable');
  revision={sha:data.sha,expires:Date.now()+3600000}; return revision.sha;
}
export async function ingestCveEnrichment(db: Database,sourceId: EnrichmentSource,apiKey?:string,key?:string):Promise<IngestResult> {
  const repository=new PostgresIngestionRepository(db), startedAt=new Date().toISOString();
  const maxItems=sourceId==='nvd-cve'&&!apiKey?8:50;
  const fields={mode:'delta' as const,window:{},processed:0,continuation:null,boundHit:false};
  const counts={discovered:0,inserted:0,changed:0,unchanged:0,failed:0}; const errors:string[]=[];
  const {runId,reused}=await repository.beginRun(sourceId,key,{mode:'delta',maxItems});
  if(reused)return {sourceId,runId,startedAt,completedAt:startedAt,status:'unchanged',...fields,counts,errors};
  try {
    await db.prepare('INSERT INTO enrichment_queue(cve_id,source_id) SELECT id,? FROM cves ON CONFLICT DO NOTHING').bind(sourceId).run();
    await syncChangedCves(db,sourceId,apiKey);
    const candidates=await db.prepare("SELECT cve_id FROM enrichment_queue WHERE source_id=? AND (retry_at IS NULL OR retry_at<=now()) AND (checked_at IS NULL OR checked_at<now()-INTERVAL '7 days') ORDER BY checked_at NULLS FIRST,cve_id LIMIT ?").bind(sourceId,maxItems).all<{cve_id:string}>();
    counts.discovered=candidates.results.length;
    const sha=sourceId==='cve-list-v5'&&counts.discovered?await cveRevision():null;
    for(const {cve_id:id} of candidates.results) {
      try {
        const [,year,number]=id.split('-');
        const url=sha?`https://raw.githubusercontent.com/CVEProject/cvelistV5/${sha}/cves/${year}/${number.slice(0,-3)}xxx/${id}.json`:`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${id}`;
        const response=sourceId==='nvd-cve'?await nvdFetch(url,apiKey):await fetchWithPolicy(url,DEFAULT_SOURCE_POLICY,{headers:{accept:'application/json'}});
        const body=await readJsonLimited(response,DEFAULT_SOURCE_POLICY.maxResponseBytes);
        const normalized=sha?parseCveRecord(body,url):parseNvdRecord(body,`https://nvd.nist.gov/vuln/detail/${id}`);
        if(normalized.cveId!==id)throw new Error('Enrichment identity mismatch');
        const changed=await saveCveEnrichment(db,sourceId,runId,normalized); counts[changed?'changed':'unchanged']++;
        await db.prepare('UPDATE enrichment_queue SET checked_at=now(),retry_at=NULL,failures=0 WHERE cve_id=? AND source_id=?').bind(id,sourceId).run();
      } catch(error) {
        counts.failed++; errors.push(`${id}: ${error instanceof Error?error.message:'Enrichment failed'}`);
        await db.prepare("UPDATE enrichment_queue SET retry_at=now()+INTERVAL '1 hour',failures=failures+1 WHERE cve_id=? AND source_id=?").bind(id,sourceId).run();
        // A rate limit must stop this batch, not start another request before its deadline.
        const retryAt=sourceCooldown(error);if(retryAt){await repository.deferSource(sourceId,retryAt);break;}
      }
      fields.processed++;
    }
    const remaining=await db.prepare("SELECT COUNT(*) total FROM enrichment_queue WHERE source_id=? AND (checked_at IS NULL OR checked_at<now()-INTERVAL '7 days')").bind(sourceId).first<{total:number}>();
    const updates=await db.prepare("SELECT window_end FROM enrichment_updates WHERE source_id=?").bind(sourceId).first<{window_end:string|null}>();
    fields.boundHit=Number(remaining?.total)>0 || Boolean(updates?.window_end);
  }catch(error){counts.failed++;errors.push(error instanceof Error?error.message:'Enrichment failed');const retryAt=sourceCooldown(error);if(retryAt)await repository.deferSource(sourceId,retryAt);}
  const status=counts.failed?'partial':fields.boundHit?'partial':counts.changed?'success':'unchanged';
  const result={status,...fields,counts,errors} satisfies Omit<IngestResult,'sourceId'|'runId'|'startedAt'|'completedAt'>;
  await repository.finishRun(runId,result); return {sourceId,runId,startedAt,completedAt:new Date().toISOString(),...result};
}

let nextNvdAt=0;
async function nvdFetch(url:string,key?:string) {
  return fetchWithPolicy(url,{...DEFAULT_SOURCE_POLICY,maxResponseBytes:32_000_000},{headers:key?{apiKey:key}:{accept:'application/json'}},[],{schedule:async request=>{
    const wait=Math.max(0,nextNvdAt-Date.now());nextNvdAt=Math.max(Date.now(),nextNvdAt)+(key?650:6100);
    if(wait)await new Promise(resolve=>setTimeout(resolve,wait));return request();
  }});
}
async function syncChangedCves(db:Database,source:EnrichmentSource,key?:string) {
  const state=await db.prepare('SELECT completed_at,window_start,window_end,next_offset FROM enrichment_updates WHERE source_id=?').bind(source).first<{completed_at:string|null;window_start:string|null;window_end:string|null;next_offset:number}>();
  if(state?.completed_at && !state.window_end && Date.now()-Date.parse(state.completed_at)<86400000)return;
  const since=state?.window_start??new Date(state?.completed_at?Date.parse(state.completed_at)-86400000:Date.now()-3*86400000).toISOString();
  const until=state?.window_end??new Date(Math.min(Date.now(),Date.parse(since)+7*86400000)).toISOString();
  const updates:Array<{id:string;modified:string}>=[];
  let offset=0,complete=true;
  if(source==='cve-list-v5') {
    const sha=await cveRevision(), policy={...DEFAULT_SOURCE_POLICY,maxResponseBytes:64_000_000};
    const data=await readJsonLimited(await fetchWithPolicy(`https://raw.githubusercontent.com/CVEProject/cvelistV5/${sha}/cves/deltaLog.json`,policy),policy.maxResponseBytes);
    if(!Array.isArray(data))throw new Error('Invalid CVE delta log');
    for(const entry of data.map(record)) for(const change of [...list(entry.new),...list(entry.updated)].map(record)) {
      const id=validCve(change.cveId),modified=iso(change.dateUpdated);
      if(id&&modified&&modified>=since)updates.push({id,modified});
    }
  }else{
    const url=new URL('https://services.nvd.nist.gov/rest/json/cves/2.0');
    url.searchParams.set('lastModStartDate',since);url.searchParams.set('lastModEndDate',until);url.searchParams.set('resultsPerPage','100');url.searchParams.set('startIndex',String(state?.next_offset??0));
    const data=record(await readJsonLimited(await nvdFetch(url.href,key),32_000_000));
    if(!Array.isArray(data.vulnerabilities)||!Number.isInteger(data.totalResults)||!Number.isInteger(data.startIndex))throw new Error('Invalid NVD modification page');
    for(const entry of data.vulnerabilities) {const cve=record(record(entry).cve),id=validCve(cve.id),modified=utc(cve.lastModified);if(!id||!modified)throw new Error('Invalid NVD modification identity');updates.push({id,modified});}
    offset=Number(data.startIndex)+data.vulnerabilities.length;complete=offset>=Number(data.totalResults);
    if(!complete&&!data.vulnerabilities.length)throw new Error('NVD pagination did not advance');
  }
  await db.transaction(async tx=>{
    await tx.prepare("UPDATE enrichment_queue q SET checked_at=NULL FROM (SELECT value->>'id' id,MAX((value->>'modified')::timestamptz) modified FROM jsonb_array_elements(?::jsonb) GROUP BY value->>'id') u WHERE q.cve_id=u.id AND q.source_id=? AND q.checked_at<u.modified").bind(JSON.stringify(updates),source).run();
    await tx.prepare('INSERT INTO enrichment_updates(source_id,completed_at,window_start,window_end,next_offset) VALUES (?,?,?,?,?) ON CONFLICT(source_id) DO UPDATE SET completed_at=excluded.completed_at,window_start=excluded.window_start,window_end=excluded.window_end,next_offset=excluded.next_offset').bind(source,complete?until:state?.completed_at??null,complete?null:since,complete?null:until,complete?0:offset).run();
  });
}
