import type { Database } from '../../../db/database';
import type { IngestResult } from '../contracts';
import { DEFAULT_SOURCE_POLICY } from '../contracts';
import { PostgresIngestionRepository } from '../postgres-repository';
import { fetchWithPolicy, readJsonLimited, sanitizeText, sourceCooldown } from '../safety';
import { sha256 } from '../hash';
import { recordSourceCompletion } from '../source-completion';
import { loadEnrichmentCycle, requireChangedMembers, enrichmentProgress, type EnrichmentCycle } from '../enrichment-cycles';
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
async function cveRevision() {
  const response=await fetchWithPolicy('https://api.github.com/repos/CVEProject/cvelistV5/commits/main',DEFAULT_SOURCE_POLICY,{headers:{accept:'application/vnd.github+json'}});
  const data=record(await readJsonLimited(response,DEFAULT_SOURCE_POLICY.maxResponseBytes));
  if(typeof data.sha!=='string'||!/^[a-f0-9]{40}$/.test(data.sha)) throw new Error('CVE repository revision unavailable');
  return data.sha;
}
export async function ingestCveEnrichment(db: Database,sourceId: EnrichmentSource,apiKey?:string,key?:string):Promise<IngestResult> {
  const repository=new PostgresIngestionRepository(db), startedAt=new Date().toISOString();
  const maxItems=sourceId==='nvd-cve'&&!apiKey?8:50;
  const fields:{mode:'delta';window:Record<string,string>;processed:number;continuation:string|null;boundHit:boolean}={mode:'delta',window:{},processed:0,continuation:null,boundHit:false};
  const counts={discovered:0,inserted:0,changed:0,unchanged:0,failed:0}; const errors:string[]=[];
  const {runId,reused,continuation,boundHit}=await repository.beginRun(sourceId,key,{mode:'delta',maxItems});
  if(reused)return {sourceId,runId,startedAt,completedAt:startedAt,status:'unchanged',...fields,continuation,boundHit,counts,errors};
  try {
    const cycle=await loadEnrichmentCycle(db,sourceId,startedAt);
    const initialProgress=await enrichmentProgress(db,cycle);
    const initialPosition=await enrichmentPosition(db,cycle,initialProgress.remaining);
    await db.prepare('UPDATE source_runs SET checkpoint_id=?,continuation_in=? WHERE id=?').bind(cycle.id,initialPosition,runId).run();
    let sha: string | null = null;
    if(sourceId==='cve-list-v5'){
      sha=cycle.source_revision??await cveRevision();
      if(!cycle.source_revision)await db.prepare('UPDATE enrichment_cycles SET source_revision=? WHERE id=? AND source_revision IS NULL').bind(sha,cycle.id).run();
      cycle.source_revision=sha;
    }
    await syncChangedCves(db,sourceId,apiKey,cycle);
    const candidates=await db.prepare("SELECT cve_id,required_generation FROM enrichment_cycle_members WHERE cycle_id=? AND satisfied_generation<required_generation AND (retry_at IS NULL OR retry_at<=now()) ORDER BY checked_at NULLS FIRST,cve_id LIMIT ?").bind(cycle.id,maxItems).all<{cve_id:string;required_generation:number}>();
    counts.discovered=candidates.results.length;
    for(const {cve_id:id,required_generation:generation} of candidates.results) {
      try {
        const [,year,number]=id.split('-');
        const url=sha?`https://raw.githubusercontent.com/CVEProject/cvelistV5/${sha}/cves/${year}/${number.slice(0,-3)}xxx/${id}.json`:`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${id}`;
        const response=sourceId==='nvd-cve'?await nvdFetch(url,apiKey):await fetchWithPolicy(url,DEFAULT_SOURCE_POLICY,{headers:{accept:'application/json'}},[404]);
        const body=response.status===404?null:await readJsonLimited(response,DEFAULT_SOURCE_POLICY.maxResponseBytes);
        const missing=response.status===404 || (sourceId==='nvd-cve' && record(body).totalResults===0 && Array.isArray(record(body).vulnerabilities) && list(record(body).vulnerabilities).length===0);
        if(missing){
          await db.transaction(async tx=>{
            await tx.prepare("UPDATE enrichment_cycle_members SET satisfied_generation=?,checked_at=now(),retry_at=NULL,failures=0,outcome='not_found' WHERE cycle_id=? AND cve_id=?").bind(generation,cycle.id,id).run();
            await tx.prepare('UPDATE enrichment_queue SET checked_at=now(),retry_at=NULL,failures=0 WHERE cve_id=? AND source_id=?').bind(id,sourceId).run();
          });
          counts.unchanged++;fields.processed++;continue;
        }
        const normalized=sha?parseCveRecord(body,url):parseNvdRecord(body,`https://nvd.nist.gov/vuln/detail/${id}`);
        if(normalized.cveId!==id)throw new Error('Enrichment identity mismatch');
        const changed=await db.transaction(async tx=>{
          const changed=await saveCveEnrichment(tx,sourceId,runId,normalized);
          await tx.prepare('UPDATE enrichment_queue SET checked_at=now(),retry_at=NULL,failures=0 WHERE cve_id=? AND source_id=?').bind(id,sourceId).run();
          await tx.prepare('UPDATE enrichment_cycle_members SET satisfied_generation=?,checked_at=now(),retry_at=NULL,failures=0,outcome=? WHERE cycle_id=? AND cve_id=?').bind(generation,normalized.status,cycle.id,id).run();
          return changed;
        });counts[changed?'changed':'unchanged']++;
      } catch(error) {
        counts.failed++; errors.push(`${id}: ${error instanceof Error?error.message:'Enrichment failed'}`);
        await db.prepare("UPDATE enrichment_queue SET retry_at=now()+INTERVAL '1 hour',failures=failures+1 WHERE cve_id=? AND source_id=?").bind(id,sourceId).run();
        await db.prepare("UPDATE enrichment_cycle_members SET retry_at=now()+INTERVAL '1 hour',failures=failures+1 WHERE cycle_id=? AND cve_id=?").bind(cycle.id,id).run();
        // A rate limit must stop this batch, not start another request before its deadline.
        const retryAt=sourceCooldown(error);if(retryAt){await repository.deferSource(sourceId,retryAt);break;}
      }
      fields.processed++;
    }
    const progress=await enrichmentProgress(db,cycle);
    fields.boundHit=progress.remaining>0 || !progress.updatesComplete;
    fields.continuation=fields.boundHit ? await enrichmentPosition(db,cycle,progress.remaining) : null;
    if(progress.remaining && !progress.eligible && progress.retryAt)await repository.deferSource(sourceId,progress.retryAt);
    if(!fields.boundHit && !counts.failed)await db.transaction(async tx=>{
      const proof=await enrichmentProgress(tx,cycle);
      if(proof.remaining || !proof.updatesComplete)throw new Error('Enrichment completion changed during certification');
      await tx.prepare('UPDATE enrichment_cycles SET completed_at=now() WHERE id=? AND completed_at IS NULL').bind(cycle.id).run();
      const closed=await tx.prepare('SELECT member_count,completed_at FROM enrichment_cycles WHERE id=?').bind(cycle.id).first<{member_count:number;completed_at:string}>();
      await recordSourceCompletion(tx,{sourceId,ownerKind:'enrichment',ownerId:cycle.id,kind:cycle.kind,coverageStart:cycle.updates_from,coverageEnd:cycle.target_through,completedAt:closed!.completed_at,memberCount:Number(closed!.member_count),sourceRunId:runId});
    });
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
async function syncChangedCves(db:Database,source:EnrichmentSource,key:string|undefined,cycle:EnrichmentCycle) {
  const state=await db.prepare('SELECT completed_at,window_start,window_end,next_offset FROM enrichment_updates WHERE source_id=?').bind(source).first<{completed_at:string|null;window_start:string|null;window_end:string|null;next_offset:number}>();
  if(cycle.updates_covered_through && Date.parse(cycle.updates_covered_through)>=Date.parse(cycle.target_through))return;
  const since=state?.window_start??(cycle.updates_covered_through??cycle.updates_from);
  const until=state?.window_end??new Date(Math.min(Date.parse(cycle.target_through),Date.parse(since)+7*86400000)).toISOString();
  const updates:Array<{id:string;modified:string}>=[];
  let offset=0,complete=true;
  if(source==='cve-list-v5') {
    const sha=cycle.source_revision;if(!sha)throw new Error('CVE cycle revision is missing');
    const policy={...DEFAULT_SOURCE_POLICY,maxResponseBytes:64_000_000};
    const data=await readJsonLimited(await fetchWithPolicy(`https://raw.githubusercontent.com/CVEProject/cvelistV5/${sha}/cves/deltaLog.json`,policy),policy.maxResponseBytes);
    if(!Array.isArray(data))throw new Error('Invalid CVE delta log');
    for(const entry of data.map(record)) for(const change of [...list(entry.new),...list(entry.updated)].map(record)) {
      const id=validCve(change.cveId),modified=iso(change.dateUpdated);
      if(id&&modified&&modified>=since&&modified<=cycle.target_through)updates.push({id,modified});
    }
  }else{
    const url=new URL('https://services.nvd.nist.gov/rest/json/cves/2.0');
    url.searchParams.set('lastModStartDate',since);url.searchParams.set('lastModEndDate',until);url.searchParams.set('resultsPerPage','100');url.searchParams.set('startIndex',String(state?.next_offset??0));
    const data=record(await readJsonLimited(await nvdFetch(url.href,key),32_000_000));
    if(!Array.isArray(data.vulnerabilities)||!Number.isInteger(data.totalResults)||!Number.isInteger(data.startIndex))throw new Error('Invalid NVD modification page');
    for(const entry of data.vulnerabilities) {const cve=record(record(entry).cve),id=validCve(cve.id),modified=utc(cve.lastModified);if(!id||!modified)throw new Error('Invalid NVD modification identity');updates.push({id,modified});}
    offset=Number(data.startIndex)+data.vulnerabilities.length;complete=offset>=Number(data.totalResults);
    if(Number(data.startIndex)!==Number(state?.next_offset??0))throw new Error('NVD pagination offset mismatch');
    if(!complete&&!data.vulnerabilities.length)throw new Error('NVD pagination did not advance');
  }
  await db.transaction(async tx=>{
    await requireChangedMembers(tx,cycle,updates);
    // CVE delta logs are bounded history. Every retained record is reconciled for
    // this source, so an outage beyond the log cannot silently lose revisions.
    if(source==='cve-list-v5')await tx.prepare(`INSERT INTO enrichment_cycle_members(cycle_id,cve_id)
      SELECT ?,id FROM cves WHERE created_at<=?::timestamptz ON CONFLICT DO NOTHING`).bind(cycle.id,cycle.started_at).run();
    if(complete)await tx.prepare('UPDATE enrichment_cycles SET updates_covered_through=?,member_count=(SELECT COUNT(*) FROM enrichment_cycle_members WHERE cycle_id=?) WHERE id=?').bind(source==='cve-list-v5'?cycle.target_through:until,cycle.id,cycle.id).run();
    await tx.prepare("UPDATE enrichment_queue q SET checked_at=NULL FROM (SELECT value->>'id' id,MAX((value->>'modified')::timestamptz) modified FROM jsonb_array_elements(?::jsonb) GROUP BY value->>'id') u WHERE q.cve_id=u.id AND q.source_id=? AND q.checked_at<u.modified").bind(JSON.stringify(updates),source).run();
    await tx.prepare('INSERT INTO enrichment_updates(source_id,completed_at,window_start,window_end,next_offset) VALUES (?,?,?,?,?) ON CONFLICT(source_id) DO UPDATE SET completed_at=excluded.completed_at,window_start=excluded.window_start,window_end=excluded.window_end,next_offset=excluded.next_offset').bind(source,complete?until:state?.completed_at??null,complete?null:since,complete?null:until,complete?0:offset).run();
  });
}

async function enrichmentPosition(db:Database,cycle:EnrichmentCycle,remaining:number):Promise<string> {
  const updates=await db.prepare('SELECT window_start,window_end,next_offset,completed_at FROM enrichment_updates WHERE source_id=?').bind(cycle.source_id).first();
  return JSON.stringify({cycle:cycle.id,remaining,updates});
}
