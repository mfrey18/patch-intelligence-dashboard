import type { Database } from '../../../db/database';
import type { IngestResult } from '../contracts';
import { DEFAULT_SOURCE_POLICY } from '../contracts';
import { fetchWithPolicy, readJsonLimited, sanitizeText, sourceCooldown } from '../safety';
import { record, list, validCve, iso } from '../adapters/utils';
import { PostgresIngestionRepository } from '../postgres-repository';
import { sha256 } from '../hash';

export const VULNCHECK_URL='https://api.vulncheck.com/v3/backup/vulncheck-kev';
export const VULNCHECK_PUBLIC_URL='https://www.vulncheck.com/kev';
export interface VulnCheckEntry {cveId:string;dateAdded:string;modifiedAt:string|null;description:string|null;name:string|null;vendor:string|null;product:string|null;ransomware:string|null;evidence:Array<{url:string;date:string|null}>;exploitLinks:string[];}
export function parseVulnCheckSnapshot(value:unknown):VulnCheckEntry[] {
  const rows=Array.isArray(value)?value:record(value).data;
  if(!Array.isArray(rows)||!rows.length)throw new Error('VulnCheck snapshot is empty or incomplete');
  const entries:VulnCheckEntry[]=[]; const seen=new Set<string>();
  for(const raw of rows) {
    const row=record(raw), dateAdded=iso(row.date_added), modifiedAt=iso(row._timestamp)??null;
    if(!dateAdded || Date.parse(dateAdded)>Date.now()+86400000 || !Array.isArray(row.cve)||!row.cve.length)throw new Error('Invalid VulnCheck entry');
    const evidence=list(row.vulncheck_reported_exploitation).map(item=> {
      const e=record(item); if(typeof e.url!=='string'||!/^https:\/\//.test(e.url))throw new Error('Invalid exploitation evidence URL');
      return {url:e.url,date:iso(e.date_added)??null};
    });
    for(const value of row.cve) {
      const cveId=validCve(value); if(!cveId||seen.has(cveId))throw new Error('Invalid or duplicate VulnCheck CVE'); seen.add(cveId);
      entries.push({cveId,dateAdded,modifiedAt,description:sanitizeText(row.shortDescription)??null,name:sanitizeText(row.vulnerabilityName)??null,vendor:sanitizeText(row.vendorProject)??null,product:sanitizeText(row.product)??null,ransomware:sanitizeText(row.knownRansomwareCampaignUse)??null,evidence,exploitLinks:list(row.vulncheck_xdb).map(item=>record(item).xdb_url).filter((v):v is string=>typeof v==='string'&&/^https:\/\//.test(v))});
    }
  }
  return entries;
}
export async function publishVulnCheckSnapshot(db:Database,runId:string,entries:VulnCheckEntry[]) {
  return db.transaction(async tx=> {
    const previous=await tx.prepare('SELECT cve_id,content_hash,active,source_modified_at FROM vulncheck_entries').all<{cve_id:string;content_hash:string;active:boolean;source_modified_at:string|null}>();
    const active=previous.results.filter(r=>r.active).length;
    if(active>100&&entries.length<active*.9)throw new Error('VulnCheck snapshot shrank unexpectedly; last good snapshot retained');
    const known=new Map(previous.results.map(r=>[r.cve_id,r])); const now=new Date().toISOString();
    const counts={discovered:entries.length,inserted:0,changed:0,unchanged:0,failed:0};
    for(const entry of entries) {
      const hash=await sha256(entry), old=known.get(entry.cveId);
      if(old?.source_modified_at&&entry.modifiedAt&&entry.modifiedAt<old.source_modified_at)throw new Error('VulnCheck timestamp regressed');
      const changed=!old||old.content_hash!==hash||!old.active;
      counts[!old?'inserted':changed?'changed':'unchanged']++;
      await tx.prepare('INSERT INTO cves(id,created_at,updated_at) VALUES (?,?,?) ON CONFLICT DO NOTHING').bind(entry.cveId,now,now).run();
      await tx.prepare('INSERT INTO vulncheck_entries(cve_id,active,date_added,source_modified_at,payload,content_hash,source_run_id,first_observed_at,last_observed_at) VALUES (?,TRUE,?,?,?::jsonb,?,?,?,?) ON CONFLICT(cve_id) DO UPDATE SET active=TRUE,date_added=excluded.date_added,source_modified_at=excluded.source_modified_at,payload=excluded.payload,content_hash=excluded.content_hash,source_run_id=excluded.source_run_id,last_observed_at=excluded.last_observed_at,removed_at=NULL').bind(entry.cveId,entry.dateAdded,entry.modifiedAt,JSON.stringify(entry),hash,runId,now,now).run();
      if(changed) {
        // Retire corrected evidence only for an entry actually present in a complete snapshot.
        await tx.prepare("UPDATE exploit_evidence SET status='withdrawn',last_observed_at=? WHERE cve_id=? AND source_id='vulncheck-kev'").bind(now,entry.cveId).run();
        const evidence=[{url:VULNCHECK_PUBLIC_URL,date:entry.dateAdded},...entry.evidence];
        for(const e of evidence) await tx.prepare("INSERT INTO exploit_evidence(id,cve_id,source_id,evidence_type,status,evidence_date,evidence_url,summary,first_observed_at,last_observed_at) VALUES (?,?,'vulncheck-kev','known_exploitation','confirmed',?,?,?,?,?) ON CONFLICT(cve_id,source_id,evidence_type,evidence_url) DO UPDATE SET status='confirmed',evidence_date=excluded.evidence_date,summary=excluded.summary,last_observed_at=excluded.last_observed_at").bind(`${entry.cveId}:vulncheck:${(await sha256(e.url)).slice(0,20)}`,entry.cveId,e.date?.slice(0,10)??null,e.url,'Reported exploitation — VulnCheck KEV',now,now).run();
        await tx.prepare("INSERT INTO intelligence_changes(id,source_run_id,entity_type,entity_id,cve_id,change_type,observed_at,summary) VALUES (?,?,'vulncheck_entry',?,?,'EXPLOITATION_STATUS_CHANGED',?,?)").bind(crypto.randomUUID(),runId,entry.cveId,entry.cveId,now,`${entry.cveId} VulnCheck exploitation evidence updated`).run();
      }
    }
    const present = new Set(entries.map(entry => entry.cveId));
    counts.changed += previous.results.filter(row => row.active && !present.has(row.cve_id)).length;
    await tx.prepare('UPDATE vulncheck_entries SET active=FALSE,removed_at=?,last_observed_at=?,source_run_id=? WHERE active=TRUE AND NOT(cve_id=ANY(?::text[]))').bind(now,now,runId,entries.map(e=>e.cveId)).run();
    // Absence from a catalog is not evidence that historical exploitation never happened.
    return counts;
  });
}
export async function ingestVulnCheck(db:Database,token?:string,key?:string):Promise<IngestResult> {
  const repository=new PostgresIngestionRepository(db),startedAt=new Date().toISOString();
  const {runId,reused}=await repository.beginRun('vulncheck-kev',key,{mode:'delta',maxItems:1});
  const result={sourceId:'vulncheck-kev',runId,startedAt,completedAt:startedAt,status:'unchanged' as IngestResult['status'],mode:'delta' as const,window:{},processed:0,continuation:null,boundHit:false,counts:{discovered:0,inserted:0,changed:0,unchanged:0,failed:0},errors:[] as string[]};
  if(reused)return result;
  try {
    if(!token)throw new Error('VulnCheck Community API token is not configured');
    const policy={...DEFAULT_SOURCE_POLICY,maxResponseBytes:64_000_000};
    const response=await fetchWithPolicy(VULNCHECK_URL,policy,{headers:{authorization:`Bearer ${token}`,accept:'application/json'},redirect:'error'});
    const envelope=record(await readJsonLimited(response,policy.maxResponseBytes));
    const download=record(list(envelope.data)[0]).url;
    if(typeof download!=='string')throw new Error('VulnCheck backup URL unavailable');
    const url=new URL(download);
    if(url.protocol!=='https:'||url.username||url.password||!(url.hostname.endsWith('.vulncheck.com')||url.hostname.endsWith('.amazonaws.com')))throw new Error('Unapproved VulnCheck snapshot origin');
    const snapshot=await readJsonLimited(await fetchWithPolicy(download,policy,{redirect:'error'}),policy.maxResponseBytes);
    result.counts=await publishVulnCheckSnapshot(db,runId,parseVulnCheckSnapshot(snapshot));
    result.processed=result.counts.discovered;result.status=result.counts.inserted+result.counts.changed?'success':'unchanged';
  }catch(error){result.status='failed';result.counts.failed++;result.errors.push(error instanceof Error?error.message:'VulnCheck ingestion failed');const retryAt=sourceCooldown(error);if(retryAt)await repository.deferSource('vulncheck-kev',retryAt);}
  result.completedAt=new Date().toISOString();await repository.finishRun(runId,result);return result;
}
