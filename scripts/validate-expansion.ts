import {createVendorAdapter, type AdapterEnvironment} from '../lib/ingestion/source-registry';
import {DEFAULT_SOURCE_POLICY, type AdvisoryRef} from '../lib/ingestion/contracts';
import {sanitizeText} from '../lib/ingestion/safety';
import {validateNormalizedAdvisory} from '../lib/ingestion/pipeline';
import {rollingWindowStart} from '../lib/ingestion/operational-policy';
import {runSourceOperation} from '../lib/ingestion/source-execution';
import {writeFile,mkdir,readFile} from 'node:fs/promises';

interface Sample {url:string;advisories:number;cves:number;products:number;remediations:number}
interface Report {source:string;status:'failed'|'sample-validated';historicalCoverage?:string;documents?:Sample[];error?:string}
const ids=process.argv.slice(2),reports:Report[]=[];
for(const id of ids) {
 const report:Report={source:id,status:'failed'};
 try {
  await runSourceOperation(180_000,new AbortController().signal,async()=>{
   const adapter=createVendorAdapter(id,process.env as AdapterEnvironment);if(!adapter)throw new Error('Not a vendor adapter');
   report.historicalCoverage=adapter.historicalCoverage??'unverified';
   const ctx={fetch,since:rollingWindowStart().toISOString(),until:new Date().toISOString(),policy:{...DEFAULT_SOURCE_POLICY,...adapter.policy}};
   const refs:AdvisoryRef[]=[];const seen=new Set<string>();
   if(adapter.discoverPage){
    let cursor:string|undefined;
    for(let page=0;page<10 && refs.length<16;page++){
     const found=await adapter.discoverPage(ctx,cursor);
     refs.push(...found.refs);
     if(!found.nextCursor)break;
     if(seen.has(found.nextCursor))throw new Error('Discovery pagination repeated a cursor');
     seen.add(found.nextCursor);cursor=found.nextCursor;
    }
   }else refs.push(...await adapter.discover(ctx));
   if(!refs.length)throw new Error('No usable advisory references returned');
   const documents:Sample[]=[];report.documents=documents;
   for(const ref of [...new Map(refs.map(ref=>[ref.id,ref])).values()].slice(0,16)) {
    const raw=await adapter.fetch(ref,ctx);const normalized=await adapter.normalize(raw,{observedAt:new Date().toISOString(),sanitizeText});
    for(const item of normalized)validateNormalizedAdvisory(item,adapter);
    documents.push({url:ref.url,advisories:normalized.length,cves:normalized.reduce((n,a)=>n+a.cves.length,0),products:normalized.reduce((n,a)=>n+a.affectedProducts.length,0),remediations:normalized.reduce((n,a)=>n+a.remediations.length,0)});
    if(documents.filter(d=>d.cves>0 && d.products>0 && d.remediations>0).length>=2)break;
   }
   const representative=documents.filter(d=>d.cves>0 && d.products>0 && d.remediations>0);
   if(representative.length<2)throw new Error('Bounded samples did not establish two representative advisories with explicit CVE, product and remediation mappings');
   report.status='sample-validated';
  });
 }catch(error){report.error=error instanceof Error?error.message:'Validation failed';}
 reports.push(report);console.log(JSON.stringify(report));
}
await mkdir('work/source-expansion',{recursive:true});
const observedAt=new Date().toISOString(),path='work/source-expansion/live-validation.json';
let previous:Report[]=[];
try { previous=JSON.parse(await readFile(path,'utf8')).reports??[]; } catch { /* First validation run. */ }
await writeFile(path,JSON.stringify({observedAt,reports:[...previous.filter(report=>!ids.includes(report.source)),...reports.map(report=>({...report,observedAt}))]},null,2));
if(reports.some(report=>report.status==='failed'))process.exitCode=1;
