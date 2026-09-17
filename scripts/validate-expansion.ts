import {createVendorAdapter, type AdapterEnvironment} from '../lib/ingestion/source-registry';
import {DEFAULT_SOURCE_POLICY} from '../lib/ingestion/contracts';
import {sanitizeText} from '../lib/ingestion/safety';
import {validateNormalizedAdvisory} from '../lib/ingestion/pipeline';
import {rollingWindowStart} from '../lib/ingestion/operational-policy';
import {writeFile,mkdir,readFile} from 'node:fs/promises';
const ids=process.argv.slice(2);const reports=[];
for(const id of ids) {
 const report:{source:string;status:string;documents?:unknown[];error?:string}={source:id,status:'failed'};
 try {
  const adapter=createVendorAdapter(id,process.env as AdapterEnvironment);if(!adapter)throw new Error('Not a vendor adapter');
  const ctx={fetch,since:rollingWindowStart().toISOString(),until:new Date().toISOString(),policy:{...DEFAULT_SOURCE_POLICY,...adapter.policy}};
  const refs=adapter.discoverPage?(await adapter.discoverPage(ctx)).refs:await adapter.discover(ctx);
  if(!refs.length)throw new Error('No usable advisory references returned');
  const documents=[];
  for(const ref of refs.slice(0,2)) {
   const raw=await adapter.fetch(ref,ctx);const normalized=await adapter.normalize(raw,{observedAt:new Date().toISOString(),sanitizeText});
   for(const item of normalized)validateNormalizedAdvisory(item,adapter);
   documents.push({url:ref.url,cves:normalized.reduce((n,a)=>n+a.cves.length,0),products:normalized.reduce((n,a)=>n+a.affectedProducts.length,0),remediations:normalized.reduce((n,a)=>n+a.remediations.length,0)});
  }
  if(documents.some(d=>!d.cves))throw new Error('Sample lacks CVE mappings');
  report.status='sample-validated';report.documents=documents;
 }catch(error){report.error=error instanceof Error?error.message:'Validation failed';}
 reports.push(report);console.log(JSON.stringify(report));
}
await mkdir('work/source-expansion',{recursive:true});
const observedAt=new Date().toISOString();
const path='work/source-expansion/live-validation.json';
let previous:{source:string}[]=[];
try { previous=JSON.parse(await readFile(path,'utf8')).reports??[]; } catch { /* First validation run. */ }
const current=reports.map(report=>({...report,observedAt}));
await writeFile(path,JSON.stringify({observedAt,reports:[...previous.filter(report=>!ids.includes(report.source)),...current]},null,2));
if(reports.some(report=>report.status==='failed'))process.exitCode=1;
