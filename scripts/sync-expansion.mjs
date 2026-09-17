// Existing sources retain their daily jobs. Expansion/enrichment uses the same DB readiness catalog.
const base=process.env.API_ORIGIN;
if(!base||!process.env.INGEST_SECRET)throw new Error('API_ORIGIN and INGEST_SECRET are required');
const headers={authorization:`Bearer ${process.env.INGEST_SECRET}`,'content-type':'application/json'};
async function call(path,body){
 const response=await fetch(`${base}${path}`,{headers,method:body?'POST':'GET',body:body?JSON.stringify(body):undefined,signal:AbortSignal.timeout(140000)});
 if(!response.ok)throw new Error(`Internal API returned ${response.status}`);
 return response.json();
}
const {sources}=await call('/api/internal/sources');
const previous=new Set(['microsoft-msrc-csaf','cisco-psirt-csaf','palo-alto-psirt-csaf','mozilla-mfsa-yaml','cisa-kev','first-epss']);
const requested=process.env.SOURCE_ID;
if(process.env.CHECKPOINT_ID&&!requested)throw new Error('CHECKPOINT_ID requires an explicit SOURCE_ID');
const attempts=Number(process.env.MAX_ATTEMPTS??30);
const batchSize=Number(process.env.BATCH_SIZE??1);
if(!Number.isSafeInteger(attempts)||attempts<1||attempts>50)throw new Error('MAX_ATTEMPTS must be 1–50');
if(!Number.isSafeInteger(batchSize)||batchSize<1||batchSize>12)throw new Error('BATCH_SIZE must be 1–12');
const selected=sources.filter(s=>requested?s.id===requested:s.enabled&&s.readiness==='production'&&!previous.has(s.id));
if(requested&&!selected.length)throw new Error('Unknown source');
selected.sort((a,b)=>(a.kind==='cve_enrichment'?1:0)-(b.kind==='cve_enrichment'?1:0));
let failed=false,changed=false;
for(const source of selected){
 try {
  for(let attempt=0;attempt<attempts;attempt++){
   const mode=process.env.INGEST_MODE??'delta';
   const checkpointId=process.env.CHECKPOINT_ID??`expansion:${source.id}:${mode}:${new Date().toISOString().slice(0,10)}`;
   const response=await call('/api/internal/ingest',{sources:[source.id],mode,checkpointId,maxItems:batchSize,refreshProjection:false});
   const result=response.results?.[0];
   changed ||= Boolean(result?.counts?.inserted||result?.counts?.changed);
   if(!result||result.status==='failed'||result.counts?.failed)throw new Error(`Source batch failed (${source.id})`);
   console.log(JSON.stringify({source:source.id,status:result.status,counts:result.counts,checkpoint:result.checkpoint?.status,boundHit:result.boundHit}));
   if(result.status==='skipped')break;
   if(result.checkpoint ? result.checkpoint.status==='complete' : !result.boundHit)break;
  }
 }catch(error){failed=true;console.error(error.message);}
}
if(changed){
 // Re-run membership-sensitive EPSS publication after admitting new CVEs.
 const epss=await call('/api/internal/ingest',{sources:['first-epss'],mode:'delta',idempotencyKey:`expansion-epss:${Date.now()}`,refreshProjection:false});
 if(epss.results?.[0]?.counts?.failed||epss.results?.[0]?.status==='failed'){failed=true;console.error('EPSS membership refresh failed');}
 const projection=await call('/api/internal/projection',{});
 if(projection.status!=='success')throw new Error('Dashboard projection refresh failed');
}
if(failed)process.exitCode=1;
