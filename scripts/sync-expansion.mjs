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
const selected=sources.filter(s=>requested?s.id===requested:s.enabled&&s.readiness==='production'&&!previous.has(s.id));
if(requested&&!selected.length)throw new Error('Unknown source');
selected.sort((a,b)=>(a.kind==='cve_enrichment'?1:0)-(b.kind==='cve_enrichment'?1:0));
let failed=false,changed=false;
for(const source of selected){
 try {
  for(let attempt=0;attempt<30;attempt++){
   const mode=process.env.INGEST_MODE??'delta';
   const checkpointId=`expansion:${source.id}:${mode}:${new Date().toISOString().slice(0,10)}`;
   const response=await call('/api/internal/ingest',{sources:[source.id],mode,checkpointId,maxItems:source.id==='oracle-cpu-csaf'?1:12,refreshProjection:false});
   const result=response.results?.[0];
   if(!result||result.status==='failed'||result.counts?.failed)throw new Error(`Source batch failed (${source.id})`);
   changed ||= Boolean(result.counts?.inserted||result.counts?.changed);
   console.log(JSON.stringify({source:source.id,status:result.status,counts:result.counts,checkpoint:result.checkpoint?.status,boundHit:result.boundHit}));
   if(result.status==='skipped')break;
   if(result.checkpoint ? result.checkpoint.status==='complete' : !result.boundHit)break;
  }
 }catch(error){failed=true;console.error(error.message);}
}
if(changed){
 // Re-run membership-sensitive EPSS publication after admitting new CVEs.
 await call('/api/internal/ingest',{sources:['first-epss'],mode:'delta',idempotencyKey:`expansion-epss:${Date.now()}`,refreshProjection:false});
 await call('/api/internal/projection',{});
}
if(failed)process.exitCode=1;
