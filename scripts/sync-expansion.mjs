import { appendFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { runDailyIngestion, writeGithubResult } from './daily-ingestion.mjs';

export const EXISTING_DAILY_SOURCES = new Set(['microsoft-msrc-csaf','cisco-psirt-csaf','palo-alto-psirt-csaf','mozilla-mfsa-yaml','cisa-kev','first-epss']);
export function selectExpansionSources(sources, requested) {
  const selected=sources.filter(s=>requested ? s.id===requested : s.enabled && s.readiness==='production' && !EXISTING_DAILY_SOURCES.has(s.id));
  if(requested && !selected.length)throw new Error('Unknown source');
  return selected.map(s=>s.id);
}
async function internalCall(env,path,body) {
  if(!env.API_ORIGIN || !env.INGEST_SECRET)throw new Error('API_ORIGIN and INGEST_SECRET are required');
  const response=await fetch(new URL(path,env.API_ORIGIN),{headers:{authorization:`Bearer ${env.INGEST_SECRET}`,'content-type':'application/json'},method:body?'POST':'GET',body:body?JSON.stringify(body):undefined,signal:AbortSignal.timeout(140000)});
  if(!response.ok)throw new Error(`Internal API returned ${response.status}`);
  return response.json();
}
export async function refreshExpansionProjection(env, call=internalCall) {
  const errors=[];
  try {
    const epss=await call(env,'/api/internal/ingest',{sources:['first-epss'],mode:'delta',idempotencyKey:`expansion-epss:${Date.now()}`,refreshProjection:false});
    const run=epss.results?.[0];
    if(!['success','unchanged'].includes(run?.status) || run?.counts?.failed || run?.boundHit)throw new Error('EPSS membership refresh did not complete');
  } catch(error) { errors.push(error); }
  try {
    const projection=await call(env,'/api/internal/projection',{});
    if(projection.status!=='success')throw new Error('Dashboard projection refresh failed');
  } catch(error) { errors.push(error); }
  if(errors.length)throw new AggregateError(errors,errors.map(error=>error.message).join(' | '));
}
export async function main(env=process.env) {
  if(env.REFRESH_PROJECTION==='true') {
    await refreshExpansionProjection(env);
    return;
  }

  const {sources}=await internalCall(env,'/api/internal/sources');
  const selected=selectExpansionSources(sources,env.SOURCE_ID);
  if(env.LIST_SOURCES==='true') {
    const matrix=JSON.stringify({source:selected});
    if(env.GITHUB_OUTPUT)await appendFile(env.GITHUB_OUTPUT,`matrix=${matrix}\nhas_sources=${selected.length>0}\n`);
    console.log(matrix);return;
  }
  // Scheduled Actions jobs pass exactly one ID; source isolation is enforced there.
  // Local explicit invocations retain bounded sequential compatibility.
  let failed=false;
  for(const sourceId of selected){
    const summary=await runDailyIngestion({env,sourceId,maxBatches:Number(env.MAX_ATTEMPTS??env.SOURCE_MAX_BATCHES??50),log:event=>console.log(JSON.stringify(event))});
    await writeGithubResult(summary);
    if(summary.alert)console.log(`::warning title=Ingestion attention::${sourceId}: ${summary.error??summary.reason}`);
    failed ||= summary.status==='failed';
  }
  if(failed)process.exitCode=1;
}
if(process.argv[1] && import.meta.url===pathToFileURL(process.argv[1]).href) {
  try{await main();}catch(error){console.error(error instanceof Error?error.message:String(error));process.exitCode=1;}
}
