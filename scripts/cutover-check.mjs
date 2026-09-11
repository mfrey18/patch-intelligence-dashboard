import assert from 'node:assert/strict';
const origin=process.env.PRIVATE_API_BASE_URL;
assert.ok(origin && process.env.INGEST_SECRET,'Private API origin and INGEST_SECRET required');
const get=async(path)=>{
  const response=await fetch(new URL(path,origin),{headers:{Authorization:`Bearer ${process.env.INGEST_SECRET}`},signal:AbortSignal.timeout(30000)});
  assert.ok(response.ok,`${path} returned ${response.status}`);return response.json();
};
const [monitor,health]=await Promise.all([get('/api/internal/monitor'),get('/api/internal/health')]);
assert.notEqual(monitor.status,'unhealthy',JSON.stringify(monitor.alerts));
assert.equal(monitor.projection.parityStatus,'passed');assert.ok(monitor.projection.actualCount>0);
assert.equal(monitor.sources.length,6);assert.ok(monitor.sources.every(source=>source.lastSuccess));
assert.ok(monitor.dashboardCoreLatencyMs<1000,'Core query exceeds one second');
assert.equal(health.databaseEngine,'postgresql');assert.equal(health.backupStale,false,'Backup absent or stale');
assert.ok(health.lastRestoreAt && Date.now()-Date.parse(health.lastRestoreAt)<35*86400000,'Successful restore test required');
assert.ok(health.diskFreeBytes>5*1024**3,'At least 5 GiB free disk required');
if(process.env.PUBLIC_API_BASE_URL){
 const publicOrigin=process.env.PUBLIC_API_BASE_URL;
 const [dashboard,denied]=await Promise.all([fetch(`${publicOrigin}/api/dashboard?include=core&limit=1`,{signal:AbortSignal.timeout(30000)}),fetch(`${publicOrigin}/api/internal/health`,{signal:AbortSignal.timeout(30000)})]);
 assert.equal(dashboard.status,200);assert.equal(denied.status,404);assert.ok((await dashboard.json()).metrics.total>0);
}
console.log(JSON.stringify({status:'passed',capturedAt:health.capturedAt,projectionCount:monitor.projection.actualCount}));
