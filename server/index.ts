import { createServer, type IncomingMessage } from 'node:http';
import { refreshDashboardProjection } from '../lib/operations/dashboard-projection';
import { seedIngestionCatalog } from '../lib/ingestion/postgres-repository';
import { connectDatabase } from '../db/index';
import { handleApi, type Env } from './api';
import { ResponseCache } from './cache';

export async function readBody(request: IncomingMessage, maximum = 16384) {
  const chunks: Buffer[] = []; let size = 0;
  for await (const chunk of request) { size += chunk.length; if (size>maximum) throw new Error('body_too_large'); chunks.push(chunk); }
  return Buffer.concat(chunks);
}
export function createApiServer(env: Env, access: 'public' | 'private') {
  const server = createServer(async (incoming,outgoing) => {
    try {
      const method = incoming.method ?? 'GET';
      // Do not trust a caller-supplied host/proxy header for cache identity or auth.
      const url = new URL(incoming.url ?? '/', 'http://patch-api.local');
      const headers = new Headers();
      for (const name of ['authorization','origin','content-type','content-length','access-control-request-method','access-control-request-headers']) {
        const value = incoming.headers[name]; if (typeof value === 'string') headers.set(name,value);
      }
      const body = ['GET','HEAD'].includes(method) ? undefined : await readBody(incoming);
      const request = new Request(url, {method,headers,body});
      const response = await handleApi(request,env,access);
      outgoing.writeHead(response.status,Object.fromEntries(response.headers));
      outgoing.end(Buffer.from(await response.arrayBuffer()));
    } catch (error) {
      const tooLarge = error instanceof Error && error.message==='body_too_large';
      outgoing.writeHead(tooLarge?413:503,{'content-type':'application/json','cache-control':'no-store'});
      outgoing.end(JSON.stringify({error:tooLarge?'Request body is too large':'Service temporarily unavailable'}));
    }
  });
  server.requestTimeout=150000;server.headersTimeout=15000;server.keepAliveTimeout=5000;
  return server;
}
if (process.argv[1]?.endsWith('/server/index.ts')) {
  if (!process.env.INGEST_SECRET || process.env.INGEST_SECRET.length<32) throw new Error('INGEST_SECRET must have at least 32 characters');
  const reader=connectDatabase(process.env.READ_DATABASE_URL ?? '',true);
  const writer=connectDatabase(process.env.DATABASE_URL ?? '');
  await reader.prepare('SELECT 1').run();await writer.prepare('SELECT 1').run();
  await seedIngestionCatalog(writer);
  await refreshDashboardProjection(writer);
  const cache=new ResponseCache();
  const common={...process.env,cache};
  const servers=[createApiServer({...common,DB:reader},'public'),createApiServer({...common,DB:writer},'private')];
  servers[0].listen(Number(process.env.PUBLIC_PORT ?? 3001),'127.0.0.1');
  servers[1].listen(Number(process.env.PRIVATE_PORT ?? 3002),'127.0.0.1');
  let stopping=false;
  const stop=async()=>{if(stopping)return;stopping=true;await Promise.all(servers.map(server=>new Promise<void>(resolve=>server.close(()=>resolve()))));await Promise.all([reader.close(),writer.close()]);};
  process.on('SIGTERM',()=>void stop());process.on('SIGINT',()=>void stop());
  console.log(JSON.stringify({event:'api_started',publicPort:3001,privatePort:3002}));
}
