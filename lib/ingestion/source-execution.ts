import { AsyncLocalStorage } from 'node:async_hooks';
import { statement, type Database, type StatementResult } from '../../db/database';

export class SourceBudgetExpired extends Error { constructor() { super('Source processing budget exhausted; work remains resumable'); } }
export class SourceLeaseLost extends Error { constructor() { super('Source lease expired or ownership changed'); } }
interface Operation { signal: AbortSignal; deadline: number }
const currentOperation = new AsyncLocalStorage<Operation>();
export function sourceOperationSignal(): AbortSignal | undefined { return currentOperation.getStore()?.signal; }
export function checkSourceBudget(): void {
  const operation=currentOperation.getStore();
  if(operation && (operation.signal.aborted || Date.now()>=operation.deadline)) throw new SourceBudgetExpired();
}
/** A request can stop waiting, but only this scope may keep committing source state. */
export async function runSourceOperation<T>(budgetMs:number,signal:AbortSignal, operation:()=>Promise<T>):Promise<T> {
  const controller=new AbortController();
  const timer=setTimeout(()=>controller.abort(),budgetMs);
  const combined=AbortSignal.any([signal,controller.signal]);
  let cancel:()=>void=()=>{};
  const interrupted=new Promise<never>((_resolve,reject)=>{cancel=()=>reject(new SourceBudgetExpired());combined.addEventListener('abort',cancel,{once:true});if(combined.aborted)cancel();});
  try { return await Promise.race([currentOperation.run({signal:combined,deadline:Date.now()+budgetMs},operation),interrupted]); }
  finally {clearTimeout(timer);combined.removeEventListener('abort',cancel);}
}
export async function sourceSleep(milliseconds:number):Promise<void> {
  checkSourceBudget();
  const signal=sourceOperationSignal();
  await new Promise<void>((resolve,reject)=>{
    const cancel=()=>{clearTimeout(timer);reject(new SourceBudgetExpired());};
    const timer=setTimeout(()=>{signal?.removeEventListener('abort',cancel);resolve();},milliseconds);
    signal?.addEventListener('abort',cancel,{once:true});
    if(signal?.aborted)cancel();
  });
  checkSourceBudget();
}

/**
 * Every mutation, including nested repository/enrichment transactions, locks and
 * checks the source lease in the SAME transaction. A stolen/expired lease or
 * elapsed request budget therefore cannot publish records or advance a cursor.
 * Reads remain ordinary queries. No SQL dialect or data shape is translated.
 */
export function leasedSourceDatabase(db:Database,sourceId:string,holder:string):Database {
  const assertLease=async(tx:Database)=>{
    checkSourceBudget();
    const lease=await tx.prepare('SELECT holder,expires_at FROM ingestion_leases WHERE source_id=? FOR UPDATE').bind(sourceId).first<{holder:string;expires_at:string}>();
    if(!lease || lease.holder!==holder || Date.parse(lease.expires_at)<=Date.now())throw new SourceLeaseLost();
  };
  const wrap=(connection:Database,insideTransaction=false):Database=>{
    const guarded:Database={
      prepare(sql){return statement(sql,async(text,values):Promise<StatementResult>=>{
        checkSourceBudget();
        const execute=async(tx:Database)=>tx.prepare(text).bind(...values).run();
        if(insideTransaction || /^\s*(SELECT|EXPLAIN)\b/i.test(text))return execute(connection);
        return connection.transaction(async tx=>{await assertLease(tx);const result=await execute(tx);await assertLease(tx);return result;});
      });},
      async transaction(operation,isolation){
        if(insideTransaction)return operation(guarded);
        return connection.transaction(async tx=>{await assertLease(tx);const result=await operation(wrap(tx,true));await assertLease(tx);return result;},isolation);
      },
      async batch(items){return guarded.transaction(async tx=>{const results:StatementResult[]=[];for(const item of items)results.push(await tx.prepare(item.sql).bind(...item.values).run());return results;});},
    };
    return guarded;
  };
  return wrap(db);
}
