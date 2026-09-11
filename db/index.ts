import { Pool, types, type PoolClient } from 'pg';
import { bindParameters, statement, type Database, type Statement, type StatementResult } from './database';

// Preserve existing API wire values independent of the host timezone and pg defaults.
types.setTypeParser(1082, value => value); // date
for (const oid of [1114, 1184]) types.setTypeParser(oid, value => new Date(value).toISOString());
for (const oid of [114, 3802]) types.setTypeParser(oid, value => value); // JSON parsed by domain boundary
// int8 can exceed JS precision. Fail instead of silently corrupting counts.
types.setTypeParser(20, value => {
  const number = Number(value);
  if (!Number.isSafeInteger(number)) throw new Error('PostgreSQL integer exceeds the safe JSON number range');
  return number;
});

export class PostgresDatabase implements Database {
  constructor(readonly pool: Pool, private readonly client?: PoolClient) {}
  prepare(sql: string) { return statement(sql, (text, values) => this.execute(text, values)); }
  private async execute(sql: string, values: unknown[]): Promise<StatementResult> {
    const result = await (this.client ?? this.pool).query(bindParameters(sql), values);
    return { results: result.rows, meta: { changes: result.rowCount ?? 0 }, success: true };
  }
  async batch(statements: Statement[]): Promise<StatementResult[]> {
    return this.transaction(async db => {
      const results: StatementResult[] = [];
      for (const item of statements) results.push(await db.prepare(item.sql).bind(...item.values).run());
      return results;
    });
  }
  async transaction<T>(operation: (db: Database) => Promise<T>, isolation: 'read committed' | 'repeatable read' = 'read committed'): Promise<T> {
    // Nested batches participate in the caller's transaction, never commit independently.
    if (this.client) return operation(this);
    const client = await this.pool.connect();
    try {
      await client.query(`BEGIN ISOLATION LEVEL ${isolation.toUpperCase()}`);
      const result = await operation(new PostgresDatabase(this.pool, client));
      await client.query('COMMIT');
      return result;
    } catch (error) { await client.query('ROLLBACK'); throw error; }
    finally { client.release(); }
  }
  async close() { await this.pool.end(); }
}

export function connectDatabase(connectionString: string, readOnly = false): PostgresDatabase {
  if (!connectionString) throw new Error('A PostgreSQL connection URL is required');
  const pool = new Pool({ connectionString, max: readOnly ? 10 : 4, connectionTimeoutMillis: 5000,
    idleTimeoutMillis: 30000, statement_timeout: readOnly ? 15000 : 120000,
    options: `-c timezone=UTC -c default_transaction_read_only=${readOnly ? 'on' : 'off'}`,
    application_name: readOnly ? 'patch-public' : 'patch-ingestion' });
  pool.on('error', error => console.error(JSON.stringify({ event: 'postgres_pool_error', code: (error as Error & { code?: string }).code })));
  return new PostgresDatabase(pool);
}
