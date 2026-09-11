/** SQL is PostgreSQL. The fluent statement API only binds parameters; it never translates dialects. */
export interface StatementResult<T = Record<string, unknown>> {
  results: T[];
  meta: { changes: number };
  success: boolean;
}
export interface Statement {
  readonly sql: string;
  readonly values: unknown[];
  bind(...values: unknown[]): Statement;
  first<T = Record<string, unknown>>(): Promise<T | null>;
  all<T = Record<string, unknown>>(): Promise<StatementResult<T>>;
  run(): Promise<StatementResult>;
}
export interface Database {
  prepare(sql: string): Statement;
  batch(statements: Statement[]): Promise<StatementResult[]>;
  transaction<T>(operation: (db: Database) => Promise<T>, isolation?: 'read committed' | 'repeatable read'): Promise<T>;
}

/** Convert anonymous bind markers outside quoted strings/identifiers to PostgreSQL parameters. */
export function bindParameters(sql: string): string {
  let index = 0;
  let quote = '';
  let output = '';
  for (let i = 0; i < sql.length; i++) {
    const char = sql[i];
    if (quote) {
      output += char;
      if (char === quote) {
        if (sql[i + 1] === quote) output += sql[++i];
        else quote = '';
      }
    } else if (char === "'" || char === '"') { quote = char; output += char; }
    else output += char === '?' ? `$${++index}` : char;
  }
  return output;
}

export type Execute = (sql: string, values: unknown[]) => Promise<StatementResult>;
export function statement(sql: string, execute: Execute, values: unknown[] = []): Statement {
  return {
    sql, values,
    bind: (...bound) => statement(sql, execute, bound),
    async first<T>() { return ((await execute(sql, values)).results[0] as T | undefined) ?? null; },
    async all<T>() { return await execute(sql, values) as StatementResult<T>; },
    run: () => execute(sql, values),
  };
}
