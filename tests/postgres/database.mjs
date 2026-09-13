import { PGlite } from '@electric-sql/pglite';
import { bindParameters, statement } from '../../db/database.ts';
import { connectDatabase } from '../../db/index.ts';
import { migrate } from '../../scripts/migrate.ts';
export async function testDatabase() {
  if (process.env.TEST_DATABASE_URL) {
    const db = connectDatabase(process.env.TEST_DATABASE_URL);
    if (!new URL(process.env.TEST_DATABASE_URL).pathname.endsWith("_test")) throw new Error("TEST_DATABASE_URL database must end in _test; the test schema is reset");
    await db.prepare("DROP SCHEMA public CASCADE").run();
    await db.prepare("CREATE SCHEMA public").run();
    await migrate(db);
    return db;
  }
  const pg = new PGlite({ parsers: { 1082: value => value, 1184: value => new Date(value).toISOString(), 114: value => value, 3802: value => value } });
  function adapter(connection, nested = false) {
    const db = {
      prepare(sql) { return statement(sql, async (text, values) => {
        const result = await connection.query(bindParameters(text), values);
        return { results: result.rows, success: true, meta: { changes: result.affectedRows ?? 0 } };
      }); },
      async transaction(fn) { return nested ? fn(db) : pg.transaction(tx => fn(adapter(tx, true))); },
      async batch(items) { return db.transaction(async tx => { const results = []; for (const item of items) results.push(await tx.prepare(item.sql).bind(...item.values).run()); return results; }); },
      close: () => pg.close(),
    }; return db;
  }
  const db = adapter(pg);
  await migrate(db);
  return db;
}
