import { readFile, readdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { connectDatabase } from '../db/index';
import type { Database } from '../db/database';

export async function migrate(db: Database) {
  await db.transaction(async tx => {
    await tx.prepare('SELECT pg_advisory_xact_lock(783400)').run();
    await tx.prepare('CREATE TABLE IF NOT EXISTS schema_migrations (name text PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())').run();
    const directory = new URL('../postgres-migrations/', import.meta.url);
    for (const name of (await readdir(directory)).filter(name => name.endsWith('.sql')).sort()) {
      const sql = await readFile(new URL(name, directory), 'utf8');
      const checksum = createHash('sha256').update(sql).digest('hex');
      const previous = await tx.prepare('SELECT checksum FROM schema_migrations WHERE name=?').bind(name).first<{ checksum: string }>();
      if (previous) { if (previous.checksum !== checksum) throw new Error(`Applied migration changed: ${name}`); continue; }
      for (const part of sql.split('--> statement-breakpoint')) if (part.trim()) await tx.prepare(part).run();
      await tx.prepare('INSERT INTO schema_migrations(name,checksum) VALUES (?,?)').bind(name, checksum).run();
    }
  });
}
if (process.argv[1]?.endsWith('/migrate.ts')) {
  const db = connectDatabase(process.env.MIGRATION_DATABASE_URL ?? '');
  try { await migrate(db); console.log('PostgreSQL migrations applied'); } finally { await db.close(); }
}
