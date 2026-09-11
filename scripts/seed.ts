import { connectDatabase } from '../db/index';
import { seedIngestionCatalog } from '../lib/ingestion/postgres-repository';
const db=connectDatabase(process.env.DATABASE_URL ?? '');
try {await seedIngestionCatalog(db);console.log('Source catalog seeded');} finally {await db.close();}
