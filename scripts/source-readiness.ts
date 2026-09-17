import {connectDatabase} from '../db/index';
import {setSourceReadiness} from '../lib/ingestion/source-readiness';
import type {SourceReadiness} from '../lib/ingestion/source-catalog';
const [id,state,...reason]=process.argv.slice(2);
if(!id||!state)throw new Error('Usage: source-readiness.ts SOURCE STATE [REASON]');
const db=connectDatabase(process.env.DATABASE_URL??'');
try {await setSourceReadiness(db,id,state as SourceReadiness,reason.join(' ')||null);console.log(JSON.stringify({sourceId:id,readiness:state}));} finally {await db.close();}
