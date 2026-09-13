#!/bin/bash
# Administrator-reviewed rehearsal: back up production, restore only to a disposable
# database, then retain the exact verified dump and current immutable release identity.
set -euo pipefail
umask 077
ROOT=/Library/PatchIntelligence
cd "$(dirname "$0")/.."
[ "$(id -u)" = 0 ] || { echo 'Administrator access required' >&2; exit 1; }
release=$(basename "$(readlink "$ROOT/current")")
[[ "$release" =~ ^[a-f0-9]{40}$ ]] || exit 1
[ "$(readlink "$ROOT/current")" = "$ROOT/releases/$release" ] || exit 1
# Reject a writable or non-root-owned rollback application before creating evidence.
/usr/bin/python3 - "$ROOT/releases/$release" <<'PY'
import os,pathlib,stat,sys
root=pathlib.Path(sys.argv[1])
for path in [root,*root.rglob('*')]:
    info=path.lstat()
    if stat.S_ISLNK(info.st_mode):
        if not path.resolve().is_relative_to(root): raise SystemExit('Release symlink escapes retained release')
    elif info.st_uid != 0 or info.st_mode & 0o222:
        raise SystemExit('Rollback release is not root-owned and immutable')
for name in ('server/index.ts','package.json','pnpm-lock.yaml'):
    if not (root/name).is_file(): raise SystemExit('Rollback release incomplete')
PY
bash "$ROOT/ops/backup.sh"
bash "$ROOT/ops/restore-test.sh"
# Bind evidence to the dump actually restored, not whichever file is newest later.
/usr/bin/python3 - "$ROOT" "$release" <<'PY'
import datetime,hashlib,json,os,pathlib,shutil,subprocess,sys
root=pathlib.Path(sys.argv[1]);release=sys.argv[2]
restored=json.loads((root/'backups/latest-restore.json').read_text())
name=restored['backup']
if pathlib.Path(name).name != name or not name.endswith('.dump'): raise SystemExit('Invalid restored backup identity')
source=root/'backups'/name
checksum=(source.with_name(name+'.sha256')).read_text().split()[0]
def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''): h.update(block)
    return h.hexdigest()
if digest(source)!=checksum: raise SystemExit('Restored backup checksum changed')
# Rehearse the exact dump again with assertions, beyond the installed table-presence check.
env=dict(os.environ,PGSERVICEFILE=str(root/'secrets/pg_service.conf'),PGSERVICE='restore_admin',PGOPTIONS='-c statement_timeout=60000')
target=f'patch_restore_verify_{os.getpid()}_{int(datetime.datetime.now().timestamp())}'
def pg(binary,*args):
    return subprocess.run([str(root/'runtime'/binary),*args],env=env,check=True,text=True,capture_output=True,timeout=180).stdout
pg('createdb',target)
try:
    pg('pg_restore','--exit-on-error','--no-owner','--no-acl','--dbname='+target,str(source))
    sql="""SELECT json_build_object(
      'cveCount',(SELECT count(*) FROM cves),
      'migrationCount',(SELECT count(*) FROM schema_migrations),
      'projectionState',(SELECT row_to_json(s) FROM dashboard_projection_state s WHERE id='current'),
      'metrics',(SELECT json_build_object('total',count(*),'critical',count(*) FILTER(WHERE severity_rank=4),
        'high',count(*) FILTER(WHERE severity_rank=3),'knownExploited',count(*) FILTER(WHERE known_exploited),
        'kev',count(*) FILTER(WHERE kev),'zeroDay',count(*) FILTER(WHERE zero_day),
        'patchAvailable',count(*) FILTER(WHERE patch_available),'p1',count(*) FILTER(WHERE priority='P1'),
        'p2',count(*) FILTER(WHERE priority='P2'),'p3',count(*) FILTER(WHERE priority='P3'),
        'microsoft',count(*) FILTER(WHERE strpos(vendor_ids,'|microsoft|')>0),
        'cisco',count(*) FILTER(WHERE strpos(vendor_ids,'|cisco|')>0)) FROM cve_dashboard_facts))"""
    validation=json.loads(pg('psql','--dbname='+target,'-X','-A','-t','--set=ON_ERROR_STOP=1','--command='+sql))
    state=validation.pop('projectionState')
    metrics=validation['metrics']
    if validation['cveCount']<=0 or validation['migrationCount']<=0 or metrics['total']<=0:
        raise SystemExit('Restored database is empty or unmigrated')
    if not state or state['status']!='published' or state['parity_status']!='passed' or state['cve_count']!=metrics['total']:
        raise SystemExit('Restored projection state/count/parity is invalid')
    parity=state['parity_json']
    if isinstance(parity,str): parity=json.loads(parity)
    if parity.get('status')!='passed' or parity.get('canonical')!=metrics or parity.get('projected')!=metrics:
        raise SystemExit('Restored actual projection metrics differ from published parity evidence')
    validation.update(projectionStatus=state['status'],parityStatus=state['parity_status'],projectionGeneratedAt=state['generated_at'],actualMetricsMatchPublishedCanonicalAndProjected=True)
finally:
    pg('dropdb','--if-exists',target)
# Prove compatibility with this checkout's PostgreSQL migration baseline.
def migration_hashes(directory):
    return {str(p.relative_to(directory)):digest(p) for p in directory.rglob('*') if p.is_file()}
retained_migrations=migration_hashes(root/'releases'/release/'postgres-migrations')
candidate_migrations=migration_hashes(pathlib.Path.cwd()/'postgres-migrations')
if not retained_migrations or retained_migrations!=candidate_migrations:
    raise SystemExit('Candidate and retained PostgreSQL migration baselines differ')
validation.update(migrationHashes=retained_migrations,candidateMigrationMatch=True,temporaryDatabaseRemoved=True)
stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
retained=root/'rollback'/stamp
retained.mkdir(parents=True,mode=0o700)
os.chmod(retained.parent,0o700)
shutil.copyfile(source,retained/name);os.chmod(retained/name,0o600)
if digest(retained/name)!=checksum: raise SystemExit('Retained backup copy failed verification')
(retained/(name+'.sha256')).write_text(f'{checksum}  {name}\n')
manifest={'preparedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'applicationRelease':release,'applicationPath':str(root/'releases'/release),'backup':name,'backupSha256':checksum,'restoreVerifiedAt':restored['completedAt'],'restoreMethod':'pg_restore --exit-on-error into disposable database; cves and schema_migrations queries; database removed','retainedDirectory':str(retained),'restoredDatabaseValidation':validation,'retention':'Retained outside automatic 14-day backup cleanup; preserve through observation and rollback window','limitations':['Local copy does not survive device loss','Database restore is an explicit recovery operation with potential loss of records after backup','Application rollback requires schema compatibility; no database downgrade is automatic']}
(retained/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps(manifest,indent=2))
PY
