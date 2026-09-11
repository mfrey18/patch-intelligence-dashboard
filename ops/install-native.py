#!/usr/bin/env python3
"""One-time administrator setup. Run after installing postgresql@18, node@24 and tailscale.
Secrets are generated locally, never printed. Does not publish Funnel or switch Pages.
"""
import json, os, pathlib, plistlib, pwd, secrets, shutil, subprocess, sys
ROOT = pathlib.Path('/Library/PatchIntelligence')
REPO = pathlib.Path(__file__).resolve().parent.parent

def run(*args, **kwargs):
    return subprocess.run([str(a) for a in args], check=True, **kwargs)

def account(name, home):
    try: return pwd.getpwnam(name)
    except KeyError: pass
    occupied = {entry.pw_uid for entry in pwd.getpwall()}
    uid = next(value for value in range(400, 499) if value not in occupied)
    for key,value in [('UniqueID',str(uid)),('PrimaryGroupID','20'),('NFSHomeDirectory',str(home)),('UserShell','/usr/bin/false'),('IsHidden','1'),('RealName',name)]:
        run('/usr/bin/dscl','.','-create',f'/Users/{name}',key,value)
    return pwd.getpwnam(name)

def write(path, value, mode=0o600, uid=0):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value if isinstance(value,bytes) else value.encode())
    os.chmod(path,mode); os.chown(path,uid,20)

def daemon(label,args,user=None,calendar=None):
    config={'Label':label,'ProgramArguments':[str(a) for a in args],
        'EnvironmentVariables':{'LC_ALL':'en_US.UTF-8','LANG':'en_US.UTF-8'},
        'StandardOutPath':str(ROOT/'logs'/f'{label}.log'),'StandardErrorPath':str(ROOT/'logs'/f'{label}.err')}
    if user: config['UserName']=user
    if calendar: config['StartCalendarInterval']=calendar
    else: config.update({'RunAtLoad':True,'KeepAlive':True,'ThrottleInterval':10})
    path=pathlib.Path('/Library/LaunchDaemons')/f'{label}.plist'
    write(path,plistlib.dumps(config),0o644)
    return path

if os.geteuid()!=0: sys.exit('Run with sudo; this creates service accounts and launchd jobs.')
if (ROOT/'secrets/api.env').exists(): sys.exit('Host already initialized; use deploy-release.sh. Refusing to replace credentials.')
prefix=pathlib.Path('/opt/homebrew' if pathlib.Path('/opt/homebrew/bin/brew').exists() else '/usr/local')
pg=prefix/'opt/postgresql@18/bin'; node=prefix/'opt/node@24/bin/node'; ts=prefix/'opt/tailscale/bin'
npm=prefix/'opt/node@24/lib/node_modules/npm/bin/npm-cli.js'
for binary in [pg/'initdb',node,npm,ts/'tailscaled']:
    if not binary.exists(): sys.exit(f'Missing {binary}; install dependencies first.')
if subprocess.run(['pgrep','-x','Tailscale'],stdout=subprocess.DEVNULL).returncode==0:
    sys.exit('Quit the GUI Tailscale client before switching to the system tailscaled service.')
ROOT.mkdir(mode=0o755,parents=True,exist_ok=True)
app=account('_patchapp',ROOT); db=account('_patchdb',ROOT/'postgres')
for directory in ['runtime','ops','releases','logs','secrets','backups','postgres','postgres/socket','tailscale','incoming','app-cache']:
    (ROOT/directory).mkdir(parents=True,exist_ok=True)
os.chmod(ROOT/'secrets',0o711)
os.chown(ROOT/'app-cache',app.pw_uid,20);os.chmod(ROOT/'app-cache',0o700)
os.chmod(ROOT/'backups',0o711);os.chmod(ROOT/'tailscale',0o700)
for directory in ['postgres','postgres/socket']:
    os.chown(ROOT/directory,db.pw_uid,20);os.chmod(ROOT/directory,0o700)
for binary in ['pg_dump','pg_restore','psql','createdb','dropdb']:
    (ROOT/'runtime'/binary).symlink_to(pg/binary)
(ROOT/'runtime/node').symlink_to(node)
for file in (REPO/'ops').glob('*.sh'): shutil.copy2(file,ROOT/'ops'/file.name)
# Install the pinned package manager as the unprivileged service account.
# launchd must not depend on the interactive user's private runtime or PATH.
tooling=ROOT/'app-cache/tooling'
run('/usr/bin/sudo','-u','_patchapp','/usr/bin/env',f'PATH={node.parent}:/usr/bin:/bin',
    node,npm,'install','--prefix',tooling,'--cache',ROOT/'app-cache/npm',
    '--ignore-scripts','--no-audit','--no-fund','pnpm@10.34.5')
shutil.copytree(tooling/'node_modules/pnpm',ROOT/'runtime/pnpm-package')
(ROOT/'runtime/pnpm').symlink_to(ROOT/'runtime/pnpm-package/bin/pnpm.cjs')
writer,reader,owner=(secrets.token_hex(32) for _ in range(3))
config={'DATABASE_URL':f'postgresql://patch_writer:{writer}@127.0.0.1:5432/patch_intelligence','READ_DATABASE_URL':f'postgresql://patch_reader:{reader}@127.0.0.1:5432/patch_intelligence','INGEST_SECRET':secrets.token_hex(32),'PATCH_DATA_ROOT':str(ROOT),'PUBLIC_DASHBOARD_ORIGINS':'https://mfrey18.github.io','PRIVATE_API_BASE_URL':'http://127.0.0.1:3002'}
write(ROOT/'secrets/api.env',''.join(f'{key}={value}\n' for key,value in config.items()),uid=app.pw_uid)
write(ROOT/'secrets/migration.env',f'MIGRATION_DATABASE_URL=postgresql://patch_owner:{owner}@127.0.0.1:5432/patch_intelligence\n')
write(ROOT/'secrets/pg_service.conf',f'[backup]\nhost=127.0.0.1\nport=5432\ndbname=patch_intelligence\nuser=patch_owner\npassword={owner}\n[restore_admin]\nhost={ROOT}/postgres/socket\nuser=_patchdb\ndbname=postgres\n')
run('/usr/bin/sudo','-u','_patchdb',pg/'initdb','-D',ROOT/'postgres/data','--username=_patchdb','--auth-local=trust','--auth-host=scram-sha-256','--encoding=UTF8')
with (ROOT/'postgres/data/postgresql.conf').open('a') as f:
    f.write(f"\nlisten_addresses='127.0.0.1'\nport=5432\nunix_socket_directories='{ROOT}/postgres/socket'\nunix_socket_permissions=0700\ntimezone='UTC'\npassword_encryption='scram-sha-256'\nmax_connections=40\n")
# Start temporarily for initial roles. Socket is accessible only to root and _patchdb.
run('/usr/bin/sudo','-u','_patchdb',pg/'pg_ctl','-D',ROOT/'postgres/data','-l',ROOT/'postgres/bootstrap.log','start','-w')
try:
    role_sql=(REPO/'ops/postgres/roles.sql').read_text()
    # Hex passwords contain no quote/control characters; send through stdin, not argv.
    sql=f"\\set owner_password '{owner}'\n\\set writer_password '{writer}'\n\\set reader_password '{reader}'\n"+role_sql
    run(pg/'psql','-X','-h',ROOT/'postgres/socket','-U','_patchdb','-d','postgres','-v','ON_ERROR_STOP=1',input=sql.encode(),stdout=subprocess.DEVNULL)
finally: run('/usr/bin/sudo','-u','_patchdb',pg/'pg_ctl','-D',ROOT/'postgres/data','stop','-m','fast','-w')
jobs=[daemon('com.patch.postgres',[pg/'postgres','-D',ROOT/'postgres/data'],'_patchdb'),
      daemon('com.patch.api',[ROOT/'ops/run-api.sh'],'_patchapp'),
      daemon('com.patch.tailscaled',[ts/'tailscaled',f'--state={ROOT}/tailscale/tailscaled.state','--socket=/var/run/tailscaled.socket']),
      daemon('com.patch.backup',[ROOT/'ops/backup.sh'],calendar={'Hour':3,'Minute':0}),
      daemon('com.patch.restore-test',[ROOT/'ops/restore-test.sh'],calendar={'Day':1,'Hour':4,'Minute':0})]
for path in jobs:
    for suffix in ['log','err']:
        log=ROOT/'logs'/f'{path.stem}.{suffix}'
        uid=db.pw_uid if path.stem=='com.patch.postgres' else app.pw_uid if path.stem=='com.patch.api' else 0
        write(log,'',0o640,uid)
    if path.stem!='com.patch.api': run('/bin/launchctl','bootstrap','system',path)
run('/usr/bin/python3', REPO/'ops/complete-host-setup.py')
print('Host initialized. Add vendor secrets, deploy a release, authenticate tailscaled, then apply reviewed tailnet grants and configure Serve/Funnel. Credentials are in /Library/PatchIntelligence/secrets; not printed.')
