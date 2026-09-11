#!/bin/bash
# Run as root from the installed, root-owned copy. Input is a trusted, tested checkout artifact.
set -euo pipefail
ROOT=/Library/PatchIntelligence
if [ "$(id -u)" != 0 ]; then echo 'Administrator access required' >&2; exit 1; fi
release=${1:?release SHA required}
[[ "$release" =~ ^[a-f0-9]{40}$ ]] || exit 1
archive="$ROOT/incoming/$release.tar.gz"
test -f "$archive"
destination="$ROOT/releases/$release"
test ! -e "$destination"
# Reject archive traversal and links before extraction; do not trust tar member names.
/usr/bin/python3 - "$archive" "$destination" <<'PY'
import os,pathlib,stat,sys,tarfile,tempfile
archive,destination=sys.argv[1:]
staging=pathlib.Path('/Library/PatchIntelligence/staging')
staging.mkdir(mode=0o700,exist_ok=True)
# Validate and extract the same root-owned snapshot, even if the upload changes.
with os.fdopen(os.open(archive,os.O_RDONLY|os.O_NOFOLLOW),'rb') as source:
    info=os.fstat(source.fileno())
    if not stat.S_ISREG(info.st_mode) or info.st_size>256*1024*1024: raise SystemExit('Invalid release archive')
    with tempfile.TemporaryFile(dir=staging) as snapshot:
        remaining=info.st_size
        while remaining:
            block=source.read(min(remaining,1024*1024))
            if not block: raise SystemExit('Incomplete release upload')
            snapshot.write(block);remaining-=len(block)
        snapshot.seek(0)
        with tarfile.open(fileobj=snapshot) as tar:
            members=tar.getmembers()
            if sum(member.size for member in members)>512*1024*1024: raise SystemExit('Release exceeds size limit')
            for member in members:
                path=pathlib.PurePosixPath(member.name)
                if path.is_absolute() or '..' in path.parts or not (member.isfile() or member.isdir()): raise SystemExit('Unsafe release archive')
                # Never honor archive-supplied identities, set-ID bits, or write
                # permissions for group/other while extracting as root.
                member.uid=0;member.gid=0;member.uname='';member.gname=''
                member.mode=0o755 if member.isdir() else member.mode & 0o755
            tar.extractall(destination)

PY
# Install with the service identity; never run npm lifecycle code as root.
chown -R _patchapp:staff "$destination"
cd "$destination"
sudo -u _patchapp env HOME="$ROOT/app-cache" XDG_CACHE_HOME="$ROOT/app-cache" XDG_DATA_HOME="$ROOT/app-cache" PATH="$ROOT/runtime:/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin" pnpm install --frozen-lockfile --ignore-scripts --store-dir "$ROOT/app-cache/pnpm-store"
set -a
# shellcheck source=/dev/null
source "$ROOT/secrets/migration.env"
set +a
sudo -u _patchapp --preserve-env=MIGRATION_DATABASE_URL "$ROOT/runtime/node" --import tsx scripts/migrate.ts
unset MIGRATION_DATABASE_URL
# Deployment metadata must never be writable by the running application.
chown -R root:staff "$destination"
chmod -R a-w "$destination"
previous=$(readlink "$ROOT/current" || true)
ln -s "$destination" "$ROOT/current.next"
mv -fh "$ROOT/current.next" "$ROOT/current"
if ! launchctl print system/com.patch.api >/dev/null 2>&1; then
  launchctl bootstrap system /Library/LaunchDaemons/com.patch.api.plist
else
  launchctl kickstart -k system/com.patch.api
fi
healthy=false
for _attempt in {1..15}; do
  if curl --connect-timeout 2 --max-time 5 --fail --silent 'http://127.0.0.1:3001/api/dashboard?include=core&limit=1' >/dev/null; then healthy=true; break; fi
  sleep 2
done
if [ "$healthy" != true ]; then
  if [ -n "$previous" ]; then ln -s "$previous" "$ROOT/current.rollback"; mv -fh "$ROOT/current.rollback" "$ROOT/current"; launchctl kickstart -k system/com.patch.api; fi
  echo 'Readiness failed; previous application release restored (schema remains forward-migrated).' >&2
  exit 1
fi
printf '%s\n' "$release" > "$ROOT/deployed-sha"
