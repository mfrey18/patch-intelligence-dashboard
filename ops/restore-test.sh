#!/bin/bash
set -euo pipefail
ROOT=${PATCH_DATA_ROOT:-/Library/PatchIntelligence}
export PATH="$ROOT/runtime:$PATH"
export PGSERVICEFILE="$ROOT/secrets/pg_service.conf" PGSERVICE=restore_admin
backup=$(find "$ROOT/backups" -type f -name '*.dump' | sort | tail -1)
test -n "$backup"
(cd "$ROOT/backups" && shasum -a 256 -c "$(basename "$backup").sha256")
# Dedicated temporary database, never production. Unique name avoids concurrent cleanup races.
target="patch_restore_$(date +%s)_$$"
createdb "$target"
trap 'dropdb --if-exists "$target"' EXIT
pg_restore --exit-on-error --no-owner --no-acl --dbname="$target" "$backup"
psql --dbname="$target" -X --set=ON_ERROR_STOP=1 --command="SELECT count(*) FROM cves; SELECT count(*) FROM schema_migrations;" >/dev/null
umask 077
printf '{"completedAt":"%s","backup":"%s"}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(basename "$backup")" > "$ROOT/backups/latest-restore.json.tmp"
mv "$ROOT/backups/latest-restore.json.tmp" "$ROOT/backups/latest-restore.json"
