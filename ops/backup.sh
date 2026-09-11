#!/bin/bash
set -euo pipefail
umask 077
ROOT=${PATCH_DATA_ROOT:-/Library/PatchIntelligence}
export PATH="$ROOT/runtime:$PATH"
export PGSERVICEFILE="$ROOT/secrets/pg_service.conf" PGSERVICE=backup
mkdir -p "$ROOT/backups"
# Atomic marker creation only after dump integrity checks finish.
stamp=$(date -u +%Y%m%dT%H%M%SZ)
partial="$ROOT/backups/$stamp.dump.partial"
trap 'rm -f "$partial"' EXIT
pg_dump --format=custom --no-owner --no-acl --file="$partial"
pg_restore --list "$partial" >/dev/null
mv "$partial" "$ROOT/backups/$stamp.dump"
(cd "$ROOT/backups" && shasum -a 256 "$stamp.dump" > "$stamp.dump.sha256")
printf '{"completedAt":"%s","file":"%s.dump"}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$stamp" > "$ROOT/backups/latest-success.json.tmp"
mv "$ROOT/backups/latest-success.json.tmp" "$ROOT/backups/latest-success.json"
find "$ROOT/backups" -type f \( -name '*.dump' -o -name '*.dump.sha256' \) -mtime +14 -delete
