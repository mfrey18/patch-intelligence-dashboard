#!/bin/bash
# Root-owned launchd entry; application code always runs as _patchapp.
set -euo pipefail
ROOT=/Library/PatchIntelligence
result=0
sudo -u _patchapp "$ROOT/runtime/node" --env-file="$ROOT/secrets/api.env" "$ROOT/ops/bootstrap.mjs" || result=$?
"$ROOT/ops/backup.sh"
"$ROOT/ops/restore-test.sh"
printf 'Bootstrap finished with exit status %s; backup restore passed.\n' "$result"
exit "$result"
