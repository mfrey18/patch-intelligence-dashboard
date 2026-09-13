#!/bin/bash
set -euo pipefail
ROOT=/Library/PatchIntelligence
set -a
# shellcheck source=/dev/null
source "$ROOT/secrets/api.env"
set +a
cd "$ROOT/current"
case "${1:-}" in
  seed) exec "$ROOT/runtime/node" --import tsx scripts/seed.ts ;;
  bootstrap) exec "$ROOT/runtime/node" scripts/bootstrap.mjs ;;
  check) exec "$ROOT/runtime/node" scripts/cutover-check.mjs ;;
  *) echo 'Usage: run-job.sh seed|bootstrap|check' >&2; exit 2 ;;
esac
