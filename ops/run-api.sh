#!/bin/bash
set -euo pipefail
ROOT=/Library/PatchIntelligence
set -a
# shellcheck source=/dev/null
source "$ROOT/secrets/api.env"
set +a
cd "$ROOT/current"
exec "$ROOT/runtime/node" --import tsx server/index.ts
