#!/bin/bash
set -euo pipefail
: "${TAILSCALE_BIN:=/usr/local/bin/tailscale}"
: "${TAILSCALE_SOCKET:=/var/run/tailscaled.socket}"
: "${TAILSCALE_HOSTNAME:?Set the stable short hostname used by the dashboard URLs}"
if [[ ! "$TAILSCALE_HOSTNAME" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]]; then
  echo 'TAILSCALE_HOSTNAME must be a lowercase DNS label of at most 63 characters' >&2
  exit 64
fi
# macOS can otherwise select an installed GUI client on a different tailnet.
ts() { "$TAILSCALE_BIN" --socket="$TAILSCALE_SOCKET" "$@"; }
ts status >/dev/null
# Persist the published name instead of inheriting future macOS hostname changes.
ts set --hostname="$TAILSCALE_HOSTNAME"
# Distinct ports: Funnel is public, Serve is private.
ts serve --bg --tcp=5432 tcp://127.0.0.1:5432
ts serve --bg --https=8443 http://127.0.0.1:3002
ts funnel --bg --https=443 http://127.0.0.1:3001
ts serve status
ts funnel status
