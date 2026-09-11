#!/bin/bash
set -euo pipefail
: "${TAILSCALE_BIN:=/usr/local/bin/tailscale}"
"$TAILSCALE_BIN" status >/dev/null
# Distinct ports: Funnel is public, Serve is private.
"$TAILSCALE_BIN" serve --bg --tcp=5432 tcp://127.0.0.1:5432
"$TAILSCALE_BIN" serve --bg --https=8443 http://127.0.0.1:3002
"$TAILSCALE_BIN" funnel --bg --https=443 http://127.0.0.1:3001
"$TAILSCALE_BIN" serve status
"$TAILSCALE_BIN" funnel status
