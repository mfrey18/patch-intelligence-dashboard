#!/bin/bash
# Forced command for the dedicated CI key. Never evaluate SSH_ORIGINAL_COMMAND.
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
readonly ROOT=/Library/PatchIntelligence
readonly requested=${SSH_ORIGINAL_COMMAND-}
case "$requested" in
  /usr/libexec/sftp-server|internal-sftp)
    # Modern scp uploads over SFTP. The account can write only to incoming and
    # ordinary temporary directories; its root-owned home and key cannot change.
    exec /usr/bin/env -i PATH="$PATH" HOME="$ROOT/deploy" \
      /usr/libexec/sftp-server -d "$ROOT/incoming" -u 077
    ;;
esac
if [[ "$requested" =~ ^sudo\ -n\ /Library/PatchIntelligence/ops/deploy-release\.sh\ ([a-f0-9]{40})$ ]]; then
  exec /usr/bin/env -i PATH="$PATH" HOME="$ROOT/deploy" \
    /usr/bin/sudo -n "$ROOT/ops/deploy-release.sh" "${BASH_REMATCH[1]}"
fi
printf '%s\n' 'This key permits release uploads and the deployment helper only.' >&2
exit 126
