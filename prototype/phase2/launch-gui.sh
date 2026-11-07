#!/usr/bin/env bash
# Launch the installed OpenCode desktop GUI inside the Phase 2 sandbox.
#
# The GUI's root is the FUSE virtual root; the only host directories it can
# reach are the ones mapped in vroot.toml.
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"

if [ ! -x "$OPENCODE_BIN" ]; then
  echo "OpenCode desktop binary not found at $OPENCODE_BIN" >&2
  exit 1
fi

STAMP=$(date +%Y%m%d-%H%M%S)
LOG_DIR="$ROOT_DIR/run/log"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/opencode-gui-$STAMP.log"

echo "Log:          $LOG_FILE"
echo "Virtual root: $VROOT"
echo "Mappings:     $CONFIG"

sandbox_bwrap_common
exec bwrap "${BWRAP_ARGS[@]}" -- "$OPENCODE_BIN" \
  --no-sandbox \
  --disable-gpu \
  --ozone-platform=x11 \
  --remote-debugging-port=9333 \
  "$@" 2>&1 | tee "$LOG_FILE"
