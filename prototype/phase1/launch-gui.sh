#!/usr/bin/env bash
# Launch the installed OpenCode desktop GUI inside the Phase 1 sandbox.
#
# Usage:
#   ./launch-gui.sh [extra electron args]
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"

if [ ! -x "$OPENCODE_BIN" ]; then
  echo "OpenCode desktop binary not found at $OPENCODE_BIN" >&2
  exit 1
fi

STAMP=$(date +%Y%m%d-%H%M%S)
LOG_FILE="$LOG_DIR/opencode-gui-$STAMP.log"
echo "Log: $LOG_FILE"
echo "Sandbox home: $SANDBOX_HOME"
echo "Test project: $TEST_PROJECT -> /home/$HOST_USER/projects/demo"

sandbox_bwrap_common
exec bwrap "${BWRAP_ARGS[@]}" -- "$OPENCODE_BIN" \
  --no-sandbox \
  --disable-gpu \
  --ozone-platform=x11 \
  --remote-debugging-port=9333 \
  "$@" 2>&1 | tee "$LOG_FILE"
