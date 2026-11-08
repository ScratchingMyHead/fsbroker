#!/usr/bin/env bash
# Desktop menu entry point for the sandboxed OpenCode GUI.
#
# This is the file to copy and adapt. It is the only OpenCode-specific part;
# fsbroker itself is generic. Set the locations and the program, then point a
# menu item (or a shortcut) at this script.
set -uo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

RUN_DIR=${FSBROKER_RUN_DIR:-$HOME/fsbroker_opencode}
CONFIG=${FSBROKER_CONFIG:-$HOME/.config/fsbroker/vroot.toml}
HOME_HOST=${FSBROKER_HOME:-$RUN_DIR/home}

APP=${OPENCODE_BIN:-/opt/OpenCode/ai.opencode}
CLI=${OPENCODE_CLI:-/opt/OpenCode/resources/opencode-cli}
# The sandbox shares the host's network namespace, so the sandboxed instance
# needs its own OpenCode CLI service port (the host uses 49374).
PORT=${OPENCODE_PORT:-49474}

# Set the port once, in the sandbox home's opencode config. Never delete that
# file, or OpenCode falls back to the host port and fails to start.
conf="$HOME_HOST/.config/opencode/service.json"
if ! grep -q '"port"' "$conf" 2>/dev/null; then
  HOME="$HOME_HOST" \
  XDG_CONFIG_HOME="$HOME_HOST/.config" \
  XDG_DATA_HOME="$HOME_HOST/.local/share" \
  XDG_STATE_HOME="$HOME_HOST/.local/state" \
  "$CLI" service set port "$PORT" >/dev/null 2>&1 || true
fi
# Drop only the stale client pointer; the running service rewrites it.
rm -f "$HOME_HOST/.local/state/opencode/service.json"

exec "$ROOT/bin/fsbroker" \
  --run-dir "$RUN_DIR" \
  --config "$CONFIG" \
  --home "$HOME_HOST" \
  session -- "$APP" \
    --no-sandbox --disable-gpu --ozone-platform=x11 --remote-debugging-port=9333
