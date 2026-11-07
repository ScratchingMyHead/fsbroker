#!/usr/bin/env bash
# Launch the sandboxed OpenCode GUI with its permission broker, as one unit:
#
#   1. mount the FUSE virtual root          (mount.sh)
#   2. start the prompt broker              (broker.sh start)
#   3. launch the GUI on that root          (launch-gui.sh, blocks)
#   4. when the GUI window closes: unmount and stop the broker
#
# Point a desktop menu item at this file. Output goes to run/log/run-opencode.log.
set -uo pipefail

ROOT="/home/rj/fsbroker"
P2="$ROOT/prototype/phase2"
BROKER="$ROOT/broker/broker.sh"
SB_HOME="$ROOT/prototype/phase1/demo/home"
LOG_DIR="$ROOT/run/log"
LOG="$LOG_DIR/run-opencode.log"
OPENCODE_CLI="/opt/OpenCode/resources/opencode-cli"
# The host OpenCode service owns the default 49374 on the shared loopback, so
# the sandboxed instance must use its own port. It is stored in the sandbox's
# .config/opencode/service.json and must be kept.
SANDBOX_SERVICE_PORT="49474"

mkdir -p "$LOG_DIR"
exec >>"$LOG" 2>&1

say() { printf '%s run-opencode: %s\n' "$(date -Is)" "$*"; }

# Only tear things down if this run brought them up, so a refused/aborted
# second launch can never unmount a session that is already running.
active=0
cleanup() {
  if [ "$active" != 1 ]; then
    say "nothing to clean up"
    return
  fi
  say "GUI finished — unmounting the virtual root and stopping the broker"
  "$P2/umount.sh" || true
  "$BROKER" stop || true
  say "done"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

say "start"

# Refuse a second instance: it could not bind the debug port and would
# otherwise unmount the session that is already running.
if pgrep -f "remote-debugging-port=933[3]" >/dev/null 2>&1; then
  say "a sandboxed OpenCode is already running; not starting another"
  exit 0
fi

# 1. Virtual root daemon. Idempotent: says "already mounted" and exits 0 if up.
if ! "$P2/mount.sh"; then
  say "mount failed; aborting"
  exit 1
fi
active=1

# 2. Prompt broker, in GUI mode.
if ! "$BROKER" start; then
  say "broker failed; aborting"
  exit 1
fi

# Wait until both sockets the sandbox needs exist before launching.
for _ in $(seq 1 50); do
  [ -S "$ROOT/run/request.sock" ] && [ -S "$ROOT/run/broker.sock" ] && break
  sleep 0.1
done
if [ ! -S "$ROOT/run/request.sock" ] || [ ! -S "$ROOT/run/broker.sock" ]; then
  say "sockets did not appear (daemon or broker not ready); aborting"
  exit 1
fi

# 3a. Make sure the sandbox's service port is set. This file must survive:
#     without it the instance falls back to 49374, which the host owns.
SERVICE_CONF="$SB_HOME/.config/opencode/service.json"
if ! grep -q '"port"' "$SERVICE_CONF" 2>/dev/null; then
  say "setting the sandbox service port to $SANDBOX_SERVICE_PORT"
  HOME="$SB_HOME" \
  XDG_CONFIG_HOME="$SB_HOME/.config" \
  XDG_DATA_HOME="$SB_HOME/.local/share" \
  XDG_STATE_HOME="$SB_HOME/.local/state" \
  "$OPENCODE_CLI" service set port "$SANDBOX_SERVICE_PORT" || true
fi

# 3b. Drop only the stale client pointer (url/token/pid); the service rewrites
#     it on start. Do NOT touch .config/opencode/service.json above.
rm -f "$SB_HOME/.local/state/opencode/service.json"

# 4. The GUI. launch-gui.sh execs bwrap in the foreground and returns when the
#    window is closed; the EXIT trap then runs the cleanup above.
say "launching the GUI (close the window to shut everything down)"
"$P2/launch-gui.sh"
