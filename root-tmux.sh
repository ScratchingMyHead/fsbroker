#!/usr/bin/env bash
# root-tmux.sh — a root tmux inside the sandbox that the sandboxed agent can drive.
#
# You get the foreground client (status bar, keyboard); the agent gets the
# socket. The session is always named "sandbox-root", so the agent uses:
#
#   tmux -S /tmp/tmux-0/default send-keys -t sandbox-root '...' Enter
#   tmux -S /tmp/tmux-0/default capture-pane -p -t sandbox-root
#
# The panes are real uid 0 but see only the fsbroker virtual root: unmapped
# paths are ENOENT, read-only mounts still refuse writes, write prompts still
# come from the broker. Reaching the host takes a deliberate act (mknod, mount),
# not an accident — but note that anything the agent types here *is* root, so a
# single send-keys can do that on purpose.
#
# Environment:
#   FSBROKER_RUN_DIR   run directory   (default ~/fsbroker_opencode)
#   ATTACH=0           set it up but do not attach
set -euo pipefail

root=$(cd -- "$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")" && pwd)
run_dir=${FSBROKER_RUN_DIR:-$HOME/fsbroker_opencode}
session=sandbox-root
attach=${ATTACH:-1}
agent_user=$(id -un)

# Runs inside the sandbox as root, via `fsbroker root-shell`.
#   $1 session name   $2 user allowed to attach   $3 1 = attach
read -r -d '' inner <<'INNER' || true
set -u
session=$1
user=$2
cd /home/agent 2>/dev/null || cd /
dir=/tmp/tmux-$(id -u)
sock=$dir/default

# The pointers go into the pane, not to stdout: stdout is hidden the moment we
# attach, so a banner printed here would only be seen on exit.
tmux has-session -t "$session" 2>/dev/null || tmux new-session -d -s "$session" \
  "printf '%s\n' 'root-tmux: socket $sock' 'root-tmux: the agent uses -S, for example:' '  tmux -S $sock send-keys -t $session ... Enter' '  tmux -S $sock capture-pane -p -t $session'; exec \${SHELL:-/bin/bash}"

# The agent is a different uid, so it needs both a reachable socket and an
# entry in tmux's access list (3.4+). Both are re-applied on every run because
# a restarted server recreates its socket.
chgrp "$user" "$dir" 2>/dev/null && chmod 750 "$dir"
chgrp "$user" "$sock" 2>/dev/null && chmod 660 "$sock"
# `server-access` exists in 3.4+; -l is a cheap way to tell. The -a may fail
# harmlessly when we already own the server (it says so and there is nothing to
# grant), which is the normal case for a non-root test.
if tmux server-access -l >/dev/null 2>&1; then
  tmux server-access -aw "$user" 2>/dev/null || true
else
  echo "root-tmux: server-access not supported (tmux < 3.4); relying on socket permissions"
fi

[ "$3" = 1 ] || exit 0
exec tmux attach -t "$session"
INNER

exec "$root/bin/fsbroker" --run-dir "$run_dir" root-shell -- \
  bash -c "$inner" root-tmux "$session" "$agent_user" "$attach"
