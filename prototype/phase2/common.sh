#!/usr/bin/env bash
# Phase 2: the sandbox root is the FUSE virtual root.
#
# Unlike Phase 1 there are no per-directory host binds for /usr, /opt or /etc:
# the only source of the sandbox root is the FUSE mount. bubblewrap adds the
# runtime filesystems (/proc, /dev, /tmp, /run) and the X11 socket on top.
set -euo pipefail

BASE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd -- "$BASE_DIR/../.." && pwd)   # /home/rj/fsbroker

VROOT="$ROOT_DIR/run/vroot"
RUN_DIR="$ROOT_DIR/run"
CONFIG="$BASE_DIR/vroot.toml"

HOST_USER=${HOST_USER:-rj}
HOST_HOME=${HOST_HOME:-$(getent passwd "$HOST_USER" | cut -d: -f6)}
HOST_DISPLAY=${DISPLAY:-:0}
OPENCODE_DIR=${OPENCODE_DIR:-/opt/OpenCode}
OPENCODE_BIN="$OPENCODE_DIR/ai.opencode"

require_mount() {
  if ! mountpoint -q "$VROOT"; then
    echo "the virtual root is not mounted at $VROOT" >&2
    echo "run $BASE_DIR/mount.sh first" >&2
    exit 1
  fi
}

sandbox_bwrap_common() {
  require_mount
  # bwrap needs the mount point of every --bind to exist inside the tree it is
  # building; the read-only virtual root will not create one, so make the
  # parent of the request client in the (writable) agent home first.
  mkdir -p "$ROOT_DIR/prototype/phase1/demo/home/.local/bin"
  BWRAP_ARGS=(
    --unshare-all
    --share-net
    --die-with-parent
    --new-session
    --hostname opencode-sandbox
    --cap-drop ALL

    # The virtual root replaces the host root entirely.
    --bind "$VROOT" /

    # Runtime filesystems bubblewrap provides itself.
    --proc /proc
    --dev /dev
    --bind "$RUN_DIR/tmp" /tmp
    --tmpfs /run
    --bind "$RUN_DIR/user1000" /run/user/1000
    --bind "$RUN_DIR/shm" /dev/shm

    # The request socket and its client are the one part of the broker that is
    # deliberately reachable from inside: they can only *ask* to add a folder,
    # and the broker still has to approve. The host-only control socket is not
    # bound in. The client goes in the agent's own PATH, read-only so the agent
    # cannot tamper with it (it could only ask anyway).
    --ro-bind "$RUN_DIR/request.sock" "/run/user/1000/fsbroker-request.sock"
    --ro-bind "$ROOT_DIR/broker/fsbroker-request" "/home/agent/.local/bin/fsbroker-request"

    # Display access is a known Phase 1 gap; unchanged here on purpose.
    --ro-bind "/tmp/.X11-unix/X0" "/tmp/.X11-unix/X0"
    --ro-bind "$HOST_HOME/.Xauthority" "/home/agent/.Xauthority"

    --setenv HOME "/home/agent"
    --setenv USER "$HOST_USER"
    --setenv LOGNAME "$HOST_USER"
    --setenv SHELL /bin/bash
    --setenv PATH "/home/agent/.local/bin:/usr/local/bin:/usr/bin:/bin"
    --setenv DISPLAY "$HOST_DISPLAY"
    --setenv XAUTHORITY "/home/agent/.Xauthority"
    --setenv XDG_SESSION_TYPE x11
    --setenv XDG_RUNTIME_DIR /run/user/1000
    --setenv LANG "${LANG:-C.UTF-8}"
    --chdir "/home/agent"
  )

  # Provider keys the opencode config refers to as {env:...}. Pass them through
  # only when they are set on the host, so the sandboxed instance matches the
  # main one without making an empty key.
  if [ -n "${OPENROUTER_API_KEY:-}" ]; then
    BWRAP_ARGS+=(--setenv OPENROUTER_API_KEY "$OPENROUTER_API_KEY")
  fi
  if [ -n "${VLLM_API_KEY:-}" ]; then
    BWRAP_ARGS+=(--setenv VLLM_API_KEY "$VLLM_API_KEY")
  fi
}

sandbox_exec() {
  sandbox_bwrap_common
  exec bwrap "${BWRAP_ARGS[@]}" -- "$@"
}
