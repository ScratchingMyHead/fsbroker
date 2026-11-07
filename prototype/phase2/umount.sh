#!/usr/bin/env bash
# Stop the virtual root daemon.
set -euo pipefail

BASE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd -- "$BASE_DIR/../.." && pwd)
VROOT="$ROOT_DIR/run/vroot"
PIDFILE="$ROOT_DIR/run/vroot.pid"

# `mountpoint -q` is false for a daemon that died while mounted (the stat
# returns ENOTCONN), so also look for a stale entry in the mount table. A lazy
# unmount is enough to clear it and let the daemon be replaced.
if mountpoint -q "$VROOT" || mount | grep -q " $VROOT "; then
  fusermount3 -uz "$VROOT" 2>/dev/null || umount -l "$VROOT" 2>/dev/null || true
fi

if [ -f "$PIDFILE" ]; then
  PID=$(cat "$PIDFILE")
  if kill -0 "$PID" 2>/dev/null; then
    kill "$PID" 2>/dev/null || true
  fi
  rm -f "$PIDFILE"
fi

echo "unmounted $VROOT"
