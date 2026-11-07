#!/usr/bin/env bash
# Start the virtual root daemon in the background.
set -euo pipefail

BASE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd -- "$BASE_DIR/../.." && pwd)
CRATE="$ROOT_DIR/vroot"
VROOT="$ROOT_DIR/run/vroot"
CONFIG="$BASE_DIR/vroot.toml"
LOG="$ROOT_DIR/run/vroot.log"
PIDFILE="$ROOT_DIR/run/vroot.pid"

if mountpoint -q "$VROOT"; then
  echo "already mounted at $VROOT"
  exit 0
fi
# A daemon that died while mounted leaves an ENOTCONN entry that `mountpoint`
# does not see; clear it before mounting over it.
if mount | grep -q " $VROOT "; then
  fusermount3 -uz "$VROOT" 2>/dev/null || umount -l "$VROOT" 2>/dev/null || true
fi

BIN="$CRATE/target/release/vroot"
if [ ! -x "$BIN" ]; then
  echo "daemon not built: $BIN" >&2
  echo "build it with: cargo build --release --manifest-path $CRATE/Cargo.toml" >&2
  exit 1
fi

mkdir -p "$VROOT"
"$BASE_DIR/setup.sh" >/dev/null

RUST_LOG=${RUST_LOG:-info}
RUST_LOG="$RUST_LOG" setsid nohup "$BIN" --config "$CONFIG" --mount-point "$VROOT" \
  >>"$LOG" 2>&1 &
echo $! > "$PIDFILE"

for _ in $(seq 1 50); do
  if mountpoint -q "$VROOT"; then
    echo "mounted at $VROOT (pid $(cat "$PIDFILE"))"
    echo "log: $LOG"
    exit 0
  fi
  sleep 0.1
done

echo "mount did not appear; see $LOG" >&2
tail -20 "$LOG" >&2 || true
exit 1
