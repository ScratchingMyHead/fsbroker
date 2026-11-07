#!/usr/bin/env bash
# Phase 2 setup: build the read-only /etc view and the runtime directories.
#
# Nothing here needs root and nothing modifies the host. The /etc copy is a
# snapshot taken on every run; re-run this script after host changes that the
# GUI needs (CA certificates, fonts, linker config).
set -euo pipefail

BASE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd -- "$BASE_DIR/../.." && pwd)   # /home/rj/fsbroker
RUN_DIR="$ROOT_DIR/run"
PLACEHOLDERS="$BASE_DIR/placeholders"
ETC_VIEW="$BASE_DIR/etc-view"

HOST_USER=${HOST_USER:-rj}
HOST_UID=${HOST_UID:-$(id -u "$HOST_USER")}
HOST_GID=${HOST_GID:-$(id -g "$HOST_USER")}

mkdir -p "$RUN_DIR/vroot" "$RUN_DIR/tmp" "$RUN_DIR/shm" "$RUN_DIR/user1000"
chmod 700 "$RUN_DIR/user1000"
chmod 1777 "$RUN_DIR/tmp" "$RUN_DIR/shm"

for d in proc dev tmp run; do
  mkdir -p "$PLACEHOLDERS/$d"
done

rm -rf "$ETC_VIEW"
mkdir -p "$ETC_VIEW"

# Small generated files: no host /etc/shadow, no keys.
cat > "$ETC_VIEW/passwd" <<EOF
root:x:0:0:root:/root:/bin/bash
$HOST_USER:x:$HOST_UID:$HOST_GID:$HOST_USER:/home/agent:/bin/bash
EOF
cat > "$ETC_VIEW/group" <<EOF
root:x:0:
$HOST_USER:x:$HOST_GID:
EOF
cat > "$ETC_VIEW/nsswitch.conf" <<'EOF'
passwd: files
group: files
shadow: files
hosts: files dns
networks: files
EOF
cat > "$ETC_VIEW/hostname" <<'EOF'
opencode-sandbox
EOF
cat > "$ETC_VIEW/hosts" <<'EOF'
127.0.0.1 localhost opencode-sandbox
::1 localhost ip6-localhost ip6-loopback
EOF
cat > "$ETC_VIEW/machine-id" <<'EOF'
0123456789abcdef0123456789abcdef
EOF

# Copy (not symlink) the host files the GUI needs. Symlinks into /usr would be
# clamped to the /etc mount root by RESOLVE_IN_ROOT, so dereference them.
copy_path() {
  local src=$1
  [ -e "$src" ] || return 0
  local dest="$ETC_VIEW/${src#/etc/}"
  mkdir -p "$(dirname "$dest")"
  if [ -d "$src" ]; then
    cp -rL --preserve=mode,timestamps "$src/." "$dest/" 2>/dev/null || true
  else
    cp -L --preserve=mode,timestamps "$src" "$dest" 2>/dev/null || true
  fi
}

copy_path /etc/ssl
copy_path /etc/fonts
copy_path /etc/ld.so.cache
copy_path /etc/ld.so.conf
copy_path /etc/ld.so.conf.d
copy_path /etc/xdg
copy_path /etc/os-release
copy_path /etc/localtime
copy_path /etc/mime.types
copy_path /etc/gtk-3.0
copy_path /etc/drirc
copy_path /etc/resolv.conf

echo "etc-view: $(du -sh "$ETC_VIEW" | cut -f1)"
echo "run dir:  $RUN_DIR"
