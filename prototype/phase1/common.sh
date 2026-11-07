#!/usr/bin/env bash
# Phase 1 prototype: shared sandbox definition.
#
# This is deliberately a *test* environment, not the final security boundary.
# It uses read-only bind mounts of selected host runtime directories plus a
# private writable home and a single bind-mounted test project.
#
# Everything the agent sees under / is constructed here. There is no bind of
# the host /, /home, /root, /var or /mnt.
set -euo pipefail

BASE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
DEMO_DIR="$BASE_DIR/demo"
SANDBOX_HOME="$DEMO_DIR/home"
TEST_PROJECT="$DEMO_DIR/project"
SANDBOX_ETC="$BASE_DIR/etc"
RUN_DIR="$DEMO_DIR/run"
LOG_DIR="$DEMO_DIR/log"

# Host-side identity/display facts (discovered, not assumed).
HOST_USER=${HOST_USER:-rj}
HOST_UID=${HOST_UID:-$(id -u "$HOST_USER")}
HOST_GID=${HOST_GID:-$(id -g "$HOST_USER")}
HOST_HOME=$(getent passwd "$HOST_USER" | cut -d: -f6)
HOST_DISPLAY=${DISPLAY:-:0}

# OpenCode desktop installation discovered on this host.
OPENCODE_DIR=${OPENCODE_DIR:-/opt/OpenCode}
OPENCODE_BIN="$OPENCODE_DIR/ai.opencode"

mkdir -p "$SANDBOX_HOME" "$TEST_PROJECT" "$RUN_DIR/user1000" "$RUN_DIR/shm" "$RUN_DIR/tmp" "$LOG_DIR"
chmod 700 "$RUN_DIR/user1000"
chmod 1777 "$RUN_DIR/shm" "$RUN_DIR/tmp"

# Keep a realistic-looking but isolated home layout.
mkdir -p \
  "$SANDBOX_HOME/.config/opencode" \
  "$SANDBOX_HOME/.config/ai.opencode.desktop" \
  "$SANDBOX_HOME/.local/share/opencode" \
  "$SANDBOX_HOME/.local/state" \
  "$SANDBOX_HOME/.cache" \
  "$SANDBOX_HOME/projects" \
  "$SANDBOX_HOME/Documents"

# Minimal /etc, generated on the host. Do not bind the host /etc wholesale.
mkdir -p "$SANDBOX_ETC"
cat > "$SANDBOX_ETC/passwd" <<EOF
root:x:0:0:root:/root:/bin/bash
$HOST_USER:x:$HOST_UID:$HOST_GID:$HOST_USER:/home/$HOST_USER:/bin/bash
EOF
cat > "$SANDBOX_ETC/group" <<EOF
root:x:0:
$HOST_USER:x:$HOST_GID:
EOF
cat > "$SANDBOX_ETC/nsswitch.conf" <<'EOF'
passwd: files
group: files
shadow: files
hosts: files dns
networks: files
EOF
cat > "$SANDBOX_ETC/hostname" <<'EOF'
opencode-sandbox
EOF
cat > "$SANDBOX_ETC/hosts" <<'EOF'
127.0.0.1 localhost opencode-sandbox
::1 localhost ip6-localhost ip6-loopback
EOF
cat > "$SANDBOX_ETC/machine-id" <<'EOF'
0123456789abcdef0123456789abcdef
EOF

# sandbox_bwrap_common: populate BWRAP_ARGS with the namespace + mount layout.
# Callers append their command and execute bwrap.
sandbox_bwrap_common() {
  BWRAP_ARGS=(
    --unshare-all
    --share-net
    --die-with-parent
    --new-session
    --hostname opencode-sandbox
    --cap-drop ALL
    --proc /proc
    --dev /dev
    --bind "$RUN_DIR/tmp" /tmp
    --tmpfs /run
    --bind "$RUN_DIR/user1000" /run/user/1000
    --bind "$RUN_DIR/shm" /dev/shm
    --ro-bind /usr /usr
    --symlink usr/bin /bin
    --symlink usr/sbin /sbin
    --symlink usr/lib /lib
    --symlink usr/lib64 /lib64
    --ro-bind /opt/OpenCode /opt/OpenCode
    # Minimal host runtime configuration, individual files only.
    --ro-bind /etc/ssl /etc/ssl
    --ro-bind /etc/fonts /etc/fonts
    --ro-bind /etc/ld.so.cache /etc/ld.so.cache
    --ro-bind /etc/ld.so.conf /etc/ld.so.conf
    --ro-bind /etc/ld.so.conf.d /etc/ld.so.conf.d
    --ro-bind /etc/xdg /etc/xdg
    --ro-bind /etc/os-release /etc/os-release
    --ro-bind /etc/localtime /etc/localtime
    --ro-bind "$SANDBOX_ETC/passwd" /etc/passwd
    --ro-bind "$SANDBOX_ETC/group" /etc/group
    --ro-bind "$SANDBOX_ETC/nsswitch.conf" /etc/nsswitch.conf
    --ro-bind "$SANDBOX_ETC/hostname" /etc/hostname
    --ro-bind "$SANDBOX_ETC/hosts" /etc/hosts
    --ro-bind "$SANDBOX_ETC/machine-id" /etc/machine-id
    --ro-bind /etc/resolv.conf /etc/resolv.conf
    --ro-bind /etc/mime.types /etc/mime.types
    # Writable isolated home: only the demo home dir is exposed.
    --bind "$SANDBOX_HOME" "/home/$HOST_USER"
    # The one real project, exposed at a virtual path.
    --bind "$TEST_PROJECT" "/home/$HOST_USER/projects/demo"
    # X11 socket + cookie: narrowest practical display access for Phase 1.
    --ro-bind "/tmp/.X11-unix/X0" "/tmp/.X11-unix/X0"
    --ro-bind "$HOST_HOME/.Xauthority" "/home/$HOST_USER/.Xauthority"
    --setenv HOME "/home/$HOST_USER"
    --setenv USER "$HOST_USER"
    --setenv LOGNAME "$HOST_USER"
    --setenv SHELL /bin/bash
    --setenv PATH "/usr/local/bin:/usr/bin:/bin"
    --setenv DISPLAY "$HOST_DISPLAY"
    --setenv XAUTHORITY "/home/$HOST_USER/.Xauthority"
    --setenv XDG_SESSION_TYPE x11
    --setenv XDG_RUNTIME_DIR /run/user/1000
    --setenv LANG "${LANG:-C.UTF-8}"
    --chdir "/home/$HOST_USER"
  )
  if [ -d /etc/gtk-3.0 ]; then
    BWRAP_ARGS+=(--ro-bind /etc/gtk-3.0 /etc/gtk-3.0)
  fi
  if [ -e /etc/drirc ]; then
    BWRAP_ARGS+=(--ro-bind /etc/drirc /etc/drirc)
  fi
  if [ -d /dev/dri ]; then
    # Optional GPU access; remove this line for a stricter prototype.
    BWRAP_ARGS+=(--ro-bind /dev/dri /dev/dri)
  fi
}

# Enter the sandbox with an arbitrary command. Exported for sibling scripts.
sandbox_exec() {
  sandbox_bwrap_common
  exec bwrap "${BWRAP_ARGS[@]}" -- "$@"
}
