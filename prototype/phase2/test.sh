#!/usr/bin/env bash
# Phase 2 test matrix: host-side checks, then the same checks through
# bubblewrap with the FUSE root mounted at /.
set -uo pipefail

BASE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd -- "$BASE_DIR/../.." && pwd)
VROOT="$ROOT_DIR/run/vroot"
BACKING="$ROOT_DIR/prototype/phase1/demo/project"
PROJECT="/home/rj/fsbroker/prototype/phase1/demo/project"

pass=0
fail=0
ok()  { printf 'PASS  %s\n' "$1"; pass=$((pass+1)); }
bad() { printf 'FAIL  %s\n' "$1"; fail=$((fail+1)); }
sb()  { "$BASE_DIR/enter.sh" -c "$1"; }

echo "=== host side: $VROOT ==="
if mountpoint -q "$VROOT"; then ok "virtual root is a mount point"; else bad "virtual root is not mounted"; fi
if [ -e "$VROOT/home/rj/.ssh" ]; then
  bad "unmapped /home/rj/.ssh must not exist"
else
  ok "unmapped /home/rj/.ssh is ENOENT"
fi

if [ -e "$VROOT/etc/shadow" ]; then
  bad "host /etc/shadow must not be reachable"
else
  ok "host /etc/shadow is ENOENT"
fi

LISTING=$(ls -A "$VROOT/home/rj" 2>/dev/null | tr '\n' ' ')
if [ "$LISTING" = ".config fsbroker su " ] || [ "$LISTING" = ".config fsbroker su" ]; then
  ok "/home/rj lists only the added subtrees ($LISTING)"
else
  bad "/home/rj leaks host entries: $LISTING"
fi

if [ -r "$VROOT/home/rj/su" ] && [ -r "$VROOT/home/rj/.config" ]; then
  ok "read-only home directories are readable"
else
  bad "read-only home directories are unreadable"
fi
if ! touch "$VROOT/home/rj/su/.fsbroker-write-test" 2>/dev/null; then
  rm -f /home/rj/su/.fsbroker-write-test
  ok "writes to read-only /home/rj/su are refused"
else
  bad "write to read-only /home/rj/su succeeded"
fi
if ! touch "$VROOT/home/rj/.config/.fsbroker-write-test" 2>/dev/null; then
  rm -f /home/rj/.config/.fsbroker-write-test
  ok "writes to read-only /home/rj/.config are refused"
else
  bad "write to read-only /home/rj/.config succeeded"
fi

echo
echo "=== runtime grants (host-only control socket) ==="
CTL="$BASE_DIR/vrootctl"
if "$CTL" ping 2>/dev/null | grep -qx "OK pong"; then
  ok "control socket answers PING"
else
  bad "control socket does not answer"
fi
"$CTL" clear >/dev/null 2>&1
if "$CTL" list 2>/dev/null | head -1 | grep -qx "OK 0"; then
  ok "grant table starts empty"
else
  bad "grant table is not empty at the start"
fi

if "$CTL" grant session /home/rj/su 2>/dev/null | grep -q "^OK granted session /home/rj/su"; then
  ok "session grant is accepted"
else
  bad "session grant was rejected"
fi
sleep 1.2   # entry TTL: let the kernel drop the read-only attributes
if touch "$VROOT/home/rj/su/.grant-probe" 2>/dev/null; then
  ok "session grant allows a write to a read-only mount"
else
  bad "session grant did not allow the write"
fi
rm -f /home/rj/su/.grant-probe
"$CTL" revoke /home/rj/su >/dev/null 2>&1
sleep 1.2
if ! touch "$VROOT/home/rj/su/.grant-probe" 2>/dev/null; then
  ok "revoke closes the grant again"
else
  bad "write still allowed after revoke"
fi
rm -f /home/rj/su/.grant-probe

"$CTL" grant once /home/rj/su >/dev/null 2>&1
sleep 1.2
if touch "$VROOT/home/rj/su/.once-a" 2>/dev/null; then
  ok "once grant allows the first write"
else
  bad "once grant did not allow the first write"
fi
if ! touch "$VROOT/home/rj/su/.once-b" 2>/dev/null; then
  ok "once grant is consumed by the first write"
else
  bad "once grant still allowed a second write"
fi
rm -f /home/rj/su/.once-a /home/rj/su/.once-b
if ! "$CTL" grant session relative/path 2>/dev/null | grep -q "^OK"; then
  ok "grants require an absolute path"
else
  bad "a relative grant path was accepted"
fi
"$CTL" clear >/dev/null 2>&1

if [ -r "$VROOT$PROJECT/hello.txt" ]; then
  ok "mapped project is readable at its real path"
else
  bad "mapped project is not readable at $PROJECT"
fi

echo "PROOF $(date -Is)" > "$VROOT$PROJECT/fuse-proof.txt" 2>/dev/null
if [ -f "$BACKING/fuse-proof.txt" ]; then
  ok "write through FUSE reached the real backing directory"
else
  bad "write through FUSE did not reach the backing directory"
fi

if { echo nope > "$VROOT/usr/nope.txt"; } 2>/dev/null; then
  bad "read-only /usr accepted a write"
else
  ok "read-only /usr refuses writes"
fi

if { echo nope > "$VROOT/nope.txt"; } 2>/dev/null; then
  bad "synthetic / accepted a write"
else
  ok "synthetic / refuses writes"
fi

# Symlink confinement is enforced by the kernel against the sandbox root, so it
# can only be tested from inside the sandbox (see the symlink section below).
# Reading the mount from the host at $VROOT resolves absolute link targets
# against the *host* root — that is the host looking in, not a confinement test.

if "$VROOT/bin/echo" exec-through-mount >/dev/null 2>&1; then
  ok "binaries served by the mount can be executed"
else
  bad "exec through the mount fails"
fi

echo
echo "=== inside bubblewrap (root = FUSE virtual root) ==="
if sb 'true' >/dev/null 2>&1; then ok "shell starts"; else bad "shell does not start"; fi
if sb 'ls / | grep -qx usr' >/dev/null 2>&1; then ok "root is the virtual root"; else bad "root is not the virtual root"; fi
if sb "cd \"$PROJECT\" && test \"\$(pwd)\" = \"$PROJECT\"" >/dev/null 2>&1; then
  ok "project directory has the real path inside"
else
  bad "project path differs inside the sandbox"
fi
if sb '/bin/echo exec-inside-ok' 2>/dev/null | grep -qx exec-inside-ok && \
   sb 'python3 -c "print(6*7)"' 2>/dev/null | grep -qx 42; then
  ok "exec and a dynamic runtime work inside the sandbox"
else
  bad "exec inside the sandbox fails"
fi
if sb "cat $PROJECT/hello.txt" >/dev/null 2>&1; then ok "project readable inside"; else bad "project unreadable inside"; fi
if sb 'test -r /home/rj/su && ls /home/rj/su >/dev/null && test -r /home/rj/.config' >/dev/null 2>&1; then
  ok "read-only home directories are readable inside"
else
  bad "read-only home directories are unreadable inside"
fi
if sb '! touch /home/rj/su/sandbox-nope' >/dev/null 2>&1; then
  ok "write to read-only /home/rj/su is refused inside"
else
  bad "write to read-only /home/rj/su succeeded inside"
fi
if sb '! test -e /home/rj/.ssh' >/dev/null 2>&1; then ok "unmapped path denied inside"; else bad "unmapped path visible inside"; fi
if sb '! test -e /etc/shadow' >/dev/null 2>&1; then ok "/etc/shadow denied inside"; else bad "/etc/shadow visible inside"; fi
if sb '! touch /usr/sandbox-nope' >/dev/null 2>&1; then ok "read-only /usr enforced inside"; else bad "read-only /usr not enforced"; fi

CTL="$BASE_DIR/vrootctl"
if sb '! test -e /home/rj/fsbroker/run/vroot.sock' >/dev/null 2>&1; then
  ok "control socket is not visible inside the sandbox"
else
  bad "control socket leaked into the sandbox"
fi
"$CTL" grant session /home/rj/su >/dev/null 2>&1
sleep 1.2
if sb 'touch /home/rj/su/.grant-inside' >/dev/null 2>&1 && [ -f /home/rj/su/.grant-inside ]; then
  ok "session grant is enforced inside the sandbox"
else
  bad "session grant is not enforced inside the sandbox"
fi
rm -f /home/rj/su/.grant-inside
"$CTL" revoke /home/rj/su >/dev/null 2>&1
sleep 1.2
if sb '! touch /home/rj/su/.grant-inside' >/dev/null 2>&1; then
  ok "revoked grant is refused inside the sandbox"
else
  bad "revoked grant still allows writes inside"
fi
rm -f /home/rj/su/.grant-inside

if sb "echo SB \$(date +%s) > $PROJECT/sandbox-proof.txt" >/dev/null 2>&1; then
  if [ -f "$BACKING/sandbox-proof.txt" ]; then
    ok "sandbox write is visible on the host backing dir"
  else
    bad "sandbox write is missing from the backing dir"
  fi
else
  bad "sandbox write failed"
fi

# The two behaviours that broke the GUI's CLI: an atomic write-temp-then-rename
# must be readable immediately, and an unlinked-but-open file must keep
# answering stat through its file descriptor.
if sb "python3 - <<'PYEOF'
import os, uuid, time

d = '/home/agent/.local/state/opencode'
os.makedirs(d, exist_ok=True)

p = os.path.join(d, 'atomic.json')
tmp = p + '.' + uuid.uuid4().hex + '.tmp'
open(tmp, 'w').write('{\"ok\":1}')
os.rename(tmp, p)
assert open(p).read() == '{\"ok\":1}'
os.unlink(p)

q = os.path.join(d, 'open-' + uuid.uuid4().hex)
fd = os.open(q, os.O_CREAT | os.O_RDWR, 0o644)
os.write(fd, b'hello')
os.unlink(q)
time.sleep(1.1)
assert os.fstat(fd).st_size == 5
os.lseek(fd, 0, 0)
assert os.read(fd, 5) == b'hello'
os.close(fd)
print('ok')
PYEOF" 2>/dev/null | grep -qx ok; then
  ok "atomic rename and unlinked-but-open files behave"
else
  bad "atomic rename or unlinked-but-open file misbehaves"
fi

echo
echo "=== symlink confinement inside the sandbox ==="
CANARY="/home/rj/.fsbroker-canary-$$"
echo "TOPSECRET-CANARY" > "$CANARY"
ln -sfn "$CANARY" "$BACKING/escape-abs"
ln -sfn "../../../../../../../../${CANARY#/}" "$BACKING/escape-rel"
ln -sfn /etc/hostname "$BACKING/inside-link"
if sb "cd \"$PROJECT\" && [ ! -e escape-abs ] && [ ! -e escape-rel ] && [ ! -e /proc/self/root$CANARY ]" >/dev/null 2>&1; then
  ok "symlinks to unmapped host paths stay inside the sandbox root"
else
  bad "a symlink reached a host path outside the sandbox root"
fi
if sb "cd \"$PROJECT\" && cat inside-link" 2>/dev/null | grep -qx opencode-sandbox; then
  ok "symlinks to mapped paths still resolve inside"
else
  bad "symlink to a mapped path does not resolve"
fi
rm -f "$BACKING/escape-abs" "$BACKING/escape-rel" "$BACKING/inside-link" "$CANARY"

echo
echo "=== process containment ==="
HOST_MNT=$(readlink /proc/self/ns/mnt)
NS=$(sb 'echo "$(readlink /proc/self/ns/mnt) $(bash -c "readlink /proc/self/ns/mnt")"' 2>/dev/null)
SB_MNT=${NS%% *}
GRAND_MNT=${NS##* }
[ -n "$SB_MNT" ] && [ "$SB_MNT" != "$HOST_MNT" ] && ok "sandbox has its own mount namespace ($SB_MNT)" \
  || bad "sandbox mount namespace looks wrong ($SB_MNT vs $HOST_MNT)"
[ -n "$GRAND_MNT" ] && [ "$GRAND_MNT" = "$SB_MNT" ] && ok "grandchild inherits the same mount namespace" \
  || bad "grandchild mount namespace differs ($GRAND_MNT vs $SB_MNT)"
if sb 'unshare -m true' >/dev/null 2>&1; then
  bad "a child could unshare a new mount namespace"
else
  ok "child cannot unshare a new mount namespace"
fi
if sb 'setns' >/dev/null 2>&1; then :; fi   # no setns binary; informational only

echo
echo "=== prompt broker (headless: --no-gui) ==="
BROKER="$ROOT_DIR/broker/broker.sh"
BCTL="$ROOT_DIR/broker/brokerctl"
STATE="$ROOT_DIR/run/broker-state.json"
AUDIT="$ROOT_DIR/run/audit.log"
"$BROKER" stop >/dev/null 2>&1
rm -f "$STATE" "$AUDIT"
"$BROKER" start --no-gui >/dev/null
sleep 1

if "$BCTL" ping 2>/dev/null | grep -qx "OK pong"; then
  ok "broker answers PING"
else
  bad "broker does not answer"
fi

sleep 1.2
if ! touch "$VROOT/home/rj/.config/.broker-no" 2>/dev/null; then
  ok "a denied prompt refuses the write"
else
  bad "a denied prompt still allowed the write"
fi

"$BCTL" grant session /home/rj/su >/dev/null 2>&1
sleep 1.2
if touch "$VROOT/home/rj/su/.broker-yes" 2>/dev/null; then
  ok "broker session grant allows a write"
else
  bad "broker session grant did not allow the write"
fi
rm -f /home/rj/su/.broker-yes
"$BCTL" revoke /home/rj/su >/dev/null 2>&1
sleep 1.2
if ! touch "$VROOT/home/rj/su/.broker-no2" 2>/dev/null; then
  ok "broker revoke refuses the write again"
else
  bad "broker revoke still allowed the write"
fi

"$BCTL" grant timed:2 /home/rj/su >/dev/null 2>&1
sleep 1.2
if touch "$VROOT/home/rj/su/.broker-timed" 2>/dev/null; then
  ok "broker timed grant allows a write"
else
  bad "broker timed grant did not allow the write"
fi
rm -f /home/rj/su/.broker-timed
sleep 2
if ! touch "$VROOT/home/rj/su/.broker-timed2" 2>/dev/null; then
  ok "broker timed grant expires"
else
  bad "broker timed grant did not expire"
fi

"$BCTL" grant session /home/rj/su >/dev/null 2>&1
sleep 1.2
if sb 'touch /home/rj/su/.broker-inside' >/dev/null 2>&1 && [ -f /home/rj/su/.broker-inside ]; then
  ok "broker session grant is enforced inside the sandbox"
else
  bad "broker session grant is not enforced inside the sandbox"
fi
rm -f /home/rj/su/.broker-inside

"$BCTL" grant always /home/rj/su >/dev/null 2>&1
"$BROKER" stop >/dev/null 2>&1
"$BROKER" start --no-gui >/dev/null
sleep 1.2
if touch "$VROOT/home/rj/su/.broker-always" 2>/dev/null; then
  ok "an always grant survives a broker restart"
else
  bad "an always grant did not survive a broker restart"
fi
rm -f /home/rj/su/.broker-always

if [ -s "$AUDIT" ]; then
  ok "the broker wrote an audit log"
else
  bad "the broker wrote no audit log"
fi

# An approved request adds a path at runtime; a denied one adds nothing.
REQDIR="/home/rj/.fsbroker-request-$$"
mkdir -p "$REQDIR"
echo hello > "$REQDIR/hello.txt"
"$BROKER" stop >/dev/null 2>&1
"$BROKER" start --no-gui --test-request ro >/dev/null
sleep 1
if sb "fsbroker-request $REQDIR ro" 2>/dev/null | grep -q "^OK"; then
  ok "a sandbox request can add a path"
else
  bad "a sandbox request was refused by the test broker"
fi
if sb "test -r $REQDIR/hello.txt" >/dev/null 2>&1; then
  ok "the requested path is visible inside the sandbox"
else
  bad "the requested path is not visible inside the sandbox"
fi
if sb "! touch $REQDIR/nope" >/dev/null 2>&1; then
  ok "a read-only request refuses writes"
else
  bad "a read-only request accepted a write"
fi

REQDIR2="/home/rj/.fsbroker-reqdeny-$$"
mkdir -p "$REQDIR2"
"$BROKER" stop >/dev/null 2>&1
"$BROKER" start --no-gui --test-request deny >/dev/null
sleep 1
if sb "! fsbroker-request $REQDIR2 ro" >/dev/null 2>&1; then
  ok "a denied request reports failure"
else
  bad "a denied request reported success"
fi
if sb "! test -e $REQDIR2" >/dev/null 2>&1; then
  ok "a denied request leaves the path invisible"
else
  bad "a denied request still exposed the path"
fi
rm -rf "$REQDIR" "$REQDIR2"

"$BROKER" stop >/dev/null 2>&1
rm -f "$STATE"

echo
echo "=== boundary report (expected gaps, not failures) ==="
CODE=$(sb 'curl -s -m 2 -o /dev/null -w "%{http_code}" http://127.0.0.1:49374/ 2>/dev/null' 2>/dev/null)
if [ "$CODE" != "000" ] && [ -n "$CODE" ]; then
  echo "FINDING  host loopback service on 49374 is reachable from the sandbox (HTTP $CODE)"
else
  echo "note     no host service answered on 49374 from inside the sandbox"
fi
if sb 'test -S /tmp/.X11-unix/X0' >/dev/null 2>&1; then
  echo "FINDING  host X11 socket is reachable from the sandbox"
else
  echo "note     host X11 socket not reachable"
fi

echo
echo "passed $pass, failed $fail"
[ "$fail" -eq 0 ]
