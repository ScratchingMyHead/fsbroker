"""Shared host-side helpers for talking to a running session.

Used by `bin/fsbroker-status` and `bin/fsbroker-manage`, both of which need to
find the run directory and read the two line protocols. Nothing here is bound
into the sandbox.
"""
import os
import socket


def default_run_dir():
    d = os.environ.get("FSBROKER_RUN_DIR")
    return d or os.path.join(
        os.environ.get("XDG_STATE_HOME", os.path.expanduser("~/.local/state")),
        "fsbroker",
    )


def discover_run_dirs():
    """Run directories with a live vroot mount, in mount-table order.

    Every mounted session appears in /proc/self/mounts as `vroot <dir>/mount
    fuse.vroot`, so the mount table names the run directories without having to
    guess where they are. A run directory that is mounted but whose daemon has
    died still shows up, which is the honest answer for it.
    """
    found = []
    try:
        with open("/proc/self/mounts", "rb") as f:
            lines = f.read().decode(errors="replace").splitlines()
    except OSError:
        return []
    for line in lines:
        parts = line.split(" ")
        if len(parts) < 3:
            continue
        source, mountpoint, fstype = parts[0], parts[1], parts[2]
        if source != "vroot" and not fstype.startswith("fuse.vroot"):
            continue
        # /proc escapes spaces and friends as octal.
        mountpoint = (mountpoint.replace("\\040", " ").replace("\\011", "\t")
                      .replace("\\012", "\n").replace("\\134", "\\"))
        rd = os.path.dirname(mountpoint.rstrip("/"))
        if rd and rd not in found:
            found.append(rd)
    return found


def query(sock, line, timeout=5):
    """Send one command, return the response lines, or None if unreachable."""
    if not os.path.exists(sock):
        return None
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(sock)
        s.sendall(line.encode() + b"\n")
        chunks = []
        while True:
            b = s.recv(65536)
            if not b:
                break
            chunks.append(b)
    except OSError:
        return None
    finally:
        s.close()
    return b"".join(chunks).decode(errors="replace").splitlines()


def native_mounts(run_dir):
    """Paths `bin/fsbroker` binds straight from the host, bypassing the vroot.

    They are visible and read-only, but no lookup reaches the daemon, so no rule
    about them can ever fire.
    """
    try:
        with open(os.path.join(run_dir, "native-mounts")) as f:
            return [line.strip() for line in f if line.strip()]
    except OSError:
        return []


def config_source(run_dir):
    """The config file the session was started with, as recorded by `mount`."""
    try:
        with open(os.path.join(run_dir, "config-source")) as f:
            path = f.read().strip()
    except OSError:
        return None
    return path or None


def approved_mounts(run_dir):
    """The sidecar holding mounts approved for good: a sibling of the config,
    which is what keeps a dialog from ever rewriting the user's own file."""
    source = config_source(run_dir)
    return f"{source}.d/mounts.toml" if source else None


def parse_mounts(lines):
    """(access, source, virtual path, host path) for each visible mount.

    `source` is `config` (the user's file), `permanent` (approved for good, and
    so removable) or `runtime` (this session only, from an approved request).
    """
    out = []
    for ln in lines[1:]:
        p = ln.split(" ", 4)
        if len(p) == 5 and p[0] == "mount":
            out.append(tuple(p[1:]))
    return out


def parse_rules(lines):
    """(kind, scope, path) for each `grant`/`deny` rule."""
    out = []
    for ln in lines[1:]:
        for kind in ("grant", "deny"):
            if ln.startswith(kind + " "):
                _, scope, path = ln.split(" ", 2)
                out.append((kind, scope, path))
                break
    return out
