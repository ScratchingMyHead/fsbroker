#!/usr/bin/env python3
"""fsbroker: the interactive permission broker.

The broker runs on the host, outside the sandbox, next to the FUSE virtual
root. When the daemon refuses a mutation to a read-only path it asks the
broker; the broker shows the user a dialog and answers with a scope:

    once | session | timed:<seconds> | always

`once` and `session` are ephemeral: the daemon holds them for as long as it
runs. `timed` and `always` are persisted in the broker's state file, so a later
daemon (or a restart) is answered without prompting.

The socket is host-only (`0600`) and deliberately not part of the virtual root,
so nothing inside the sandbox can reach it.

Protocol (one request line, one response line, then close):

    -> PING
    <- OK pong
    -> LIST
    <- OK <n>\\n (grant|deny) <scope> <path>...
    -> GRANT <scope> <path>          scope: session|always|timed:<seconds>
    -> DENY <scope> <path>
    -> REVOKE <path>
    <- OK revoked <n> <path>
    -> CLEAR
    <- OK cleared <n>
    -> ASK <op> <pid> <uid> <path> [<path>...]
    <- ALLOW <scope> <path> [<path>...]
    <- DENY

A rule covers a path and everything under it, so the path may be a file (that
file alone) or a directory. Denials are rules like grants: `once` answers this
one operation without remembering anything; the rest are remembered until they
expire or are revoked.
"""
import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time

DEFAULT_TIMEOUT = 240          # seconds to wait for a dialog answer
TIMED_CHOICES = {              # menu label -> seconds
    "10 minutes": 600,
    "1 hour": 3600,
    "6 hours": 6 * 3600,
    "12 hours": 12 * 3600,
}

# What a dismissed dialog, a missing GUI or a timeout means: refuse this one
# operation and remember nothing.
DENY_ONCE = {"action": "deny", "duration": "once", "secs": None, "path": None}

# A dismissed (or unavailable) access request: grant nothing, remember nothing.
NO_REQUEST = {"access": None, "remember": False}

# Header written once, the first time a mount is approved for good.
HEADER = """# Mounts approved for good from an access request.
#
# Deliberately not in {source}: a dialog must never rewrite the config you
# wrote, and everything in this file is safe for the rule manager to remove.
"""


# --------------------------------------------------------------------------
# state
# --------------------------------------------------------------------------

class State:
    """Durable grants: `always` and `timed` decisions."""

    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        self.grants = []
        self._load()

    def _load(self):
        try:
            with open(self.path) as f:
                data = json.load(f)
            self.grants = data.get("grants", [])
        except FileNotFoundError:
            self.grants = []
        except (OSError, ValueError) as e:
            print(f"broker: ignoring unreadable state {self.path}: {e}", file=sys.stderr)
            self.grants = []

    def _save(self):
        tmp = f"{self.path}.tmp"
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        durable = [g for g in self.grants if not g.get("ephemeral")]
        with open(tmp, "w") as f:
            json.dump({"grants": durable}, f, indent=2)
        os.replace(tmp, self.path)

    def prune(self):
        now = time.time()
        with self.lock:
            self.grants = [g for g in self.grants
                           if g.get("expiry") is None or g["expiry"] > now]

    def add(self, path, scope, secs=None, ephemeral=False, kind="allow"):
        """Add a rule. `ephemeral` rules (session) are not persisted: they live
        as long as the broker does, which is how the user thinks of "this
        session". `kind` is "allow" or "deny"; a new rule for a path replaces
        whatever was there, so an allow and a deny cannot fight over one path.
        """
        entry = {
            "path": path,
            "scope": scope,
            "kind": kind,
            "expiry": (time.time() + secs) if secs else None,
            "ephemeral": ephemeral,
            "granted_at": time.time(),
        }
        with self.lock:
            self.grants = [g for g in self.grants if g["path"] != path]
            self.grants.append(entry)
            if not ephemeral:
                self._save()

    def match(self, paths):
        """The rule covering every path, as (kind, hits), or None.

        Per path the most specific (longest) matching rule wins, so a file rule
        beats a directory rule that contains it. If any path resolves to a deny
        the whole decision is a deny: an operation is allowed only when nothing
        it touches is denied.
        """
        self.prune()
        kind = "allow"
        hits = []
        with self.lock:
            for p in paths:
                best = None
                for g in self.grants:
                    if p == g["path"] or p.startswith(g["path"].rstrip("/") + "/"):
                        if best is None or len(g["path"]) > len(best["path"]):
                            best = g
                if best is None:
                    return None
                hits.append(best)
                if best.get("kind", "allow") == "deny":
                    kind = "deny"
        return (kind, hits)

    def rewrite(self, src, dst):
        """Follow a rename: rules naming `src`, or anything under it, move to
        `dst`. Called when a rename is allowed, so a rule the user set for a
        path does not go stale just because the path was renamed."""
        if not src or not dst or not src.startswith("/") or not dst.startswith("/"):
            return 0
        src = src.rstrip("/") or "/"
        prefix = src + "/"
        with self.lock:
            changed = 0
            for g in self.grants:
                p = g["path"]
                if p == src:
                    g["path"] = dst
                    changed += 1
                elif p.startswith(prefix):
                    g["path"] = dst.rstrip("/") + "/" + p[len(prefix):]
                    changed += 1
            if changed:
                seen = {}
                for g in self.grants:
                    seen[g["path"]] = g
                self.grants = list(seen.values())
                self._save()
            return changed

    def list(self):
        self.prune()
        with self.lock:
            out = []
            for g in self.grants:
                if g.get("scope") == "session":
                    scope = "session"
                elif g.get("expiry") is None:
                    scope = "always"
                else:
                    scope = f"timed:{int(g['expiry'] - time.time())}"
                out.append((g.get("kind", "allow"), scope, g["path"]))
            return out

    def revoke(self, path):
        with self.lock:
            before = len(self.grants)
            self.grants = [g for g in self.grants if g["path"] != path]
            if len(self.grants) != before:
                self._save()
            return before - len(self.grants)

    def clear(self):
        with self.lock:
            n = len(self.grants)
            self.grants = []
            self._save()
            return n


# --------------------------------------------------------------------------
# audit
# --------------------------------------------------------------------------

class Audit:
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()

    def log(self, op, paths, pid, uid, decision, scope):
        rec = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "op": op,
            "paths": paths,
            "pid": pid,
            "uid": uid,
            "comm": proc_field(pid, "comm"),
            "cwd": safe_readlink(f"/proc/{pid}/cwd"),
            "decision": decision,
            "scope": scope,
        }
        line = json.dumps(rec)
        with self.lock:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            with open(self.path, "a") as f:
                f.write(line + "\n")
        print(f"audit {line}", file=sys.stderr, flush=True)


def safe_readlink(p):
    try:
        return os.readlink(p)
    except OSError:
        return None


def proc_field(pid, name):
    try:
        with open(f"/proc/{pid}/{name}") as f:
            return f.read().strip()
    except OSError:
        return None


# --------------------------------------------------------------------------
# prefix rules
# --------------------------------------------------------------------------

def default_icon():
    """The prompts are windows too, and get the same placeholder in the task bar
    without an icon of their own."""
    here = os.path.dirname(os.path.abspath(__file__))
    for name in ("fsbroker.png", "fsbroker.svg"):
        path = os.path.normpath(os.path.join(here, os.pardir, "icons", name))
        if os.path.exists(path):
            return path
    return None


def read_config_source(run_dir):
    """The config file the session was started with, as recorded by
    `bin/fsbroker` in the run directory."""
    if not run_dir:
        return None
    try:
        with open(os.path.join(run_dir, "config-source")) as f:
            path = f.read().strip()
    except OSError:
        return None
    return path or None


def mount_roots(run_dir):
    """The host paths of the configured mounts, longest first.

    Used to stop the scope picker at the deepest mapping that contains the
    path: above it nothing is mapped, and a rule there would silently cover
    every mapped path beneath it.
    """
    if not run_dir:
        return []
    try:
        import tomllib
        with open(os.path.join(run_dir, "vroot.resolved.toml"), "rb") as f:
            cfg = tomllib.load(f)
    except (OSError, ValueError, ImportError):
        return []
    # The daemon names paths the way the sandbox sees them, so the cap uses
    # virtual_path, which equals host for identity mappings and differs only
    # where a mount is placed somewhere else.
    roots = []
    for m in cfg.get("mount", []):
        v = m.get("virtual_path") or m.get("host")
        if v and v.startswith("/"):
            roots.append(os.path.normpath(v))
    roots.sort(key=len, reverse=True)
    return roots


def label_for(path, kind="path"):
    """The picker row text: what choosing this path actually covers.

    `kind` is one of root/dir/file/path, decided by `candidates` (which knows
    things the filesystem cannot answer, like a rename's common parent).
    """
    if kind == "root":
        name = os.path.basename(path.rstrip("/")) or path
        return f"{path}   — the whole {name} mapping"
    if kind == "dir":
        return f"{path}   — this folder and everything below"
    if kind == "file":
        return f"{path}   — just this file"
    return f"{path}   — just this path"


def _kind(path, start, op, root):
    if path == root:
        return "root"
    if op == "rename" and path == start:
        return "dir"        # the common parent of a rename is a directory
    if os.path.isdir(path):
        return "dir"
    if os.path.exists(path):
        return "file"
    return "path"           # e.g. a name being created


def candidates(op, paths, roots):
    """Paths a decision can be scoped to, narrowest first.

    Every row is a valid rule: the matcher covers the path and descendants, so
    a file row means that file alone. A rename touches two directories, so its
    narrowest row is their common parent rather than either file. The walk
    stops at the mount root containing the path (see `mount_roots`).
    """
    if op == "rename" and len(paths) >= 2:
        a, b = os.path.dirname(paths[0]), os.path.dirname(paths[1])
        try:
            start = os.path.commonpath([a, b])
        except ValueError:
            start = a or b
    else:
        start = paths[0]
    start = os.path.normpath(start) if start else "/"

    root = None
    for r in roots:
        if start == r or start.startswith(r.rstrip("/") + "/"):
            root = r
            break

    out = []
    cur = start
    while True:
        out.append(cur)
        if cur == root:
            break
        parent = os.path.dirname(cur)
        if parent == cur:                      # reached /
            break
        cur = parent
        if root is None and len(out) >= 3:     # no config: file + two parents
            break
    return [(p, _kind(p, start, op, root)) for p in out]


def parse_answer(text):
    """Parse a `--test-answer` value: `[deny:]<duration>[@<path>]`.

    `once`, `always`, `session`, `timed:600`, `deny:always@/a/b`, `deny`.
    """
    if not text:
        return None
    kind = "allow"
    if text.startswith("deny:"):
        kind, text = "deny", text[len("deny:"):]
    elif text == "deny":
        kind, text = "deny", "once"
    path = None
    if "@" in text:
        text, path = text.split("@", 1)
    secs = None
    if text.startswith("timed:"):
        duration, secs = "timed", int(text.split(":", 1)[1])
    else:
        duration = text
    return {"action": kind, "duration": duration, "secs": secs, "path": path}


# --------------------------------------------------------------------------
# GUI
# --------------------------------------------------------------------------

class Prompt:
    """Shows one permission dialog and returns the chosen decision."""

    def __init__(self, no_gui, test_answer, test_request=None, roots=None,
                 run_dir=None, can_remember=False):
        self.no_gui = no_gui
        self.test_answer = test_answer
        self.test_request = test_request
        self.roots = roots or []
        self.run_dir = run_dir
        self.can_remember = can_remember
        self.queue = []
        self.queue_lock = threading.Lock()
        self.busy = False
        self.Gtk = None
        self.GLib = None
        if not no_gui and not test_answer:
            self._load_gtk()

    def _load_gtk(self):
        import gi
        gi.require_version("Gtk", "3.0")
        gi.require_version("Gdk", "3.0")
        from gi.repository import Gtk, GLib
        self.Gtk = Gtk
        self.GLib = GLib

    def available(self):
        return self.Gtk is not None

    def ask(self, op, paths, pid, uid):
        """Block until the user (or the test harness) decides. Returns a
        decision dict: action, duration, secs and the chosen scope path."""
        if self.test_answer:
            return self._test_decision(op, paths, self.test_answer)
        if self.Gtk is None:
            return dict(DENY_ONCE)

        answer = {"decision": None, "event": threading.Event()}
        with self.queue_lock:
            self.queue.append(("ask", (op, paths, pid, uid), answer))
        self.GLib.idle_add(self._pump)
        answer["event"].wait(DEFAULT_TIMEOUT)
        return answer["decision"] or dict(DENY_ONCE)

    def request(self, path, writable, pid, uid):
        """Ask the user to add `path` to the virtual root. Returns a dict:
        `access` is `ro`, `rw` or None, and `remember` says the answer should
        outlive this session."""
        if self.test_request:
            remember = self.test_request.endswith("+remember")
            access = self.test_request.removesuffix("+remember")
            return {"access": access if access in ("ro", "rw") else None,
                    "remember": remember and access in ("ro", "rw")}
        if self.Gtk is None:
            return dict(NO_REQUEST)

        answer = {"decision": None, "event": threading.Event()}
        with self.queue_lock:
            self.queue.append(("request", (path, writable, pid, uid), answer))
        self.GLib.idle_add(self._pump)
        answer["event"].wait(DEFAULT_TIMEOUT)
        return answer["decision"] or dict(NO_REQUEST)

    def _test_decision(self, op, paths, text):
        d = parse_answer(text)
        if not d:
            return dict(DENY_ONCE)
        if not d.get("path"):
            d["path"] = candidates(op, paths, self.roots)[0][0]
        return d

    def _pump(self):
        with self.queue_lock:
            if self.busy or not self.queue:
                return False
            self.busy = True
            kind, payload, answer = self.queue.pop(0)
        # A bug in dialog construction must never wedge the broker: always
        # unblock the waiting request and free the pump.
        try:
            if kind == "ask":
                answer["decision"] = self._show_ask(*payload)
            else:
                answer["decision"] = self._show_request(*payload)
        except Exception as e:
            print(f"broker: dialog error: {e}", file=sys.stderr, flush=True)
            answer["decision"] = (dict(NO_REQUEST) if kind == "request"
                                  else dict(DENY_ONCE))
        finally:
            answer["decision"] = answer["decision"] or (
                dict(NO_REQUEST) if kind == "request" else dict(DENY_ONCE))
            answer["event"].set()
            with self.queue_lock:
                self.busy = False
            self.GLib.idle_add(self._pump)
        return False

    def _details(self, Gtk, grid, rows):
        for i, (label, value) in enumerate(rows):
            lab = Gtk.Label(label=f"{label}:", xalign=0)
            lab.get_style_context().add_class("dim-label")
            val = Gtk.Label(label=value, xalign=0)
            val.set_selectable(True)
            grid.attach(lab, 0, i, 1, 1)
            grid.attach(val, 1, i, 1, 1)

    def _centre(self, dlg):
        """Put the dialog in the middle of the screen the pointer is on.

        These windows have no parent, so the window manager places them and
        tends to cascade a run of them off to one side. Ask GTK for the centre
        as well, and once the window has a size, move it there explicitly —
        the position hint alone is not always honoured.
        """
        Gtk = self.Gtk
        try:
            dlg.set_position(Gtk.WindowPosition.CENTER_ALWAYS)
        except Exception:
            pass
        try:
            from gi.repository import Gdk
            display = Gdk.Display.get_default()
            monitor = None
            seat = display.get_default_seat()
            if seat is not None:
                pointer = seat.get_pointer()
                if pointer is not None:
                    _screen, x, y = pointer.get_position()
                    monitor = display.get_monitor_at_point(x, y)
            monitor = (monitor or display.get_primary_monitor()
                       or display.get_monitor(0))
            geo = monitor.get_geometry()
            w, h = dlg.get_allocated_width(), dlg.get_allocated_height()
            dlg.move(geo.x + max(0, (geo.width - w) // 2),
                     geo.y + max(0, (geo.height - h) // 2))
        except Exception as e:
            print(f"broker: could not centre the dialog: {e}",
                  file=sys.stderr, flush=True)

    def _spawn_manager(self):
        """Open the rule manager as its own process. Being a separate process is
        what makes it non-modal: this prompt stays open and answerable."""
        manager = os.path.normpath(os.path.join(
            os.path.dirname(os.path.abspath(__file__)), os.pardir,
            "bin", "fsbroker-manage"))
        argv = [manager] + (["--run-dir", self.run_dir] if self.run_dir else [])
        try:
            subprocess.Popen(argv, start_new_session=True,
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
        except OSError as e:
            print(f"broker: could not start the rule manager: {e}",
                  file=sys.stderr, flush=True)

    def _show_request(self, path, writable, pid, uid):
        Gtk = self.Gtk
        dlg = Gtk.Dialog(title="fsbroker — access request")
        dlg.set_default_size(560, -1)
        dlg.set_resizable(False)
        dlg.set_keep_above(True)

        grid = Gtk.Grid(column_spacing=12, row_spacing=6, margin=12)
        self._details(Gtk, grid, [
            ("Request", "add a folder to the sandbox"),
            ("Path", path),
            ("Access", "read-write" if writable else "read-only"),
            ("Process", f"{proc_field(pid, 'comm') or '?'} (pid {pid})"),
            ("Working dir", safe_readlink(f"/proc/{pid}/cwd") or "?"),
            ("User", str(uid)),
        ])
        dlg.get_content_area().add(grid)

        # Off by default: a request normally lasts for this session only, and
        # anything longer should be a deliberate choice.
        remember = Gtk.CheckButton(label="Remember it for future sessions")
        remember.set_active(False)
        remember.set_sensitive(self.can_remember)
        if not self.can_remember:
            remember.set_tooltip_text(
                "no config path recorded for this session, so it cannot be made permanent")
        dlg.get_content_area().add(remember)

        dlg.add_button("Deny", 0)
        dlg.add_button("Add read-only", 1)
        dlg.add_button("Add read-write", 2)

        dlg.show_all()
        self._centre(dlg)
        response = dlg.run()
        if response == 2:
            access = "rw"
        elif response == 1:
            access = "ro"
        else:
            access = None
        keep = (bool(remember.get_active()) and self.can_remember
                and access is not None)
        dlg.destroy()
        return {"access": access, "remember": keep}

    def _show_ask(self, op, paths, pid, uid):
        Gtk = self.Gtk
        cands = candidates(op, paths, self.roots)

        dlg = Gtk.Dialog(title="fsbroker — permission request")
        dlg.set_default_size(620, -1)
        dlg.set_resizable(False)
        dlg.set_keep_above(True)
        content = dlg.get_content_area()

        grid = Gtk.Grid(column_spacing=12, row_spacing=6, margin=12)
        self._details(Gtk, grid, [
            ("Operation", op),
            ("Path", "\n".join(paths)),
            ("Process", f"{proc_field(pid, 'comm') or '?'} (pid {pid})"),
            ("Working dir", safe_readlink(f"/proc/{pid}/cwd") or "?"),
            ("User", str(uid)),
        ])
        content.add(grid)

        # What the decision covers. The first row is the narrowest: the file (or
        # the common parent for a rename), then each ancestor up to the mount
        # root. A deny uses the same choice, so "always deny this folder" works.
        target_grid = Gtk.Grid(column_spacing=12, row_spacing=6, margin=12)
        target_label = Gtk.Label(label="Applies to:", xalign=0)
        target_label.get_style_context().add_class("dim-label")
        combo = Gtk.ComboBoxText()
        for path, kind in cands:
            combo.append_text(label_for(path, kind))
        combo.set_active(0)
        target_grid.attach(target_label, 0, 0, 1, 1)
        target_grid.attach(combo, 1, 0, 1, 1)
        content.add(target_grid)

        # For how long. The amount for "timed" is chosen from its own menu; the
        # default is the first entry, so the radio is usable without a second
        # click.
        dur_grid = Gtk.Grid(column_spacing=12, row_spacing=6, margin=12)
        dur_label = Gtk.Label(label="Duration:", xalign=0)
        dur_label.get_style_context().add_class("dim-label")
        dur_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        once = Gtk.RadioButton.new_with_label(None, "once")
        session = Gtk.RadioButton.new_with_label_from_widget(once, "session")
        timed = Gtk.RadioButton.new_with_label_from_widget(once, "timed")
        always = Gtk.RadioButton.new_with_label_from_widget(once, "always")
        once.set_active(True)

        default_label, default_secs = next(iter(TIMED_CHOICES.items()))
        chosen = {"secs": default_secs}
        timed_menu = Gtk.Menu()
        for label, secs in TIMED_CHOICES.items():
            item = Gtk.MenuItem(label=label)

            def pick(_w, s=secs, lbl=label):
                chosen["secs"] = s
                timed.set_active(True)
                timed_button.set_label(f"timed: {lbl}")

            item.connect("activate", pick)
            timed_menu.append(item)
        timed_menu.show_all()
        timed_button = Gtk.MenuButton(label=f"timed: {default_label}")
        timed_button.set_popup(timed_menu)

        dur_box.add(once)
        dur_box.add(session)
        dur_box.add(timed)
        dur_box.add(timed_button)
        dur_box.add(always)
        dur_grid.attach(dur_label, 0, 0, 1, 1)
        dur_grid.attach(dur_box, 1, 0, 1, 1)
        content.add(dur_grid)

        # Buttons live in the content area, not the dialog action area:
        # `add_action_widget` would make the MenuButton "activate" the dialog
        # (closing it) instead of opening its menu, and `get_action_area` is
        # deprecated. A plain `ButtonBox` keeps that behaviour.
        buttons = Gtk.ButtonBox(
            orientation=Gtk.Orientation.HORIZONTAL,
            spacing=6,
            margin=12,
        )
        buttons.set_layout(Gtk.ButtonBoxStyle.END)
        # A way out of a hasty "always": open the manager without answering this
        # prompt. Its own process, so nothing here is modal.
        manage = Gtk.Button(label="Manage rules…")
        manage.connect("clicked", lambda *_: self._spawn_manager())
        deny = Gtk.Button(label="Deny")
        deny.connect("clicked", lambda *_: dlg.response(0))
        allow = Gtk.Button(label="Allow")
        allow.connect("clicked", lambda *_: dlg.response(1))
        buttons.add(manage)
        buttons.add(deny)
        buttons.add(allow)
        content.add(buttons)

        dlg.show_all()
        self._centre(dlg)
        response = dlg.run()

        if response not in (0, 1):
            dlg.destroy()
            return dict(DENY_ONCE)

        index = combo.get_active()
        path = cands[index][0] if 0 <= index < len(cands) else cands[0][0]
        if session.get_active():
            duration = "session"
        elif timed.get_active():
            duration = "timed"
        elif always.get_active():
            duration = "always"
        else:
            duration = "once"
        dlg.destroy()
        return {
            "action": "allow" if response == 1 else "deny",
            "duration": duration,
            "secs": chosen["secs"] if duration == "timed" else None,
            "path": path,
        }


# --------------------------------------------------------------------------
# request handling
# --------------------------------------------------------------------------

class Broker:
    def __init__(self, args):
        self.state = State(args.state)
        self.audit = Audit(args.audit)
        self.roots = mount_roots(args.run_dir)
        self.config_source = read_config_source(args.run_dir)
        self.sidecar = (f"{self.config_source}.d/mounts.toml"
                        if self.config_source else None)
        self.prompt = Prompt(args.no_gui, args.test_answer, args.test_request,
                             roots=self.roots, run_dir=args.run_dir,
                             can_remember=self.sidecar is not None)
        self.sock_path = args.socket

    def handle(self, line):
        parts = line.split()
        if not parts:
            return "ERR empty\n"
        cmd = parts[0].upper()

        if cmd == "PING":
            return "OK pong\n"

        if cmd == "LIST":
            rules = self.state.list()
            out = [f"OK {len(rules)}"]
            out += [f"{'grant' if kind == 'allow' else 'deny'} {scope} {path}"
                    for kind, scope, path in rules]
            return "\n".join(out) + "\n"

        if cmd in ("GRANT", "DENY"):
            if len(parts) != 3:
                return f"ERR usage: {cmd} <session|always|timed:seconds> <path>\n"
            kind = "allow" if cmd == "GRANT" else "deny"
            scope, path = parts[1], parts[2]
            if not path.startswith("/"):
                return "ERR path must be absolute\n"
            if scope == "session":
                self.state.add(path, "session", ephemeral=True, kind=kind)
                return f"OK {kind} session {path}\n"
            if scope == "always":
                self.state.add(path, "always", kind=kind)
                return f"OK {kind} always {path}\n"
            if scope.startswith("timed:"):
                secs = int(scope.split(":", 1)[1])
                self.state.add(path, "timed", secs=secs, kind=kind)
                return f"OK {kind} timed:{secs} {path}\n"
            return "ERR scope must be session, always or timed:<seconds>\n"

        if cmd == "REVOKE":
            if len(parts) != 2:
                return "ERR usage: REVOKE <path>\n"
            n = self.state.revoke(parts[1])
            return f"OK revoked {n} {parts[1]}\n"

        if cmd == "CLEAR":
            n = self.state.clear()
            return f"OK cleared {n}\n"

        if cmd == "ASK":
            return self.ask(parts[1:])

        if cmd == "REQUEST":
            return self.request(parts[1:])

        return f"ERR unknown command: {cmd}\n"

    def request(self, rest):
        if len(rest) != 4:
            return "ERR usage: REQUEST <pid> <uid> <ro|rw> <path>\n"
        pid, uid, mode, path = rest
        if mode not in ("ro", "rw"):
            return "ERR mode must be ro or rw\n"
        if not path.startswith("/"):
            return "ERR path must be absolute\n"
        writable = mode == "rw"

        answer = self.prompt.request(path, writable, pid, uid)
        access = answer.get("access")
        if access is None:
            self.audit.log("request", [path], pid, uid, "deny", None)
            return "DENY\n"

        scope = "read-write" if access == "rw" else "read-only"
        if answer.get("remember"):
            if self.remember_mount(path, writable=(access == "rw")):
                scope += " permanent"
            else:
                scope += " (could not be remembered)"
        self.audit.log("request", [path], pid, uid, "allow", scope)
        return "ALLOW " + ("read-write" if access == "rw" else "read-only") + "\n"

    def remember_mount(self, path, writable):
        """Add a mount to the sidecar of approved paths, where the next session
        will find it. The user's own config is never touched, so anything the
        manager may remove lives in a file the manager owns."""
        if not self.sidecar:
            return False
        block = f"\n[[mount]]\nhost = \"{path}\"\n"
        if writable:
            block += "writable = true\n"
        try:
            existing = ""
            try:
                with open(self.sidecar) as f:
                    existing = f.read()
            except FileNotFoundError:
                os.makedirs(os.path.dirname(self.sidecar), exist_ok=True)
                existing = HEADER.format(source=self.config_source or "?")
            if f'"{path}"' in existing:
                return True          # already approved; nothing to add
            with open(self.sidecar, "a") as f:
                f.write(block)
            print(f"broker: approved for good: {path}", file=sys.stderr, flush=True)
            return True
        except OSError as e:
            print(f"broker: could not remember {path}: {e}",
                  file=sys.stderr, flush=True)
            return False

    def ask(self, rest):
        if len(rest) < 4:
            return "ERR usage: ASK <op> <pid> <uid> <path>...\n"
        op, pid, uid = rest[0], rest[1], rest[2]
        paths = rest[3:]

        match = self.state.match(paths)
        if match is not None:
            kind, hits = match
            if kind == "deny":
                self.audit.log(op, paths, pid, uid, "deny", "cached")
                return "DENY\n"
            scope = self._combined_scope(hits)
            prefixes = sorted({h["path"] for h in hits})
            self.audit.log(op, paths, pid, uid, "allow", f"cached {scope}")
            self._follow_rename(op, paths)
            return "ALLOW " + scope + " " + " ".join(prefixes) + "\n"

        answer = self.prompt.ask(op, paths, pid, uid)
        action = answer.get("action", "deny")
        duration = answer.get("duration", "once")
        target = answer.get("path") or candidates(op, paths, self.roots)[0][0]

        if action == "deny":
            if duration == "once":
                self.audit.log(op, paths, pid, uid, "deny", "once")
                return "DENY\n"
            scope = self._remember(target, duration, answer.get("secs"), "deny")
            self.audit.log(op, paths, pid, uid, "deny", f"{scope} {target}")
            return "DENY\n"

        if duration == "once":
            self.audit.log(op, paths, pid, uid, "allow", "once")
            self._follow_rename(op, paths)
            return "ALLOW once " + " ".join(paths) + "\n"

        scope = self._remember(target, duration, answer.get("secs"), "allow")
        if scope == "once":
            self.audit.log(op, paths, pid, uid, "deny", f"bad duration {duration}")
            return "DENY\n"

        self.audit.log(op, paths, pid, uid, "allow", f"{scope} {target}")
        self._follow_rename(op, paths)
        return f"ALLOW {scope} {target}\n"

    def _remember(self, path, duration, secs, kind):
        """Store a rule and return its scope string, or "once" if the duration
        is not one we persist."""
        if duration == "session":
            self.state.add(path, "session", ephemeral=True, kind=kind)
            return "session"
        if duration == "always":
            self.state.add(path, "always", kind=kind)
            return "always"
        if duration == "timed":
            self.state.add(path, "timed", secs=secs, kind=kind)
            return f"timed:{secs}"
        return "once"

    def _follow_rename(self, op, paths):
        """Keep rules pointing at the right path when something is renamed."""
        if op == "rename" and len(paths) >= 2:
            self.state.rewrite(paths[0], paths[1])

    @staticmethod
    def _combined_scope(hits):
        """The weakest scope among cached matches."""
        if any(g.get("scope") == "session" for g in hits):
            return "session"
        timed = [g for g in hits if g.get("expiry") is not None]
        if timed:
            remaining = max(0, int(min(g["expiry"] for g in timed) - time.time()))
            return f"timed:{remaining}"
        return "always"


# --------------------------------------------------------------------------
# server
# --------------------------------------------------------------------------

def serve_one(broker, conn):
    try:
        data = b""
        while not data.endswith(b"\n"):
            chunk = conn.recv(65536)
            if not chunk:
                break
            data += chunk
            if len(data) > 65536:
                break
        line = data.decode(errors="replace").strip()
        response = broker.handle(line)
    except Exception as e:  # never let one bad request kill the broker
        response = f"ERR {e}\n"
    try:
        conn.sendall(response.encode())
    except OSError:
        pass
    finally:
        conn.close()


def serve(broker):
    """Accept connections forever, one thread each.

    An ASK is answered by showing a dialog and waiting for the user, so serving
    one connection at a time meant everything else that asked during a prompt —
    the rule manager, `fsbroker-status`, `brokerctl` — sat waiting for the
    answer and timed out. The prompts themselves are still serialised by the
    queue in Prompt.
    """
    path = broker.sock_path
    if os.path.exists(path):
        os.unlink(path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    os.chmod(path, 0o600)
    srv.listen(16)
    print(f"broker: listening on {path}", file=sys.stderr, flush=True)

    while True:
        try:
            conn, _ = srv.accept()
        except OSError:
            break
        threading.Thread(target=serve_one, args=(broker, conn),
                         daemon=True).start()


def main():
    p = argparse.ArgumentParser(description="fsbroker permission broker")
    p.add_argument("--run-dir", default=os.environ.get("FSBROKER_RUN_DIR"),
                   help="where the socket, state and audit log live "
                        "(env FSBROKER_RUN_DIR)")
    p.add_argument("--socket", default=None, help="override the socket path")
    p.add_argument("--state", default=None, help="override the state file")
    p.add_argument("--audit", default=None, help="override the audit log")
    p.add_argument("--no-gui", action="store_true",
                   help="never show a dialog; deny anything not already granted")
    p.add_argument("--test-answer", default=os.environ.get("FSBROKER_TEST_ANSWER"),
                   help="answer every write prompt with this scope (for tests)")
    p.add_argument("--test-request", default=os.environ.get("FSBROKER_TEST_REQUEST"),
                   help="answer every add-request with deny|ro|rw (for tests)")
    args = p.parse_args()

    # Everything the broker writes lives under the run directory.
    run = args.run_dir or os.path.join(
        os.environ.get("XDG_STATE_HOME", os.path.expanduser("~/.local/state")),
        "fsbroker",
    )
    args.run_dir = run
    args.socket = args.socket or os.path.join(run, "broker.sock")
    args.state = args.state or os.path.join(run, "broker-state.json")
    args.audit = args.audit or os.path.join(run, "audit.log")

    broker = Broker(args)

    if broker.prompt.available():
        from gi.repository import Gtk
        icon = default_icon()
        if icon:
            try:
                Gtk.Window.set_default_icon_from_file(icon)
            except Exception as e:
                print(f"broker: could not load icon {icon}: {e}",
                      file=sys.stderr, flush=True)
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        signal.signal(signal.SIGTERM, lambda *_: Gtk.main_quit())
        threading.Thread(target=serve, args=(broker,), daemon=True).start()
        print("broker: dialog ready", file=sys.stderr, flush=True)
        Gtk.main()
    else:
        serve(broker)


if __name__ == "__main__":
    main()
