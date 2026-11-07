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
    <- OK <n>\\n grant <scope> <path>...
    -> REVOKE <path>
    <- OK revoked <n> <path>
    -> CLEAR
    <- OK cleared <n>
    -> ASK <op> <pid> <uid> <path> [<path>...]
    <- ALLOW <scope> <path> [<path>...]
    <- DENY
"""
import argparse
import json
import os
import signal
import socket
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

    def add(self, path, scope, secs=None, ephemeral=False):
        """Add a grant. `ephemeral` grants (session) are not persisted: they
        live as long as the broker does, which is how the user thinks of
        "this session"."""
        entry = {
            "path": path,
            "scope": scope,
            "expiry": (time.time() + secs) if secs else None,
            "ephemeral": ephemeral,
            "granted_at": time.time(),
        }
        with self.lock:
            self.grants = [g for g in self.grants if g["path"] != path]
            self.grants.append(entry)
            if not ephemeral:
                self._save()

    def matched_grants(self, paths):
        """Return the durable grants covering every path, weakest scope first."""
        self.prune()
        with self.lock:
            hits = []
            for p in paths:
                best = None
                for g in self.grants:
                    if p == g["path"] or p.startswith(g["path"].rstrip("/") + "/"):
                        if best is None or len(g["path"]) > len(best["path"]):
                            best = g
                if best is None:
                    return None
                hits.append(best)
            return hits

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
                out.append((scope, g["path"]))
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

def prefix_for(op, paths):
    """The directory an `always`/`session`/`timed` grant should cover."""
    if op == "rename" and len(paths) == 2:
        a = os.path.dirname(paths[0])
        b = os.path.dirname(paths[1])
        common = os.path.commonpath([a, b])
        return common if common not in ("", "/") else b

    p = paths[0]
    if os.path.isdir(p):
        return p
    parent = os.path.dirname(p)
    return parent or "/"


# --------------------------------------------------------------------------
# GUI
# --------------------------------------------------------------------------

class Prompt:
    """Shows one permission dialog and returns the chosen scope string."""

    def __init__(self, no_gui, test_answer, test_request=None):
        self.no_gui = no_gui
        self.test_answer = test_answer
        self.test_request = test_request
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
        from gi.repository import Gtk, GLib
        self.Gtk = Gtk
        self.GLib = GLib

    def available(self):
        return self.Gtk is not None

    def ask(self, op, paths, pid, uid):
        """Block until the user (or the test harness) decides."""
        if self.test_answer:
            return self.test_answer
        if self.Gtk is None:
            return "deny"

        answer = {"scope": None, "event": threading.Event()}
        with self.queue_lock:
            self.queue.append(("ask", (op, paths, pid, uid), answer))
        self.GLib.idle_add(self._pump)
        answer["event"].wait(DEFAULT_TIMEOUT)
        return answer["scope"] or "deny"

    def request(self, path, writable, pid, uid):
        """Ask the user to add `path` to the virtual root."""
        if self.test_request:
            return self.test_request
        if self.Gtk is None:
            return "deny"

        answer = {"scope": None, "event": threading.Event()}
        with self.queue_lock:
            self.queue.append(("request", (path, writable, pid, uid), answer))
        self.GLib.idle_add(self._pump)
        answer["event"].wait(DEFAULT_TIMEOUT)
        return answer["scope"] or "deny"

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
                answer["scope"] = self._show_ask(*payload)
            else:
                answer["scope"] = self._show_request(*payload)
        except Exception as e:
            print(f"broker: dialog error: {e}", file=sys.stderr, flush=True)
            answer["scope"] = "deny"
        finally:
            answer["scope"] = answer["scope"] or "deny"
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

        dlg.add_button("Deny", 0)
        dlg.add_button("Add read-only", 1)
        dlg.add_button("Add read-write", 2)

        dlg.show_all()
        response = dlg.run()
        if response == 2:
            scope = "read-write"
        elif response == 1:
            scope = "read-only"
        else:
            scope = "deny"
        dlg.destroy()
        return scope

    def _show_ask(self, op, paths, pid, uid):
        Gtk = self.Gtk
        dlg = Gtk.Dialog(title="fsbroker — permission request")
        dlg.set_default_size(560, -1)
        dlg.set_resizable(False)
        dlg.set_keep_above(True)

        grid = Gtk.Grid(column_spacing=12, row_spacing=6, margin=12)
        self._details(Gtk, grid, [
            ("Operation", op),
            ("Path", "\n".join(paths)),
            ("Process", f"{proc_field(pid, 'comm') or '?'} (pid {pid})"),
            ("Working dir", safe_readlink(f"/proc/{pid}/cwd") or "?"),
            ("User", str(uid)),
        ])
        dlg.get_content_area().add(grid)

        # Buttons live in the content area, not the dialog action area:
        # `add_action_widget` would make the MenuButton "activate" the dialog
        # (closing it) instead of opening its menu, and `get_action_area` is
        # deprecated. A plain `ButtonBox` gives us the dropdown we want.
        buttons = Gtk.ButtonBox(
            orientation=Gtk.Orientation.HORIZONTAL,
            spacing=6,
            margin=12,
        )
        buttons.set_layout(Gtk.ButtonBoxStyle.END)
        deny = Gtk.Button(label="Deny")
        deny.connect("clicked", lambda *_: dlg.response(0))
        once = Gtk.Button(label="Allow once")
        once.connect("clicked", lambda *_: dlg.response(1))
        buttons.add(deny)
        buttons.add(once)

        menu = Gtk.Menu()
        ids = {}
        nid = 10
        for label, secs in TIMED_CHOICES.items():
            item = Gtk.MenuItem(label=label)
            ids[nid] = f"timed:{secs}"
            item.connect("activate", lambda _w, i=nid: dlg.response(i))
            menu.append(item)
            nid += 1
        for label, scope in [("This session", "session"), ("Always", "always")]:
            item = Gtk.MenuItem(label=label)
            ids[nid] = scope
            item.connect("activate", lambda _w, i=nid: dlg.response(i))
            menu.append(item)
            nid += 1
        menu.show_all()

        more = Gtk.MenuButton(label="Allow for…")
        more.set_popup(menu)
        buttons.add(more)

        dlg.get_content_area().add(buttons)
        dlg.show_all()
        response = dlg.run()

        if response in (0, Gtk.ResponseType.DELETE_EVENT, Gtk.ResponseType.NONE):
            scope = "deny"
        elif response == 1:
            scope = "once"
        else:
            scope = ids.get(response, "deny")
        dlg.destroy()
        return scope


# --------------------------------------------------------------------------
# request handling
# --------------------------------------------------------------------------

class Broker:
    def __init__(self, args):
        self.state = State(args.state)
        self.audit = Audit(args.audit)
        self.prompt = Prompt(args.no_gui, args.test_answer, args.test_request)
        self.sock_path = args.socket

    def handle(self, line):
        parts = line.split()
        if not parts:
            return "ERR empty\n"
        cmd = parts[0].upper()

        if cmd == "PING":
            return "OK pong\n"

        if cmd == "LIST":
            grants = self.state.list()
            out = [f"OK {len(grants)}"]
            out += [f"grant {scope} {path}" for scope, path in grants]
            return "\n".join(out) + "\n"

        if cmd == "GRANT":
            if len(parts) != 3:
                return "ERR usage: GRANT <always|timed:seconds> <path>\n"
            scope, path = parts[1], parts[2]
            if scope == "session":
                self.state.add(path, "session", ephemeral=True)
                return f"OK granted session {path}\n"
            if scope == "always":
                self.state.add(path, "always")
                return f"OK granted always {path}\n"
            if scope.startswith("timed:"):
                secs = int(scope.split(":", 1)[1])
                self.state.add(path, "timed", secs)
                return f"OK granted timed:{secs} {path}\n"
            return "ERR scope must be always or timed:<seconds>\n"

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
        if answer in ("read-write", "rw"):
            self.audit.log("request", [path], pid, uid, "allow", "read-write")
            return "ALLOW read-write\n"
        if answer in ("read-only", "ro"):
            self.audit.log("request", [path], pid, uid, "allow", "read-only")
            return "ALLOW read-only\n"
        self.audit.log("request", [path], pid, uid, "deny", None)
        return "DENY\n"

    def ask(self, rest):
        if len(rest) < 4:
            return "ERR usage: ASK <op> <pid> <uid> <path>...\n"
        op, pid, uid = rest[0], rest[1], rest[2]
        paths = rest[3:]

        hits = self.state.matched_grants(paths)
        if hits is not None:
            scope = self._combined_scope(hits)
            prefixes = sorted({h["path"] for h in hits})
            self.audit.log(op, paths, pid, uid, "allow", f"cached {scope}")
            return "ALLOW " + scope + " " + " ".join(prefixes) + "\n"

        answer = self.prompt.ask(op, paths, pid, uid)
        if answer == "deny":
            self.audit.log(op, paths, pid, uid, "deny", None)
            return "DENY\n"

        if answer == "once":
            self.audit.log(op, paths, pid, uid, "allow", "once")
            return "ALLOW once " + " ".join(paths) + "\n"

        prefix = prefix_for(op, paths)
        if answer == "session":
            self.state.add(prefix, "session", ephemeral=True)
            scope = "session"
        elif answer == "always":
            self.state.add(prefix, "always")
            scope = "always"
        elif answer.startswith("timed:"):
            secs = int(answer.split(":", 1)[1])
            self.state.add(prefix, "timed", secs)
            scope = f"timed:{secs}"
        else:
            self.audit.log(op, paths, pid, uid, "deny", f"bad answer {answer}")
            return "DENY\n"

        self.audit.log(op, paths, pid, uid, "allow", f"{scope} {prefix}")
        return f"ALLOW {scope} {prefix}\n"

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

def serve(broker):
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


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    p = argparse.ArgumentParser(description="fsbroker permission broker")
    p.add_argument("--socket", default=os.path.join(root, "run", "broker.sock"))
    p.add_argument("--state", default=os.path.join(root, "run", "broker-state.json"))
    p.add_argument("--audit", default=os.path.join(root, "run", "audit.log"))
    p.add_argument("--no-gui", action="store_true",
                   help="never show a dialog; deny anything not already granted")
    p.add_argument("--test-answer", default=os.environ.get("FSBROKER_TEST_ANSWER"),
                   help="answer every write prompt with this scope (for tests)")
    p.add_argument("--test-request", default=os.environ.get("FSBROKER_TEST_REQUEST"),
                   help="answer every add-request with deny|ro|rw (for tests)")
    args = p.parse_args()

    broker = Broker(args)

    if broker.prompt.available():
        from gi.repository import Gtk
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        signal.signal(signal.SIGTERM, lambda *_: Gtk.main_quit())
        threading.Thread(target=serve, args=(broker,), daemon=True).start()
        print("broker: dialog ready", file=sys.stderr, flush=True)
        Gtk.main()
    else:
        serve(broker)


if __name__ == "__main__":
    main()
