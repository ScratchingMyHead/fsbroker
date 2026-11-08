# fsbroker — interactive Linux filesystem permission broker

Run a program inside a deny-by-default filesystem sandbox and let a host-side
broker grant it more access, one decision at a time.

The sandbox root is a FUSE virtual root (`vroot`): it exposes only the
directories listed in a config file, at their real host paths, and returns
`ENOENT` for everything else. Nothing outside the list exists to the sandboxed
program. When it tries to change something read-only, or asks to add a folder,
a prompt appears on your real desktop and the answer is enforced by the kernel
(the FUSE daemon), not by the application.

Status: working end to end — deny-by-default FUSE root, runtime write grants,
an interactive prompt broker (once / 10 min / 1 h / 6 h / 12 h / this session /
always) with an audit log, and an in-sandbox "add a folder" request. Per-project
profiles and a dedicated UID are still to come.

## Layout

The repository is **code only**. Everything it writes at runtime lives in a run
directory you choose.

```
fsbroker/
├── bin/
│   ├── fsbroker           the host entry point (mount, broker, run, status, …)
│   ├── fsbroker-status    one view of what the agent can currently access
│   └── fsbroker-request   the in-sandbox "add a folder" client
├── vroot/                 the FUSE daemon (Rust, fuser + libfuse3)
├── broker/                the prompt broker (Python + Gtk3)
│   ├── broker.py          dialogs, durable grants, audit log
│   └── brokerctl          host-side client
├── config/
│   └── vroot.example.toml a starting config
├── examples/
│   └── skill/request-access/SKILL.md  example agent skill for asking to add a folder
├── docs/                  design notes and phase reports
└── prototype/             development-only experiments (phase 1/2), not used
                           at runtime
```

A run directory (e.g. `~/fsbroker_opencode`) holds the mount point, sockets,
pids, broker state, audit log, logs, the sandbox home, and the generated
`etc-view`/`placeholders`. None of it is in the repository.

## Getting started

Build the daemon (Rust; needs `cargo` and libfuse3):

```bash
bin/fsbroker build
```

Copy the example config and edit the `[[mount]]` list:

```bash
mkdir -p ~/.config/fsbroker
cp config/vroot.example.toml ~/.config/fsbroker/vroot.toml
$EDITOR ~/.config/fsbroker/vroot.toml
```

Two placeholders are expanded before the daemon reads the config:

- `${run}` — the run directory
- `${home}` — the sandbox's writable home (default `<run>/home`)

Locations (override with flags or the environment):

| | flag | environment | default |
|---|---|---|---|
| run directory | `--run-dir` | `FSBROKER_RUN_DIR` | `~/.local/state/fsbroker` |
| config | `--config` | `FSBROKER_CONFIG` | `~/.config/fsbroker/vroot.toml` |
| sandbox home | `--home` | `FSBROKER_HOME` | `<run>/home` |

## Using it

```bash
bin/fsbroker --run-dir ~/fsbroker_opencode session      # mount + broker + the app, tear down on exit
bin/fsbroker --run-dir ~/fsbroker_opencode shell        # a shell inside the sandbox
bin/fsbroker --run-dir ~/fsbroker_opencode run ls /     # one command inside
bin/fsbroker --run-dir ~/fsbroker_opencode status       # what the agent can access
bin/fsbroker --run-dir ~/fsbroker_opencode approvals    # remembered write approvals
bin/fsbroker --run-dir ~/fsbroker_opencode paths        # resolved locations
```

`approvals` also takes `grant <always|session|timed:seconds> <path>`, `revoke
<path>` and `clear`, so you can pre-authorise a write without waiting for a
prompt. (The lower-level client is `broker/brokerctl`, which needs `--run-dir`
or `FSBROKER_RUN_DIR`.)

`session` with no argument launches the OpenCode desktop GUI; give it a command
to run that instead:

```bash
bin/fsbroker --run-dir ~/fsbroker_opencode session -- /usr/bin/python3 app.py
```

Manual lifecycle, if you prefer:

```bash
bin/fsbroker ... mount        # start the daemon
bin/fsbroker ... broker start # start the prompt broker (Gtk dialogs)
bin/fsbroker ... shell        # ... do things
bin/fsbroker ... broker stop
bin/fsbroker ... umount
```

A desktop menu item is a one-liner that calls `session`; keep the run dir and
config in flags. There is also a small `run-opencode.sh` in the repo that does
exactly that for OpenCode.

## The two things the agent can do

**Change something read-only.** A write to a read-only mapping blocks and raises
a dialog naming the operation, path, requesting process, working directory and
user. Choices: `Deny`, `Allow once`, and `Allow for…` → `10 minutes` / `1 hour`
/ `6 hours` / `12 hours` / `This session` / `Always`.

- `once` is exactly the one operation.
- `This session` is remembered by the broker until it stops.
- `timed` and `Always` are stored in `<run>/broker-state.json` and survive a
  restart (`Always` = don't ask again in future runs).
- Every decision is appended to `<run>/audit.log` as one JSON line.

What a decision covers, and for how long:

- **Allow once** — exactly that one operation on that path; nothing is
  remembered.
- **This session / 10 minutes … / Always** — scoped to the **directory**. Acting
  on a file grants the directory that contains it; acting on a directory grants
  that directory; a `rename` grants the common parent of both ends. So approving
  one write in a folder stops the prompt for the rest of that folder, for as long
  as the grant lasts.
- **Deny** — remembered by the daemon for **60 seconds**, per **exact path** (the
  item the operation named, and anything under it if it is a folder). A retry in
  that window fails immediately with `EACCES` instead of prompting; a different
  file in the same folder still prompts, and after 60 seconds the denied path
  prompts again. Denials are not persisted and clear when the daemon stops.

**Add a folder it cannot see.** Paths outside the mapping set are `ENOENT` and
are deliberately *not* prompted for. The agent asks explicitly:

```bash
fsbroker-request /home/rj/Documents           # read-only
fsbroker-request /home/rj/Documents --write   # read-write
```

(on `PATH` inside the sandbox). An **access request** dialog offers `Deny` /
`Add read-only` / `Add read-write`; approval adds the mapping for the rest of
the session. It is not written back to the config. The request socket is the
only socket bound into the sandbox, and it can only ask.

The agent will not know to use `fsbroker-request` unless you tell it, so give it
a skill (or system prompt) that says when and how. An example skill is in
`examples/skill/request-access/SKILL.md`. For the OpenCode desktop app, copy it
into the sandbox home's skill directory, e.g.
`<run>/home/.config/opencode/skill/request-access/SKILL.md`. The only
fsbroker-specific part is the `fsbroker-request` command; adapt the wording for
any other agent that can run shell commands.

## How it is enforced

- **Deny by default.** A path exists only if it is a configured mount, a
  descendant of one, or a synthetic directory that is an ancestor of one.
  Everything else is `ENOENT`; there is no fallback to the host root.
- **The kernel does the confinement.** Every host access resolves under the
  mapping's directory fd with `openat2(..., RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS)`,
  so absolute symlinks, `..` and `/proc/self/root` are clamped to the mapping.
- **Writability is per mount, or per runtime grant.** Read-only mounts refuse
  every mutation; a runtime grant (from `vrootctl`, or the broker) widens that
  for a path prefix. When a broker is configured the daemon reports real mode
  bits and decides every mutation itself — otherwise `default_permissions`
  would refuse the write in the kernel and the daemon could never prompt.
- **The broker and its state are outside the sandbox.** The control socket
  (`vroot.sock`) is host-only; nothing inside can grant itself anything.

`bin/fsbroker-status` (or `fsbroker status`) prints a single view of everything:
the visible mounts (permanent config + this session's requests) and the active
write approvals. Anything not listed there is `ENOENT` to the agent.

Inside `vroot/src`: `config.rs` (mapping + live mount table), `fs.rs` (the FUSE
filesystem), `policy.rs` (runtime grants), `ctl.rs` (host-only control socket),
`req.rs` (sandbox request socket), `broker.rs` (prompt-broker client), `sys.rs`
(`openat2`/`stat`/`getdents64`).

## Known limitations (important)

- **X11 is not isolated.** The sandbox talks to the host X server, so it can
  observe and control other X clients, including the prompt. Accepted for now;
  Xephyr or a private compositor is the fix before the prompt is a security
  boundary.
- **The network namespace is shared.** The sandbox sees the host loopback and
  LAN (that is also why its OpenCode service must use a different port).
- **Same UID.** It runs as your UID, so the boundary is the mount namespace, not
  the UID. A dedicated agent account is the long-term answer.
- **The FUSE loop is single-threaded** (`fuser` 0.14): while a prompt is open the
  whole mount waits for the answer (up to 5 minutes). A threaded loop is the fix.
- **A denied path is cached for 60 s**, so a retry loop fails fast instead of
  re-prompting.
- **1 s attribute TTL** (`fuser` has no invalidation), so changes can take up to
  a second to be visible.
- **One daemon, no supervisor.** If the daemon dies while mounted, the mount
  point reports `ENOTCONN` until it is unmounted (`fsbroker umount` handles it).

## Development

`prototype/` keeps the history: phase 1 (a plain bubblewrap sandbox) and phase 2
(the virtual root, its reports and the 54-check test matrix). It is not used at
runtime and its harness predates the run-directory model, so it still needs
repointing at `bin/fsbroker`. See `docs/phase2-report.md` for the design,
bugs found while running a real Electron app on the mount, and the
per-project/per-session permission model.
