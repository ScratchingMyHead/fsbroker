# fsbroker — interactive Linux filesystem permission broker

Status: **Phase 3 in progress** — deny-by-default FUSE virtual root, runtime
write grants, and an interactive prompt broker (allow once / 10 min / 1 h /
6 h / 12 h / this session / always) with an audit log. Per-project profiles and
a dedicated UID are still to come.

Project layout:

```
/home/rj/fsbroker
├── README.md
├── vroot/                    the FUSE daemon (Rust, fuser + libfuse3)
├── broker/                   the prompt broker (Python + Gtk3)
│   ├── broker.py             dialogs, durable grants, audit log
│   ├── brokerctl             host-side client
│   ├── fsbroker-request      in-sandbox "add a folder" client
│   └── broker.sh             start/stop the broker
├── docs/
│   ├── environment.md        discovered host facts
│   ├── phase1-report.md      prototype results, evidence and gaps
│   └── phase2-report.md      virtual root, test matrix, bugs, permission model
├── run/
│   ├── vroot/                the live FUSE mount point
│   ├── tmp/                  real host dir bound as the sandbox /tmp
│   ├── broker-state.json     durable (always / timed) grants
│   ├── audit.log             one JSON line per broker decision
│   └── log/                  daemon, GUI and test logs
└── prototype/
    ├── phase1/               sandbox that runs the actual GUI
    │   ├── common.sh         sandbox definition (bubblewrap)
    │   ├── enter.sh          enter the sandbox with a shell/command
    │   ├── launch-gui.sh     launch the installed OpenCode desktop GUI
    │   └── demo/
    │       ├── home/         isolated writable home (mapped to /home/agent)
    │       └── project/      real backing directory for the test project
    └── phase2/               virtual root prototype
        ├── vroot.toml        the mapping set (identity paths)
        ├── mount.sh          start the daemon
        ├── umount.sh         stop the daemon
        ├── enter.sh          enter the sandbox (root = FUSE mount)
        ├── launch-gui.sh     launch the GUI (root = FUSE mount)
        ├── vrootctl          host-only client for runtime grants
        ├── etc-view/         curated /etc snapshot
        └── test.sh           54-check host + sandbox matrix
```

Inside `vroot/src`: `config.rs` (TOML mapping), `fs.rs` (the FUSE
filesystem), `policy.rs` (runtime grant table), `ctl.rs` (host-only control
socket), `broker.rs` (prompt-broker client), `sys.rs`
(`openat2`/`stat`/`getdents64` syscall wrappers).

## Phase 1: run it

```bash
cd /home/rj/fsbroker/prototype/phase1
./enter.sh                 # interactive shell inside the sandbox
./enter.sh -c 'ls /'       # run one command
./launch-gui.sh            # launch the actual OpenCode desktop GUI
```

The GUI opens as a second, independent OpenCode instance. The existing host
instance keeps running; the sandbox uses its own home, profile, database and
CLI service port (49474).

## What Phase 1 proves

- The actual OpenCode 2.2.0 Electron GUI starts and renders inside a
  bubblewrap namespace.
- It uses a fresh profile and database under the private home.
- It can open the bind-mounted test project, start a session, call a model and
  run its Shell tool inside the sandbox.
- The Shell tool sees `hostname=opencode-sandbox`, only the sandbox home, and
  cannot see `/home/rj/su`, `/home/rj/.ssh`, `/root`, `/var` or `/mnt`.
- Shell writes reach the real backing directory immediately.
- Git, Python, Node and other subprocesses run inside the sandbox.
- Closing the GUI tears down its own namespace and leaves the host instance
  untouched.

See `docs/phase1-report.md` for the test matrix and the security gaps that must
be closed before this is more than a prototype.

## Phase 2: run it

```bash
cd /home/rj/fsbroker/prototype/phase2
./mount.sh                 # start the FUSE daemon on run/vroot
./enter.sh                 # shell whose / is the virtual root
./enter.sh -c 'ls /'       # run one command
./launch-gui.sh            # launch the GUI on the virtual root
./umount.sh                # stop the daemon
bash test.sh               # 54-check host + sandbox matrix

./vrootctl list                     # show runtime grants
./vrootctl grant session /home/rj/su   # allow writes there until the daemon stops
./vrootctl grant once   /home/rj/su    # allow the next write only
./vrootctl revoke /home/rj/su          # close a grant
```

Runtime grants widen a read-only mapping without editing the config. The
control socket (`run/vroot.sock`, mode `0600`) is host-only: it is not part of
the mapping set, so nothing inside the sandbox can reach it.

## Phase 3: the prompt broker

```bash
../../broker/broker.sh start       # show the dialog (Gtk3)
../../broker/broker.sh start --no-gui   # headless: deny anything not already granted
../../broker/broker.sh stop

../../broker/brokerctl list
../../broker/brokerctl grant always /home/rj/su   # pre-authorise, no prompt
../../broker/brokerctl revoke /home/rj/su
```

When the daemon refuses a mutation on a read-only path, it asks the broker,
which shows a host-side dialog naming the operation, path, requesting process,
working directory and user. The choices are **Deny**, **Allow once**, and
**Allow for…** → 10 minutes, 1 hour, 6 hours, 12 hours, This session, Always.

- `once` is exactly the one operation.
- `session`/`timed`/`always` are remembered by the broker: the daemon holds no
  copy, so a revoke or expiry takes effect on the next operation. `timed` and
  `always` are written to `run/broker-state.json` and survive a broker restart;
  `session` is dropped when the broker stops.
- Every decision is appended to `run/audit.log` as JSON (timestamp, op, paths,
  pid/comm/cwd, uid, decision, scope).
- The broker socket (`run/broker.sock`, mode `0600`) is host-only and is not in
  the mapping set.
- When a broker socket is configured, a read-only mapping reports its real mode
  bits instead of masking the write bits — otherwise `default_permissions`
  would refuse the write in the kernel and the daemon would never get to ask.
  The daemon stays the enforcement point. With no broker configured, the old
  mode-bit masking still applies.

### Asking for a folder from inside

A path that is not in the mapping set is `ENOENT` and is **not** prompted for
(prompting on every `opencode.json`-style probe would be unusable). Instead the
agent asks explicitly:

```bash
fsbroker-request /home/rj/Documents           # read-only
fsbroker-request /home/rj/Documents --write   # read-write
```

The command is on the sandbox `PATH`. It connects to the daemon's request
socket (the one socket that *is* bound into the sandbox), which asks the broker.
The broker shows an **access request** dialog (`Deny` / `Add read-only` /
`Add read-write`); approval adds the folder to the virtual root for the rest of
the daemon's run, read-only or read-write as chosen. The request socket can only
*ask*; it never widens access on its own.

The mapping set lives in `prototype/phase2/vroot.toml`. Each `[[mount]]`
without `virtual_path` appears inside the sandbox at the same absolute path it
has on the host, so the project keeps its real path. Anything not listed is
`ENOENT`.

## What Phase 2 proves

- One FUSE mount, not a pile of binds, is the sandbox root; bubblewrap only
  adds `/proc`, `/dev`, `/tmp`, `/run`, `/dev/shm` and X11.
- Unmapped paths are denied by the kernel-facing filesystem, including through
  absolute symlinks, `..` traversal and `/proc/self/root`.
- The mapped project is readable and writable at its real host path inside and
  outside the sandbox; writes land in the backing directory immediately.
- Read-only mappings (`/usr`, `/bin`, `/lib`, `/opt/OpenCode`, the `/etc`
  snapshot) refuse writes at the daemon and in the permission bits.
- Executables, scripts and dynamic runtimes run correctly from the mount; the
  edit-temp-then-rename pattern works, as does `stat` on unlinked-but-open
  files.
- The actual OpenCode GUI runs with the virtual root as `/`, starts its CLI
  background service and loads a session through it.
- Writes to a read-only mapping can be opened at runtime by an operator through
  the host-only control socket (`vrootctl`), one operation at a time or for the
  session; the grant is enforced both on the host view of the mount and inside
  the sandbox, and revoked again when it expires.
- A refused write triggers a host-side prompt (the broker); its answer is
  enforced by the daemon, recorded in the audit log, and — for the durable
  scopes — remembered by the broker rather than by the daemon.

See `docs/phase2-report.md` for the test matrix, the bugs found, and the
per-project/per-session permission model.

## Known limitations (important)

- **X11 is not isolated.** The sandbox talks to the host X server, so it can
  observe and control other X clients. Accepted for now; Xephyr or a private
  compositor is the fix.
- **The network namespace is shared.** The sandbox sees the host loopback and
  LAN.
- **Same UID.** The prototype runs as UID 1000, not a dedicated agent account,
  so the boundary is the namespace, not the UID.
- **`/tmp` is a real host directory** bound over the mount, explicitly accepted
  for this prototype.
- **One daemon, no supervisor.** If the daemon dies while mounted, the mount
  point reports `ENOTCONN` until it is unmounted.
- **The FUSE loop is single-threaded** (`fuser` 0.14), so while a prompt is
  open the whole mount is frozen for every other process until it is answered
  or times out (5 minutes). A multi-threaded loop is the fix.
- **X11 is shared, so the prompt is spoofable.** The sandbox can see and click
  the dialog. Prompts are a usability feature today; Xephyr/a private display
  is a prerequisite before the prompt is a security boundary.
- **A denied path is cached for 60 s.** A retry loop fails fast instead of
  re-prompting, at the cost that a grant made afterwards can take up to a
  minute to be honoured for that exact path.
- **1 s attribute TTL.** The kernel caches lookups for one second, so after a
  grant, revoke, delete or rename the old attributes can be served for up to
  one second. Tooling and tests wait it out.
- **Phase 1's bind-mount layout still exists** as `prototype/phase1`; Phase 2
  supersedes it.
- Electron runs with `--no-sandbox` and remote debugging enabled for the
  prototype. Neither belongs in the final launcher.

