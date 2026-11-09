# fsbroker — interactive Linux filesystem permission broker

Run a harness or other app inside a deny-by-default filesystem sandbox and let
a host-side broker grant it more access to the actual filesystem with a desktop
popup. This provides protection against an agentic harness accidentally harming
data outside allowed locations without fully restricting the agent to a virtual
filesystem. e.g. performing system administration on the host system without
dangerously broad file access. This would not stand up to a malicious agent
intentionally trying to circumvent it.

The sandbox root is a FUSE virtual root (`vroot`): it exposes only the
directories listed in a config file, at their real host paths, and returns
`ENOENT` for everything else. Nothing outside the list exists to the sandboxed
program. When it tries to change something read-only, or asks to add a folder,
a prompt appears on your desktop and the answer is enforced by the kernel
(the FUSE daemon), not by the application.

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

- `${run}` — the run directory, including the virtual root
- `${home}` — the sandbox's writable home (default `<run>/home`)

Locations (override with flags or the environment):

| | flag | environment | default |
|---|---|---|---|
| run directory | `--run-dir` | `FSBROKER_RUN_DIR` | `~/.local/state/fsbroker` |
| config | `--config` | `FSBROKER_CONFIG` | `~/.config/fsbroker/vroot.toml` |
| sandbox home | `--home` | `FSBROKER_HOME` | `<run>/home` |

## Using it

Tailor `run-opencode.sh` to the harness you wish to use and point a
desktop menu item at it.

The launcher sets where the runtime lives, which config to use, and the program to
run, then calls:

```bash
bin/fsbroker ... session -- <program> [args]
```

`session` mounts the virtual root, starts the broker, runs the program, and
unmounts and stops the broker again when it exits.

Everything harness-specific lives in `run-opencode.sh` — copy it and change the
program to sandbox something else. `bin/fsbroker` itself knows nothing about
OpenCode.

The two commands worth knowing:

```bash
bin/fsbroker ... status            # what the agent can access
bin/fsbroker-status                # the same, standalone
```

`bin/fsbroker-status` without `--run-dir` finds the running sessions for you:
a mounted session appears in the mount table as `vroot <run-dir>/mount`, so one
report is printed per mounted session (there is usually one). Passing
`--run-dir` (or setting `FSBROKER_RUN_DIR`) still reports exactly that
directory, mounted or not.

`bin/fsbroker` also has `shell`, `run`, `mount`, `umount`, `broker`,
`approvals` and `root-shell` for manual use and troubleshooting; none of it is
needed for normal operation.

## Managing the rules

```bash
./manage_rules.sh                  # or: bin/fsbroker ... rules
```

One window per running session, showing the same three things as `status`: the
visible mounts, the write approvals, and the denials. Anything that did not come
from the config you wrote has a **Remove** button:

| shown as | came from | Remove does |
|---|---|---|
| `config` | your config file | — (not offered) |
| `approved` | the sidecar, from a remembered request | takes it out of the sidecar *and* unmounts it now |
| `session request` | an access request this session | unmounts it now |
| a rule | a prompt's allow/deny | deletes the rule |

So removability follows from where a rule lives, rather than a list of exceptions
someone has to maintain: your file is yours and the manager never writes to it,
and the sidecar contains only things you approved from the popup.

The permission dialog has a **Manage rules…** button that opens it, which is the
point of it being a separate process: you can go and take back a rule you just
granted without answering the prompt in front of you, and neither window blocks
the other.

Removing a mount takes effect for everything the agent looks up from then on.
Files it already has open keep working until it closes them — the same promise a
revoked grant makes, and the same caveat as deleting an open file.

## A root shell that still sees only the sandbox

A running session can be entered as real root from the host via tmux (WITH A GREAT DEAL OF CAUTION). The sandboxed agent can access the root tmux with send-keys and capture-pane (more details when you run it). To do so the user should run:

```bash
fsbroker/tmux-root.sh
```

It `sudo nsenter`s into the sandbox's mount namespace, so the shell sees only
the sandbox mapped paths: anything unmapped is `ENOENT`, read-only mappings still refuse
writes, and write prompts still come from the broker. Privileges are the host's,
so root can deliberately leave the namespace; the point is that it cannot reach
anything by accident.

This needs `allow_other = true` in the config and `user_allow_other`
uncommented in `/etc/fuse.conf` — FUSE otherwise refuses the mount to any uid
but yours. With `allow_other` on, the mount is reachable by other local uids, so
the run directory is tightened to `0700`.

## The two things the agent can do

**Change something read-only.** A write to a read-only mapping blocks and raises
a dialog naming the operation, path, requesting process, working directory and
user. It has three controls:

- **Applies to** — how wide the decision is. The first row is the narrowest: the
  file itself, or for a `rename` the folder the two ends share. Below it is one
  row per ancestor folder, up to the mount that contains the path (the last row
  is labelled as the whole mapping). Above the mapping there is nothing to
  reach, and a rule there would silently cover every mapped path beneath it, so
  the list stops there.
- **Duration** — `once`, `session`, `timed` (with a menu for `10 minutes` /
  `1 hour` / `6 hours` / `12 hours`) or `always`.
- **Deny** or **Allow**.

- `once` is exactly that one operation, and remembers nothing.
- `session` is remembered by the broker until it stops.
- `timed` and `always` are stored in `<run>/broker-state.json` and survive a
  restart (`always` = don't ask again in future runs).
- Every decision is appended to `<run>/audit.log` as one JSON line.

What a rule covers, and for how long:

- **once** — that one operation only; nothing is remembered, so the next
  identical operation asks again (allow or deny alike).
- **session / 10 minutes … / always** — the chosen path **and everything under
  it**. Choosing a file row is exactly that file (the matcher compares path
  components, so `/a/foo` does not cover `/a/foobar`); choosing a folder row
  covers its whole subtree, which is how you approve one file, one project, or
  a whole mapping.
- **Deny** works the same way: denying a folder stops prompts for everything
  under it for as long as the denial lasts, and a retry fails with `EACCES`
  without a dialog. `once` denies a single operation.
- The most specific rule wins, and a deny anywhere in an operation's paths beats
  an allow.
- Renaming something moves the rules that named it: a rule for `/a/f` becomes a
  rule for the new path, and rules under a renamed folder follow it too.
- `fsbroker approvals` (or `fsbroker status`) lists the current rules, denials
  included.

**Add a folder it cannot see.** Paths outside the mapping set are `ENOENT` and
are deliberately *not* prompted for. The agent asks explicitly:

```bash
fsbroker-request /home/joe/Documents           # read-only
fsbroker-request /home/joe/Documents --write   # read-write
```

(on `PATH` inside the sandbox). An **access request** dialog offers `Deny` /
`Add read-only` / `Add read-write`, plus a **Remember it for future sessions**
checkbox. Without it the mapping lasts for this session. With it, it is also
written to a sidecar beside your config — `<config>.d/mounts.toml` — so the next
session mounts it from the start.

Your config file is never rewritten by a dialog. That is what the sidecar is
for: everything in it is a decision you made from the popup, so everything in it
is safe for the rule manager to remove, and nothing in it can be a mount the
sandbox needs to start. The request socket is the only socket bound into the
sandbox, and it can only ask.

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
- **The kernel does the confinement.** Each host access resolves under its
  mapping's directory fd with `openat2(..., RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS)`,
  so `..`, absolute targets and `/proc/self/root` cannot escape that mapping's
  subtree on the host. Symlink targets are followed in the sandbox's own tree,
  which is what lets a link point into another mapping (how `/etc/alternatives`
  resolves) while an unmapped host path stays unreachable.
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

## Real files, and the three exceptions

The virtual root serves the host's own files; nothing is copied, so nothing can
go stale. Three things need more than a mapping:

- **The read-only bulk is bound straight from the host**, bypassing the vroot:
  `/usr/lib`, `/usr/lib64`, `/usr/libexec`, `/usr/share`, `/opt/OpenCode`, `/lib`
  and `/lib64` (the list is `NATIVE_MOUNTS` in `bin/fsbroker`, and only paths the
  config actually maps are bound). The reason is the daemon's descriptor budget:
  it holds one file descriptor for *every open file in the sandbox*, so its
  `RLIMIT_NOFILE` is the sandbox's shared budget, and libraries are the bulk of
  what any program opens — every process maps about 135 of them. Measured on a
  running session: 551 of the daemon's 712 descriptors were
  `/usr/lib/x86_64-linux-gnu`. Serving those from the kernel instead removes
  ~87% of the pressure and takes the single-threaded FUSE loop off the library
  path. `fsbroker-status` shows them as `kernel`.

  The trade is explicit: a bind is a *real* host bind, so root in a `root-shell`
  can `mount -o remount,rw` it and write through — unlike a vroot mount, where
  the daemon still decides no matter what the mount flags say. That is why only
  the paths you never want a prompt for are bound, and `/usr/bin`, `/bin`,
  `/sbin`, `/etc`, `/usr/local` and `/var` are deliberately left on the vroot.
- **A few `/etc` files are bound over the real `/etc`** — `passwd` and `group`
  (so the sandbox user's home is `/home/agent`), `hostname`, `hosts` and
  `machine-id`. Everything else is the host's own `/etc`, read-only. That is
  safe because the sandbox's uid is yours: `/etc/shadow`, `/etc/sudoers` and
  `/etc/ssl/private` are root-only, so they stay unreadable either way. It is
  also more correct than a curated copy, which breaks whatever it forgets — a
  missing `/etc/alternatives` leaves every library symlink through it dangling
  (`libblas`, `lapack`, anything `update-alternatives` manages).
- **Pass-throughs** bind real host objects into the sandbox where a filesystem
  cannot help: unix sockets and device nodes. The daemon can show a socket's
  name, but `connect()` through it fails, because the kernel needs a real socket
  inode, and devices are the same. They also live under `/run` and `/dev`, which
  bubblewrap builds rather than mounts. The ones a desktop needs are on by
  default — the PipeWire/Pulse socket, `/dev/snd`, systemd-resolved's
  `resolv.conf` (which `/etc/resolv.conf` points into), and the GPU's render node
  `/dev/dri/renderD128` — and `[[pass]]` adds more (see the example config). Note
  what the audio ones include: the same socket allows recording, and `/dev/snd`
  is raw hardware access that bypasses the sound server. The render node is the
  one that cannot set display modes; `card0`/`card1` can, and stay in the config.

## Known limitations

- **X11 is not isolated.** The sandbox talks to the host X server, so it can
  observe and control other X clients, including the prompt.
- **The network namespace is shared.** The sandbox sees the host loopback and
  LAN (that is also why its OpenCode service must use a different port).
- **Same UID.** It runs as your UID, so the boundary is the mount namespace, not
  the UID.
- **The FUSE loop is single-threaded** (`fuser` 0.14): while a prompt is open
  everything *on the vroot* waits for the answer (up to 5 minutes). Much less
  painful since the read-only bulk moved to kernel binds, but a process doing a
  lot of I/O on a granted path still blocks others.
- **The daemon's descriptor limit is the sandbox's**, shared by every process in
  it: it holds one descriptor per open file. Both are now raised to the hard
  limit at startup (a launcher otherwise hands out 1024), so it no longer
  rears its head, but a runaway process can still exhaust the pool.
- **1 s attribute TTL** (`fuser` has no invalidation), so changes can take up to
  a second to be visible.
- **One daemon, no supervisor.** If the daemon dies while mounted, the mount
  point reports `ENOTCONN` until it is unmounted (`fsbroker umount` handles it).

