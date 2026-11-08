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
bin/fsbroker ... status                              # what the agent can access
bin/fsbroker-status --run-dir ~/fsbroker_opencode    # the same, standalone
```

`bin/fsbroker` also has `shell`, `run`, `mount`, `umount`, `broker`,
`approvals` and `root-shell` for manual use and troubleshooting; none of it is
needed for normal operation.

## A root shell that still sees only the sandbox

A running session can be entered as real root from the host via tmux (WITH A GREAT DEAL OF CAUTION). The sandboxed agent can access the root tmux with send-keys and capture-pane (more details when you run it). To do so the user should run:

```bash
fsbroker/root-tmux.sh
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

## Known limitations

- **X11 is not isolated.** The sandbox talks to the host X server, so it can
  observe and control other X clients, including the prompt.
- **The network namespace is shared.** The sandbox sees the host loopback and
  LAN (that is also why its OpenCode service must use a different port).
- **Same UID.** It runs as your UID, so the boundary is the mount namespace, not
  the UID.
- **The FUSE loop is single-threaded** (`fuser` 0.14): while a prompt is open the
  whole mount waits for the answer (up to 5 minutes).
- **1 s attribute TTL** (`fuser` has no invalidation), so changes can take up to
  a second to be visible.
- **One daemon, no supervisor.** If the daemon dies while mounted, the mount
  point reports `ENOTCONN` until it is unmounted (`fsbroker umount` handles it).

