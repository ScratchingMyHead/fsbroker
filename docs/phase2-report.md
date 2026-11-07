# Phase 2 report — deny-by-default FUSE virtual root

Date: 2026-11-07
Host: Linux Mint 22.3, Cinnamon, X11, user `rj` (UID 1000), kernel 6.17.0-35
OpenCode: 2.2.0 desktop (`/opt/OpenCode/ai.opencode`, Electron 44.9.1)
Toolchain: Rust 1.99.1, `fuser` 0.14 against libfuse3 3.14

## Goal

Replace Phase 1's pile of read-only binds with one kernel-enforced virtual
root: a FUSE mount that exposes only the folders the user added, keeps them at
their **real host paths**, and returns `ENOENT` for everything else. The GUI
and the FUSE daemon stay outside the restricted environment; the sandbox has
the FUSE mount as its `/`.

## Architecture

```
host (unrestricted)
├── vroot daemon (Rust)  ── mounts run/vroot ────────────────┐
└── launch-gui.sh ── bwrap: mount run/vroot at /            │
                     + fresh /proc, /dev, /tmp, /run        │  FUSE
                     + X11 socket/cookie                    │  requests
                     └── ai.opencode (Electron) ────────────┘
```

`vroot` (`/home/rj/fsbroker/vroot`) is a small FUSE filesystem:

- **Deny by default.** A path exists only if it is a configured mount, a
  descendant of one, or a synthetic directory that is an ancestor of a mount.
  Everything else is `ENOENT`; there is no fallback to the host root.
- **Identity mapping.** `virtual_path` defaults to the host path, so
  `/home/rj/fsbroker/prototype/phase1/demo/project` means the same thing inside
  and outside. The only remapped path is the agent's home, `/home/agent`
  (host: `prototype/phase1/demo/home`), which deliberately does not exist on
  the host so it cannot be confused with `/home/rj`.
- **Synthetic parents list only what was added.** `/home/rj` shows `fsbroker`
  and nothing else; the host directory is never enumerated.
- **Confinement is done by the kernel, not by the daemon's string checks.**
  Every access resolves the path under the mapping's `dirfd` with
  `openat2(..., RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS)`. Absolute symlinks,
  `..` climbing and `/proc/self/root/...` magic links are clamped to the
  mapping, so a symlink whose target is outside it stays `ENOENT`.
- **Writability is per mount, or per runtime grant.** Read-only mounts refuse
  every mutation in the daemon *and* have their write bits masked in `getattr`,
  so a caller cannot even test its way into a write. A runtime grant (Phase 3)
  widens that for one path prefix, either for the next matching operation
  (`once`) or for the daemon's lifetime (`session`).
- **Devices and special files are refused.** `mknod` (FIFOs, sockets, device
  nodes) is denied.
- **Mutations that change the tree are tracked.** `rename` rewrites the
  path→inode index; `unlink`/`rmdir` mark nodes as orphans so `stat` on an
  unlinked-but-open file keeps working (details below).

`prototype/phase2/common.sh` then wraps the mount with bubblewrap: it binds the
FUSE root at `/` and adds only runtime filesystems (`/proc`, `/dev`, `/tmp`,
`/run`, `/dev/shm`) and the X11 socket/cookie. Unlike Phase 1, `/usr`, `/bin`,
`/lib`, `/lib64`, `/opt/OpenCode` and `/etc` are **not** bind-mounted: they are
entries inside `vroot.toml`, and `/etc` is a curated snapshot
(`prototype/phase2/etc-view`) so `/etc/shadow` and host keys never exist.

## Test matrix

`prototype/phase2/test.sh` — **54 passed, 0 failed** (full output in
`run/log/phase2-tests.txt`). Tests run twice: directly against the host mount
and inside the bubblewrap sandbox. The grant and broker checks were added in
Phase 3 and are marked below.

Host side:

| Check | Result |
|---|---|
| Virtual root is a mount point | Pass |
| Unmapped `/home/rj/.ssh` is `ENOENT` | Pass |
| Host `/etc/shadow` is `ENOENT` | Pass |
| `/home/rj` lists only the added subtrees (`.config fsbroker su`) | Pass |
| Read-only home directories (`~/su`, `~/.config`) are readable | Pass |
| Writes to read-only `/home/rj/su` and `/home/rj/.config` are refused | Pass |
| Control socket answers `PING`, grant table starts empty | Pass (Phase 3) |
| Session grant allows a write; revoke closes it again | Pass (Phase 3) |
| `once` grant is consumed by the first write | Pass (Phase 3) |
| Grants require an absolute path | Pass (Phase 3) |
| Mapped project readable at its real host path | Pass |
| Write through FUSE reaches the real backing directory | Pass |
| Read-only `/usr` refuses writes | Pass |
| Synthetic `/` refuses writes | Pass |
| Binaries served by the mount can be executed | Pass |

Inside bubblewrap (root = virtual root):

| Check | Result |
|---|---|
| Shell starts | Pass |
| `/` is the virtual root | Pass |
| Project directory has its real path inside (`pwd`) | Pass |
| Exec and a dynamic runtime work (ELF + Python) | Pass |
| Project readable inside | Pass |
| Read-only home directories are readable inside | Pass |
| Write to read-only `/home/rj/su` is refused inside | Pass |
| Unmapped path denied inside | Pass |
| `/etc/shadow` denied inside | Pass |
| Read-only `/usr` enforced inside | Pass |
| Control socket is not visible inside the sandbox | Pass (Phase 3) |
| Session grant is enforced inside; revoke is refused inside | Pass (Phase 3) |
| Sandbox write is visible on the host backing dir | Pass |
| Atomic rename and unlinked-but-open files behave | Pass |
| Symlinks to unmapped host paths stay inside the root | Pass |
| Symlinks to mapped paths still resolve | Pass |
| Broker answers `PING`; a denied prompt refuses the write | Pass (Phase 3) |
| Broker session grant allows a write; revoke refuses it again | Pass (Phase 3) |
| Broker timed grant allows a write, then expires | Pass (Phase 3) |
| Broker session grant is enforced inside the sandbox | Pass (Phase 3) |
| An `always` grant survives a broker restart | Pass (Phase 3) |
| The broker wrote an audit log | Pass (Phase 3) |
| A sandbox request adds a path; it becomes visible inside | Pass (Phase 3) |
| A read-only request refuses writes | Pass (Phase 3) |
| A denied request reports failure and stays invisible | Pass (Phase 3) |
| Sandbox has its own mount namespace | Pass |
| Grandchild inherits the same mount namespace | Pass |
| Child cannot unshare a new mount namespace | Pass |

Boundary findings, reported rather than failed because they are accepted
Phase 2 gaps:

- The host loopback service on 49374 is reachable from the sandbox.
- The host X11 socket is reachable from the sandbox.

## Bugs found and fixed

These were real defects that only show up when a large application uses the
mount, and they are the most useful outcome of running the GUI.

1. **Every `execve` through the mount returned `EINVAL`.**
   The kernel sets an internal `__FMODE_EXEC` bit (`0x20`) in
   `fuse_open_in.flags`. `open(2)` tolerates unknown bits, but `openat2(2)`
   rejects them, and the daemon forwards the flags to `openat2` on the backing
   file. Proven with `open(0x8020)` succeeding and `openat2(0x8020)` returning
   `EINVAL`. Fixed with `BACKING_OPEN_FLAGS`: only flags that mean something
   for the backing file are forwarded. A libfuse3 passthrough control
   filesystem exec'd fine, which is how the bug was isolated to the daemon
   rather than the kernel or the mount options.

2. **Creation nested deeper than one level landed in the wrong directory.**
   `mkdir`/`create`/`symlink`/`rename` called a helper that opened the parent
   *of the parent*. The operation succeeded one level too high and the
   following attribute lookup failed, so the kernel saw `ENOENT`. Fixed with a
   separate `open_dir` helper (callers that need `(parent, name)` still use
   `open_parent`).

3. **Read immediately after a write-temp-then-rename failed with `ENOENT`.**
   Every editor and the OpenCode CLI write a temp file and rename it over the
   destination; the kernel keeps the inode it already has for the file and
   addresses it by its old node id. The daemon still had the old path for that
   inode. Fixed by rewriting the path index on `rename` (`rename_subtree`) and
   marking the overwritten destination inode as unlinked. This was exactly why
   the GUI's CLI service shut down: it created `service.json.<uuid>.tmp`,
   renamed it, and could not read it back.

4. **Naive deletion broke `stat` on unlinked-but-open files.**
   The first fix dropped all bookkeeping for a deleted path. `fstat` on an
   open file after `unlink` then returned `ENOENT` (the kernel revalidates
   attributes after the directory entry changes). Correct behaviour needs
   both: a new file created at the same path must get a *fresh* inode (or the
   kernel can serve cached pages from the deleted file), while the old inode
   must keep answering `stat` until the kernel forgets it. Solved with orphan
   nodes: the path→inode entry is dropped on unlink, the node is kept and
   `stat` is answered from an open handle (or the last known attributes), and
   the node is freed only in `forget` when the lookup count reaches zero.

5. **Two test-harness false results.** The symlink test read the mount from the
   *host*, where absolute symlink targets resolve against the host root; that
   is the host looking in, not a confinement test. And the namespace test
   compared IDs from two separate `enter.sh` invocations. Both fixed.

## GUI result

The actual OpenCode desktop GUI runs with the FUSE mount as its root:

- Window renders on `opencode-sandbox`; DevTools on 9333; screenshot
  `run/log/phase2-gui.png`.
- The CLI background service starts, registers
  `/home/agent/.local/state/opencode/service.json`, and listens on 49474;
  the renderer loads a session transcript through it.
- The daemon log shows the app's normal traffic (tens of thousands of
  `READ`/`WRITE`/`OPEN` requests) and denies lookups of paths it is not
  allowed to see (e.g. `/home/rj/projects`, `.opencode`, `opencode.json` from
  a session recorded under Phase 1's old path).
- The session shown after launch is a leftover from Phase 1 and points at
  `/home/rj/projects/demo`, which no longer exists by design. That is the
  expected "session location unavailable" message, not a mount failure; a new
  project selection uses the real path.

## Gaps and risks

Deliberate prototype shortcuts, not claims of protection:

- **X11 is shared.** The sandbox can observe and control other X clients.
  Accepted for now because GUI use is rare; a nested X server (Xephyr) is the
  fix, and nothing else depends on the shared display.
- **Network namespace is shared.** The host loopback and LAN are reachable in
  both directions. FUSE itself needs no network.
- **`/tmp` is a real host directory** (`run/tmp`) bound over the mount. The
  user explicitly accepted this; it is not isolated.
- **Same UID (1000).** `vroot` is a per-user mount without `allow_other`, so
  the daemon enforces *path* policy only. Any host process running as `rj`
  can read the mount directly; the boundary is the sandbox namespace, not the
  UID. A dedicated agent UID is required before `allow_other` or
  multi-principal policy makes sense.
- **Daemon lifecycle.** If the daemon dies while mounted, the mount point
  reports `ENOTCONN` until it is unmounted. There is no supervisor or
  auto-restart yet; `mount.sh`/`umount.sh` are manual.
- **Attribute cache.** TTL is 1 s. Short enough for interactive use, long
  enough to avoid a request storm; a cache-invalidation strategy
  (`FUSE_NOTIFY_INVAL_*`, absent from `fuser` 0.14) is not implemented, so
  external changes can take up to a second to appear. One sharp edge: if the
  host creates a file through the mount and deletes it again, the sandbox can
  hold the stale positive dentry for up to a second and get `ENOENT` on the
  first attempt to recreate that exact name. It needs a host-side create+delete
  and an in-sandbox recreate inside the same second, so it is a tooling
  nuisance, not a common path; scripts wait out the TTL.
- **Read-only runtime entries are still host data.** `/usr`, `/opt/OpenCode`
  and the `/etc` snapshot are real host content; they are mapped deliberately
  and read-only, but the final system should derive them from an image or
  package set rather than the host.
- **A prompt freezes the mount.** `fuser` 0.14 runs one request loop, so while
  the dialog is open every other operation on the mount waits (up to the 5
  minute timeout). Accepted for v1; a threaded loop is the fix.
- **The prompt is spoofable while X11 is shared.** The sandbox can screenshot
  and click the dialog. It is a usability gate, not yet a security boundary.
- **Audit log is a plain append.** `run/audit.log` is structured JSON, but there
  is no rotation, signing, or tamper protection yet.

## Permission model: per project and per session

The enforceable unit on Linux is a **process tree with its own mount
namespace and (ideally) its own UID**. FUSE requests carry a PID and UID, but
the PID is only meaningful inside the daemon's PID namespace and the UID is
shared by everything the user runs, so neither can distinguish two OpenCode
sessions inside one process.

Two things that are already possible with the current design:

1. **Different permissions per project in one sandbox.** Each `[[mount]]` has
   its own `writable` flag, so project A can be read-write while project B is
   read-only in the same virtual root. The virtual root is just a config file,
   and any set of paths can coexist.
2. **A different world per launch.** Choosing a different `vroot.toml` (plus
   the matching backing directories) at launch gives a project its own set of
   visible and writable paths, with deny-by-default doing the rest.

What cannot work: two sessions sharing one OpenCode process with different
*enforced* permissions. The agent's tool calls all execute as the same process
tree, so a per-session rule inside that process would be advisory only. Per
session enforcement needs one of:

- one sandbox (bwrap + its own FUSE mount) per project/profile, which is the
  straightforward route: `launch-gui.sh <profile>` builds the mapping set from
  the profile, and the GUI cannot see anything else;
- one FUSE daemon per UID/principal with policy at the daemon, which requires
  a dedicated account per principal (or `allow_other` plus a UID map) and is
  the right long-term answer for multiple agents on one host;
- in-process per-session rules only for UX (warning, confirmation), never as
  the security boundary.

Recommended shape for the next phase: a **profile** = config file + sandbox +
daemon instance, and one profile per project. OpenCode-specific session
awareness can sit on top as *labeling* (which profile a session belongs to),
while enforcement stays with the namespace and the FUSE policy.

## Phase 3: runtime write grants

The first half of Phase 3 keeps the static mapping set as the *visibility*
policy and adds a runtime layer for *access*:

- `policy.rs` holds a small grant table: a path prefix plus a scope, `once` or
  `session`. `peek` tests coverage without consuming; `consume` removes a
  matching `once` grant. A `session` grant lives until the daemon stops.
- `ctl.rs` serves a line protocol on a `0600` Unix socket next to the mount
  point (`run/vroot.sock`): `PING`, `LIST`, `GRANT <once|session> <path>`,
  `REVOKE <path>`, `CLEAR`. The socket is host-only by construction — it is not
  part of the mapping set, so it does not exist inside the sandbox (tested).
- `fs.rs` routes every mutation through `authorize_write` (or
  `authorize_rename` for the two-path rename case). A writable mount passes; a
  covering grant passes and, if it was `once`, is consumed; otherwise the
  operation fails `EACCES`. `getattr` shows the grant in the mode bits, so a
  caller's `access(W_OK)` is consistent with what an `open` will do.
  `utimens` is metadata-only and stays allowed on read-only paths.
- `prototype/phase2/vrootctl` is the host-side client.

This is the transport the interactive prompt uses: the daemon denies, asks the
broker, and applies exactly the grant the user chose (`once` for "just this",
`session` for "this session"). The broker — prompt UI, durable grants, audit
log — runs outside the sandbox; the deny path stays in the kernel-facing
daemon.

### The prompt broker

`broker/broker.py` (Python + Gtk3; `python3-gi` is already present, so nothing
has to be downloaded, and the enforcement stays in Rust) implements the other
half:

- Listens on `run/broker.sock` (`0600`, host-only). The daemon's new
  `broker.rs` client sends `ASK <op> <pid> <uid> <path>...` and reads
  `ALLOW <scope> <path>...` or `DENY`.
- The dialog names the operation, path, requesting **process** (`pid` and
  `comm` from the FUSE request), its **working directory** and **uid**, and
  offers `Deny`, `Allow once`, and `Allow for…` → 10 minutes, 1 hour, 6 hours,
  12 hours, This session, Always. Screenshots:
  `run/log/broker-dialog.png`, `run/log/broker-menu.png`.
- **The broker owns every scope wider than one operation.** `session` is an
  in-memory grant; `timed` and `always` are written to
  `run/broker-state.json`. The daemon keeps no copy, so a revoke or an expiry
  is effective on the very next operation. On a repeated request the broker
  answers from state without prompting, so a build that writes a directory 500
  times prompts once.
- Every decision is appended to `run/audit.log` as a JSON line.
- A prefix grant covers a directory: for a file path the broker uses its
  parent directory (or, for a rename, the common ancestor of both paths).

One consequence worth stating: **`default_permissions` had to give way for the
enforcement point to be reachable.** Masking the write bits on a read-only
mount makes the kernel refuse `open(O_WRONLY)` before the filesystem is
consulted, so the daemon never gets a chance to ask. When a broker socket is
configured, the daemon therefore reports the real mode bits and decides every
mutation itself; with no broker configured it keeps masking, so the cheap
kernel-level denial is still there by default.

### Requesting new paths from inside

A mutation of a *visible* read-only path can be prompted for; a path that is
not in the mapping set at all is `ENOENT` and is **not** prompted for — an
application probes dozens of irrelevant paths at startup and prompting on each
would be a storm. The explicit channel is `fsbroker-request`:

- The daemon serves a second socket, `run/request.sock`. Unlike the control
  socket it *is* bound into the sandbox (and the client at
  `/home/agent/.local/bin/fsbroker-request`), because its whole job is to carry
  an *ask* out. It cannot grant anything on its own.
- The client sends `REQUEST <path> <ro|rw>`; the daemon takes the caller's
  pid/uid from `SO_PEERCRED` and forwards the request to the broker, which
  shows an **access request** dialog (`Deny` / `Add read-only` /
  `Add read-write`).
- Approval opens the host directory and appends it to the live mount table;
  from then on it is an ordinary mapping (read-only unless the user chose
  read-write) for the rest of the daemon's run. It is not written back to
  `vroot.toml`.
- Overlapping requests are harmless: a path already covered by a mapping (or a
  synthetic ancestor) answers `already-visible` and adds nothing.

Adding a mapping at runtime exposed a real bug: the mount vector was re-sorted
by path length on every insertion, but `NodeKind::Host(mi)` indices are baked
into inodes that already exist. After one request the indices shifted and
`/bin/bash` resolved under the wrong mount (`execvp: Is a directory`). The fix
is to append and never reorder — with nesting forbidden, at most one mount can
match a path, so order does not matter for lookup.

## Next milestone

Phase 3 is functionally complete. What remains: a multi-threaded FUSE loop so a
prompt does not freeze the mount, a request channel for *unmapped* paths
(`fsbroker-request`), then profiles and launcher integration — one config per
project, a dedicated agent account (or `allow_other` + UID-based policy), a
supervised daemon, and closing the X11 and network gaps.
