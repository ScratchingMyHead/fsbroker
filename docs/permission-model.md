# Permission model (draft)

Status: implemented. `vroot` refines the static map with runtime grants, and
the host-side prompt broker (`broker/broker.py`) answers refused mutations with
`once`, `session`, `timed` or `always`. Remaining work is the request channel
for unmapped paths and the display-isolation prerequisite below.

## Defaults

| Area | Visible | Default access |
|---|---|---|
| `/home/agent` (agent home) | yes | read-write (scratch space, not user data) |
| `/usr`, `/bin`, `/sbin`, `/lib`, `/lib64`, `/opt/OpenCode` | yes | read-only |
| `/etc` (the host's own) | yes | read-only, with a few files bound over it |
| `/proc`, `/dev`, `/tmp`, `/run`, `/dev/shm` | yes | runtime, added by bwrap |
| pass-throughs (sockets, `/dev/snd`) | yes | bound in as-is; see `[[pass]]` |
| any directory the user adds | yes | **read-only unless `writable = true`** |
| everything else | no (`ENOENT`) | — |

The agent home is the only place it can write without the user adding
anything. An added directory is visible at its real path and read-only until
the user marks it writable; that flag can be static config or granted at
runtime through the broker.

## Operation classes

- **Read** — `open(O_RDONLY)`, `readdir`, `getattr`, `readlink`, read mmap.
  Allowed anywhere the path is visible.
- **Write** — `open` for write, `create`, `write`, `truncate`, `fallocate`.
  Allowed in the agent home and in mounts marked writable.
- **Mutate** — `unlink`, `rmdir`, `rename`, `link`, `symlink`, `mkdir`,
  `chmod`, `chown`, `setxattr`. Allowed exactly where writes are allowed.
- **Exec** — a read followed by mapping; no separate prompt. Executing a
  read-only file does not change it.
- **Metadata-only** — `utimens` (atime/mtime) is allowed; it is how normal
  tools behave and it changes no content.
- **Never** — `mknod` (device nodes, FIFOs, sockets), setuid/setgid changes.

A read-only mount refuses every write and mutate operation, both in the
daemon and in the permission bits it reports. `writable = true` is the
explicit opt-in for write-by-default, per directory.

## Escalation

Two distinct triggers, handled differently on purpose:

1. **A mutation of a visible read-only path.** The daemon can block the
   request and ask the broker. This is the transparent case: the application
   does `open(O_WRONLY)` or `unlink` and simply waits for the answer. Approve
   → the operation proceeds; deny → `EACCES`. The decision is cached as a
   grant so a build that writes the same directory 500 times asks once.
2. **A path that does not exist in the virtual root.** Do **not** prompt on
   every `ENOENT`. Applications probe dozens of irrelevant paths at startup
   (`opencode.json`, `.opencode`, config fallbacks) and prompting on each would
   be unusable, and would leak whether a host path exists. Instead the agent
   asks explicitly — `fsbroker-request <path> [--write]` inside the sandbox.
   The request socket is the one part of the broker bound into the sandbox, and
   it can only ask. Approval adds the mapping at runtime (read-only or
   read-write as the user chooses) for the rest of the daemon's run; `ENOENT`
   is not negatively cached, so the next attempt just works.

Grant shape:

```
(path prefix, operation class, scope = once | session | timed:<seconds> | always)
```

The dialog offers `once` (this one operation), `timed` (10 minutes, 1 hour,
6 hours, 12 hours), `session` (until the broker stops) and `always`. The broker
owns every scope wider than one operation — `session` in memory, `timed` and
`always` in `run/broker-state.json` — and the daemon keeps no copy, so a revoke
or expiry applies to the next operation. A grant on `/home/rj/projects/foo`
does not extend to `/home/rj/projects/bar`. Nothing edits the config behind the
user's back; there is a list/revoke command.

If the prompt is not answered within the timeout (5 minutes at the daemon,
4 minutes at the broker) the operation is denied. A denial is a rule like a
grant: `once` refuses that one operation and remembers nothing, while
`session`, `timed` and `always` are remembered by the broker and refused
without a dialog, scoped to the path the user picked (a file, or a folder and
its subtree). The rule set is what `fsbroker approvals` lists.

## Trust boundary

- The prompt must come from **outside** the sandbox and must not be
  spoofable. With a shared X11 display the sandbox can screenshot the prompt
  and inject clicks into it, so prompt approval only makes sense once the GUI
  runs on its own display (Xephyr or a private compositor). This turns the
  X11 gap from "accepted" into a prerequisite for the broker.
- The broker, its state and its audit log live outside the agent's writable
  set.
- The prompt shows the canonical path, the operation, the requesting pid,
  its command line and cwd, and (when the launcher provides one) a session or
  profile label.
- Policy is evaluated on the path the kernel asks about, which is already
  resolved by the VFS through the virtual root; a symlink inside a writable
  project that points at a read-only directory stays subject to the
  read-only rules.

## Implementation constraints

- `fuser` 0.14 runs the request loop on one thread, so a request blocked on a
  prompt stalls every other operation in the mount. The broker path needs
  either a multi-threaded loop or a version of the daemon that can park a
  request without blocking the rest.
- `default_permissions` masks write bits for read-only mounts, which keeps the
  kernel as the first line of defence — but it also stops the daemon from ever
  seeing the write, so a prompt could not happen. When a broker socket is
  configured the daemon therefore reports the real mode bits and enforces every
  mutation itself; without a broker it keeps masking.
- The broker must never answer a request by reading through the mount
  (deadlock); it works from the daemon's message only.

## Open questions

1. Prompt on mutation only (recommended), or also on reads of paths outside
   the added set? Read-prompting on arbitrary lookups is a prompt-storm risk.
2. Should "always allow" write broker state only (recommended), or edit
   `vroot.toml` directly?
3. Adopt Xephyr as part of the broker milestone (recommended), or ship prompts
   on the shared display and accept spoofing for now?
4. Inside a `writable = true` directory, should deletes still ask separately,
   or is "writable" full trust? (Recommended: full trust, less noise.)
