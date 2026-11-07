# Phase 1 report — OpenCode GUI in a restricted environment

Date: 2026-11-07
Host: Linux Mint 22.3, Cinnamon, X11, user `rj` (UID 1000)
OpenCode: 2.2.0 desktop (`/opt/OpenCode/ai.opencode`, Electron 44.9.1)

## Goal

Prove that the actual OpenCode desktop GUI can run inside a namespace-based
environment and that its children, shell commands and file access stay inside
that environment. No FUSE, no permission broker and no dedicated agent UID are
used yet.

## Sandbox construction

`prototype/phase1/common.sh` builds the environment with bubblewrap:

- `--unshare-all --share-net` (private mount, PID, user, IPC, UTS and cgroup
  namespaces; network is shared for this phase).
- New `/proc`, minimal `/dev`, private `/tmp`, `/run` and `/dev/shm`.
- Read-only bind of `/usr`, `/lib`, `/lib64`, `/bin`, `/sbin`, `/opt/OpenCode`
  and a small allow-list of `/etc` files/directories.
- A private writable home at `/home/rj` (inside the sandbox).
- One real project directory, `/home/rj/fsbroker/prototype/phase1/demo/project`,
  bind-mounted at `/home/rj/projects/demo`.
- The X11 socket and cookie (Phase 1 only; see gaps).
- No bind of the host `/`, `/home`, `/root`, `/var`, `/mnt`, `/run/user` or
  desktop session bus.

The GUI is launched by `launch-gui.sh` with `--no-sandbox`, `--disable-gpu`,
`--ozone-platform=x11` and a debug port for automation.

## Test matrix

| Requirement | Result | Evidence |
|---|---|---|
| Actual GUI starts and renders | Pass | `log/sandbox-gui-02.png`; window on `opencode-sandbox` |
| Fresh profile, no host database | Pass | sandbox DB 4 KB vs host 1.99 GB; separate user-data dir |
| Host instance unaffected | Pass | both ran concurrently on ports 49374 / 49474 |
| GUI can open the test project | Pass | selected `/home/rj/projects/demo` in GTK chooser; project appears in sidebar |
| Session creation | Pass | `log/sandbox-session-2.png` |
| Model call works | Pass | free model returned a response and invoked the Shell tool |
| Shell tool runs inside sandbox | Pass | `pwd=/home/rj/projects/demo`, `hostname=opencode-sandbox`, `/etc/hostname` matches |
| Host home not visible | Pass | `ls /home/rj` shows only sandbox entries; `/home/rj/su` absent |
| Writes reach the real backing dir | Pass | `echo SANDBOX_PROOF > .../proof.txt`; host sees `project/proof.txt` |
| Git works | Pass | `git rev-parse`, `git log`, `git status` inside sandbox |
| Other subprocesses | Pass | Python 3.12, Node, Perl, bash/sh all run |
| File watching | Pass (CLI) | `watcher started path=/home/rj/projects/demo` in CLI log |
| Child process confinement | Pass | mount/PID/user/IPC/UTS namespaces differ from host; CLI's `/proc/<pid>/root` exposes only sandbox home |
| Clean shutdown | Pass | closing the window removes bwrap, Electron, CLI and children; host instance still alive |
| Integrated terminal panel | Not present in this desktop build | View menu only has Reload/DevTools/zoom/fullscreen; agent Shell tool is the verified shell path |

Screenshots and logs are in `prototype/phase1/demo/log/`.

## Namespace evidence

```
mnt   host=mnt:[4026531832]   sandbox=mnt:[4026533120]
pid   host=pid:[4026531836]   sandbox=pid:[4026533123]
user  host=user:[4026531837]  sandbox=user:[4026533125]
ipc   host=ipc:[4026531839]   sandbox=ipc:[4026533122]
uts   host=uts:[4026531838]   sandbox=uts:[4026533121]
net   host=net:[4026531833]   sandbox=net:[4026531833]   (shared — gap)
```

`ls /proc/<sandbox-cli>/root/home/rj` shows only the sandbox home;
`/proc/<sandbox-cli>/root/home/rj/su` and `.ssh` do not exist.

## Problems found and resolved

1. **Service port collision.** OpenCode's CLI defaults to 49374, which the
   host instance already used, and the sandbox shares the host loopback. The
   sandbox was configured with `opencode service set port 49474` (stored in its
   own `~/.config/opencode/service.json`). This is a workaround; the real fix is
   network namespace isolation.
2. **First window was only a splash.** Starting the GUI while the host instance
   owned the port produced a splash plus "Desktop IPC handler failed". Pinning a
   free port fixed it. The error path is useful: it shows the app fails closed
   rather than silently sharing the host service.
3. **No session bus.** Electron and GTK log D-Bus/dconf/accessibility warnings.
   They do not prevent launch, project selection or shell use. The GTK folder
   chooser works directly without a portal. A narrow D-Bus proxy will be needed
   for desktop integration later.
4. **models.dev catalog timeout.** The CLI logs a 10 s timeout fetching
   `models.dev`; the host link is slow. Model calls still work. Not fatal.
5. **No terminal panel in this build.** The desktop UI exposes sessions,
   review, context and settings but no terminal toggle on Linux. The agent's
   Shell tool is the shell mechanism and was verified inside the sandbox.

## Security gaps to close before Phase 2/6

These are deliberate prototype shortcuts, not claims of protection:

- **X11**: full access to the host display server. The sandbox can read the
  keyboard, screenshot other windows and inject input into host applications.
  Use a nested X server (Xephyr is installed), a private Wayland compositor, or
  a narrowly proxied display.
- **Network**: shared net namespace means host loopback and LAN access. The
  sandbox could reach the host OpenCode service and other localhost services.
  Use a private net namespace plus an explicit proxy for model/API traffic.
- **UID**: same UID as the desktop user. A dedicated unprivileged agent account
  is required for FUSE `allow_other` and for credential separation.
- **Electron sandbox**: `--no-sandbox` was required inside bwrap for this
  prototype. The final launcher should restore Chromium's sandbox where
  possible or document why it cannot be used.
- **Remote debugging**: port 9333 is bound on the shared loopback during the
  prototype. Remove it from production launches.
- **Read-only host binds**: `/usr`, `/opt/OpenCode` and selected `/etc` files
  are still host data. They are read-only and needed at runtime, but the final
  virtual root must expose them deliberately rather than by host path.
- **GPU**: `/dev/dri` was bound even with `--disable-gpu`; drop it next time.

## Next milestone

Phase 2: a FUSE filesystem that presents a configurable virtual root, maps
whitelisted host directories into it, denies unmapped paths by default, and
demonstrates the same project access and writes through the FUSE mount — still
without the permission broker.
