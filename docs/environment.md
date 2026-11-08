# Discovered host environment

Recorded before any system-level change. This is the environment the
prototype targets.

| Item | Value |
|---|---|
| Distribution | Linux Mint 22.3 "Zena" (Ubuntu 24.04 / noble base) |
| Kernel | 6.17.0-35-generic |
| Desktop | Cinnamon |
| Display server | X11 (`DISPLAY=:0`, `XDG_SESSION_TYPE=x11`) |
| User | `rj` / UID 1000 / GID 1000 |
| Home | `/home/rj` (ecryptfs-backed) |
| OpenCode desktop | 2.2.0 at `/opt/OpenCode/ai.opencode` (Electron 44.9.1) |
| OpenCode CLI | 1.19.4 at `/home/rj/.opencode/bin/opencode`; desktop bundles its own CLI at `/opt/OpenCode/resources/opencode-cli` and installs it under the desktop profile |
| Bubblewrap | 0.9.0 (`/usr/bin/bwrap`) |
| FUSE | `/dev/fuse` present, `fusermount3` 3.14.0, `libfuse3-3` installed |
| Unprivileged user namespaces | enabled (`/proc/sys/kernel/unprivileged_userns_clone=1`) |
| Rust toolchain | not currently installed |

Other relevant facts:

- `/dev/dri/card1` and `renderD128` exist (GPU available).
- The X11 socket is `/tmp/.X11-unix/X0`; the cookie is `/home/rj/.Xauthority`.
- Audio is PipeWire with `pipewire-pulse`. The sockets are
  `/run/user/1000/pipewire-0` (and `pipewire-0-manager`) and
  `/run/user/1000/pulse/native`; `/dev/snd/*` is `root:audio` and access is
  granted to the logged-in user by ACL. `/etc/resolv.conf` is a symlink into
  `/run/systemd/resolve/`, which is why DNS needs that path passed through too.
- `exiftool`-style desktop integration is not required for the prototype.
- No Docker/Podman socket was observed as part of the agent environment.
- The host `/home/rj/su` working tree is unrelated to this project; the project
  lives at `/home/rj/fsbroker`.

## OpenCode packaging note

The desktop application is Electron, not Tauri (although it contains a Tauri
migration flag in its settings). It reads its profile from
`~/.config/ai.opencode.desktop` and stores the CLI in
`~/.config/ai.opencode.desktop/cli/<version>-x64/opencode-cli`.

The GUI is a Chromium renderer that talks to a local OpenCode server. The
server and all tool/terminal subprocesses are children of the desktop process,
so namespace confinement must cover the whole process tree, not only the
window.
