---
name: request-access
description: Ask the user to add a file or folder to this sandbox when it is not currently visible. Use when the user asks to add, grant, or open access to a directory/path (e.g. their Documents, Downloads, a project, an external drive), when a path they mention returns "No such file or directory" even though they say it exists, or when the user says "here's a folder" / "add my <something>".
---

# request-access

This session runs inside an isolated sandbox. Only a fixed set of host
directories is mapped in; everything else returns `ENOENT` (No such file or
directory) even though it exists on the real machine. You cannot see a location
until the user adds it — that is the point, and you must not guess or probe for
paths you were not given.

To ask for a location, run the `fsbroker-request` command. It raises a dialog on
the user's real desktop (outside the sandbox); only the user can approve.

## Usage

```bash
fsbroker-request <absolute-path>              # request read-only access
fsbroker-request <absolute-path> --write      # request read-write access
```

- Prefer **read-only**. Only add `--write` when the user has actually asked you
  to modify files there.
- The path must be absolute, and it must be a **directory** (files are not
  accepted; ask for the folder that contains a file instead).
- Use the user's real path. Inside the sandbox `HOME=/home/agent`, but the user's
  real home is a host directory outside it, so when the user says `~/Documents`
  that is **not** `/home/agent/Documents`. Ask for the absolute path if you are
  not sure — do not guess, and do not translate `~` to the sandbox home.
- If the exact path is ambiguous, ask the user for the absolute path before
  requesting. Do not request wildcards or `/`.

## What happens

The dialog shows the path and the access level. Results:

- `OK added <path> ro|rw` — approved. The path is now visible **for the rest of
  this session** (it is not remembered after the sandbox is closed).
- `OK already-visible` — it was already mapped; just use it.
- `DENY` — the user declined. Do not retry in a loop; tell the user and stop.
- `ERR ...` — a problem (bad path, nothing listening). Report it.

The command exits `0` on `OK`, non-zero on `DENY`/`ERR`.

After a successful `OK added`, wait a moment (about a second) and then use the
path normally (`ls`, `read`, etc.).

## Examples

```bash
# The user says: "add my Downloads folder"
fsbroker-request /home/USER/Downloads

# The user says: "I need you to save into ~/projects/foo"
fsbroker-request /home/USER/projects/foo --write

# Then use it
ls /home/USER/Downloads
```

## Notes

- This command only exists **inside the fsbroker sandbox**. If
  `fsbroker-request` is not found, you are not in that sandbox and this skill
  does not apply — say so instead of improvising.
- Approval adds a read-only mapping by default; a read-only location refuses
  writes and you should not try to work around that.
- Do not request access on your own initiative. Ask the user first, explain
  which path and why, then run the command.
