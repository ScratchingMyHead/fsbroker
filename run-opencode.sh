#!/usr/bin/env bash
# Desktop menu entry point: run the sandboxed OpenCode GUI with its permission
# broker, then tear everything down when the window closes.
#
# All runtime state lives in /home/rj/fsbroker_opencode (not in this repo).
# The config is /home/rj/.config/fsbroker/vroot.toml.
exec /home/rj/fsbroker/bin/fsbroker \
  --run-dir /home/rj/fsbroker_opencode \
  --config /home/rj/.config/fsbroker/vroot.toml \
  --home /home/rj/fsbroker_opencode/home \
  session
