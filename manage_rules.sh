#!/usr/bin/env bash
# Open the fsbroker rule manager.
#
#   ./manage_rules.sh                 # a window per running session (usually one)
#   ./manage_rules.sh --run-dir DIR   # exactly that run directory
#
# The manager lists what the sandbox can see and what it may change, and removes
# anything that is not from the config: mounts added by an approved access
# request, and the write allow/deny rules the prompt created.
set -euo pipefail

root=$(cd -- "$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")" && pwd)
exec "$root/bin/fsbroker-manage" "$@"
