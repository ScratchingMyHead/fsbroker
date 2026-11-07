#!/usr/bin/env bash
# Enter the Phase 1 sandbox with a shell or an arbitrary command.
#
# Usage:
#   ./enter.sh                 # interactive shell
#   ./enter.sh -c 'ls -la /'   # run a command
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"

if [ "$#" -eq 0 ]; then
  set -- /bin/bash
elif [ "$1" = "-c" ]; then
  # Convenience: ./enter.sh -c 'command' means a shell command string.
  set -- /bin/bash "$@"
fi

sandbox_bwrap_common
exec bwrap "${BWRAP_ARGS[@]}" -- "$@"
