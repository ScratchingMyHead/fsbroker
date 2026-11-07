#!/usr/bin/env bash
# Enter the Phase 2 sandbox: a shell whose / is the FUSE virtual root.
#
#   ./enter.sh            interactive
#   ./enter.sh -c 'ls /'  one command
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"

CMD=("$@")
if [ "$#" -eq 0 ]; then
  CMD=(/bin/bash)
elif [ "$1" = "-c" ]; then
  CMD=(/bin/bash "$@")
fi
sandbox_exec "${CMD[@]}"
