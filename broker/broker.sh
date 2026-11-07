#!/usr/bin/env bash
# Start/stop the fsbroker prompt broker.
#
#   broker.sh start [broker.py args...]   # default: show dialogs
#   broker.sh start --no-gui              # deny anything not already granted
#   broker.sh stop
#   broker.sh status
set -euo pipefail

BASE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd -- "$BASE/.." && pwd)
PIDFILE="$ROOT/run/broker.pid"
LOG="$ROOT/run/broker.log"

running() { [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; }

case "${1:-start}" in
  start)
    shift || true
    if running; then
      echo "broker already running (pid $(cat "$PIDFILE"))"
      exit 0
    fi
    setsid nohup python3 "$BASE/broker.py" "$@" >>"$LOG" 2>&1 &
    echo $! > "$PIDFILE"
    echo "broker started (pid $(cat "$PIDFILE")); log: $LOG"
    ;;
  stop)
    if running; then
      kill "$(cat "$PIDFILE")" 2>/dev/null || true
      rm -f "$PIDFILE"
      echo "broker stopped"
    else
      rm -f "$PIDFILE"
      echo "broker not running"
    fi
    ;;
  status)
    if running; then echo "broker running (pid $(cat "$PIDFILE"))"; else echo "broker not running"; exit 1; fi
    ;;
  *)
    echo "usage: broker.sh {start|stop|status} [args...]" >&2
    exit 2
    ;;
esac
