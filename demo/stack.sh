#!/usr/bin/env bash
# Starts a separate copy of the demo for recording, so your working dashboard data is never touched:
#   RagMonitor on :8100 with its own database, the Skerry site on :4100 with its own API token.
# Then it resets to a green dashboard and wires the bookings export in behind the bot.
#   bash demo/stack.sh up      # start and prepare
#   bash demo/stack.sh down    # stop both
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export RAGMON_DB="$ROOT/dashboard/demo-recording.db"
LOGS="$ROOT/demo/out/logs"

case "${1:-up}" in
  up)
    mkdir -p "$LOGS"
    rm -f "$RAGMON_DB"
    (cd "$ROOT/dashboard" && CHAT_SITE_URL=http://localhost:4100 nohup python3 -m uvicorn server:app --port 8100 > "$LOGS/monitor.log" 2>&1 &)
    for _ in $(seq 1 30); do curl -sf localhost:8100/api/status >/dev/null && break; sleep 1; done
    TOKEN=$(cd "$ROOT/dashboard" && python3 scripts/apptoken.py create "Skerry travel site" | grep -o 'rm_live_[A-Za-z0-9_-]*')
    (cd "$ROOT/website-chatbot" && RAGMON_URL=http://localhost:8100 RAGMON_TOKEN="$TOKEN" nohup python3 -m uvicorn server:app --port 4100 > "$LOGS/site.log" 2>&1 &)
    for _ in $(seq 1 30); do curl -sf -o /dev/null localhost:4100/ && break; sleep 1; done
    cd "$ROOT/dashboard"
    RAGMON_URL=http://localhost:8100 python3 scripts/demo.py seed
    RAGMON_URL=http://localhost:8100 python3 scripts/demo.py connect
    echo "ready: dashboard http://localhost:8100  site http://localhost:4100"
    ;;
  down)
    pkill -f "uvicorn server:app --port 8100" || true
    pkill -f "uvicorn server:app --port 4100" || true
    echo "stopped"
    ;;
esac
