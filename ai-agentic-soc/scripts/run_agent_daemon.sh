#!/bin/bash
#
# Supervised launcher for the AI-Agentic SOC background triage agent.
#
# - restarts the agent if it ever exits (crash, indexer blip, OOM)
# - prevents the Mac from idle-sleeping so notifications still fire during a
#   long unattended demo window (uses `caffeinate -i`)
# - writes a supervisor log next to the agent's own daemon log
#
# Usage:
#   scripts/run_agent_daemon.sh            # run forever (restart on exit)
#   scripts/run_agent_daemon.sh 14400      # run for at most 4 hours, then stop
#
# Stop it with:
#   pkill -f agent.runner ; pkill -f run_agent_daemon.sh

set -u

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$DIR" || exit 1

PY="$DIR/venv/bin/python"
LOG_DIR="$DIR/data"
mkdir -p "$LOG_DIR"
SUPERVISOR_LOG="$LOG_DIR/agent_supervisor.log"

MAX_SECONDS="${1:-0}"   # 0 = run forever
START_TS=$(date +%s)

log() {
    printf '[%s] %s\n' "$(date -u '+%Y-%m-%d %H:%M:%SZ')" "$*" >> "$SUPERVISOR_LOG"
}

log "supervisor starting (max_seconds=$MAX_SECONDS, pid=$$)"

# Keep the machine from idle-sleeping while the supervisor is alive.
if command -v caffeinate >/dev/null 2>&1; then
    caffeinate -i -w "$$" &
    log "caffeinate -i engaged (pid $!)"
fi

RESTARTS=0
while true; do
    if [ "$MAX_SECONDS" -gt 0 ]; then
        ELAPSED=$(( $(date +%s) - START_TS ))
        if [ "$ELAPSED" -ge "$MAX_SECONDS" ]; then
            log "time budget reached (${ELAPSED}s) — stopping supervisor"
            break
        fi
    fi

    RESTARTS=$((RESTARTS + 1))
    log "launching agent (attempt $RESTARTS)"
    "$PY" -m agent.runner >> "$LOG_DIR/agent_daemon.log" 2>&1
    RC=$?
    log "agent exited rc=$RC"

    # A clean stop (SIGTERM handled -> rc 0) means the user asked us to stop.
    if [ "$RC" -eq 0 ]; then
        log "clean exit — not restarting"
        break
    fi

    log "restarting in 5s"
    sleep 5
done

log "supervisor stopped"
