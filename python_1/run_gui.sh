#!/usr/bin/env bash
set -e

# Launcher for Tracker Keeper GUI that prefers Homebrew Python with Tcl/Tk.
# Usage: ./run_gui.sh

# Default preferred Python (Homebrew)
PREFERRED_PY="/opt/homebrew/bin/python3.11"

# Prevent multiple instances: look for other processes running this script
existing=$(pgrep -f "tracker keeper 2.5 GUI.py" || true)
if [ -n "$existing" ]; then
  echo "GUI already running (PIDs: $existing). Not starting another." >&2
  exit 0
fi

# Allow overriding via env var, e.g. PYTHON=/path/to/python ./run_gui.sh
PYTHON=${PYTHON:-$PREFERRED_PY}

if [ ! -x "$PYTHON" ]; then
  if command -v python3 >/dev/null 2>&1; then
    PYTHON=python3
  else
    echo "No suitable Python found. Install Homebrew python@3.11 or set PYTHON env var." >&2
    exit 1
  fi
fi

echo "Using Python: $(command -v $PYTHON || echo $PYTHON)"
exec "$PYTHON" "tracker keeper 2.5 GUI.py"
