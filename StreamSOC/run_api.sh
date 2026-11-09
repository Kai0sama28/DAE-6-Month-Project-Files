#!/usr/bin/env bash
# Start the FastAPI triage control plane. The agent engine lives in
# ai-agentic-soc/, so this script runs from that folder.
set -euo pipefail
cd "$(dirname "$0")/ai-agentic-soc"

PYTHON="${PYTHON:-python3}"
if [ ! -x .venv/bin/python ]; then
  if [ -d .venv ]; then
    echo "Existing .venv is not a Linux virtualenv (it may have been created on Windows). Remove it or run the Windows script." >&2
    exit 1
  fi
  if ! "$PYTHON" -m venv .venv; then
    echo "Could not create .venv. Install python3-venv (Debian/Ubuntu) or use Python 3.11-3.13." >&2
    exit 1
  fi
fi
# shellcheck disable=SC1091
. .venv/bin/activate
python -m pip install --upgrade pip >/dev/null
python -m pip install -r requirements.txt
exec python -m services.triage_api
