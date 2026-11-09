#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

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
if ! python -c "import streamlit" >/dev/null 2>&1; then
  python -m pip install -r requirements.txt
fi
exec python -m streamlit run app.py --server.address 127.0.0.1
