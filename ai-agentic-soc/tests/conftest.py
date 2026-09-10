from __future__ import annotations

import os
from pathlib import Path

_TEST_DIR = Path("/tmp/ai-agentic-soc-tests")
_TEST_DIR.mkdir(exist_ok=True)
for f in _TEST_DIR.iterdir():
    if f.is_file():
        f.unlink()

os.environ["IDENTITY_DATABASE_URL"] = f"sqlite:///{_TEST_DIR}/identity.db"
os.environ["EDR_DATABASE_URL"] = f"sqlite:///{_TEST_DIR}/edr.db"
os.environ["DATABASE_URL"] = f"sqlite:///{_TEST_DIR}/investigations.db"
os.environ["WAZUH_VERIFY_TLS"] = "false"
os.environ["WAZUH_API_USER"] = "test"
os.environ["WAZUH_API_PASSWORD"] = "test"