"""Persistent human-in-the-loop decisions.

A decision is stored separately from the generated report so the report stays
an immutable record of what the engine produced. The file lives under
``data/`` (gitignored) and is written atomically.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from services.triage_api.schemas import DecisionRecord


class DecisionStore:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()

    def get(self, incident_id: str) -> Optional[DecisionRecord]:
        with self._lock:
            data = self._load()
        entry = data.get(incident_id)
        if not isinstance(entry, dict):
            return None
        try:
            return DecisionRecord(**entry)
        except (TypeError, ValueError):
            return None

    def set(
        self,
        incident_id: str,
        decision: str,
        analyst: str,
        note: str,
    ) -> DecisionRecord:
        record = DecisionRecord(
            incident_id=incident_id,
            decision=decision,
            analyst=analyst or "analyst",
            note=note or "",
            decided_at=datetime.now(timezone.utc).isoformat(),
        )
        with self._lock:
            data = self._load()
            data[incident_id] = record.model_dump()
            self._write(data)
        return record

    def _load(self) -> Dict[str, Any]:
        try:
            if not self.path.exists():
                return {}
            loaded = json.loads(self.path.read_text(encoding="utf-8"))
            return loaded if isinstance(loaded, dict) else {}
        except (OSError, ValueError):
            return {}

    def _write(self, data: Dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(self.path)
