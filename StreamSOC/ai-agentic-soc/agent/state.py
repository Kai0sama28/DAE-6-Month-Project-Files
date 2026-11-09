"""Persistent watcher state.

Keeps the agent restartable: the indexer cursor, the ids already seen (so a
restart does not re-investigate the same alerts) and the incident counter.
Stored under ``data/`` which is gitignored.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

MAX_SEEN_IDS = 20000


class AgentState:
    """Small JSON-backed state store (single writer, guarded by a lock)."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self._data: dict[str, Any] = {
            "cursor": None,
            "seen_ids": [],
            "incident_seq": 0,
            "last_incident": None,
            "recent_keys": [],
            "runs": 0,
        }
        self._load()

    def _load(self) -> None:
        try:
            if self.path.exists():
                loaded = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    self._data.update(loaded)
        except (OSError, ValueError):
            pass

    def save(self) -> None:
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(self.path.suffix + ".tmp")
            tmp.write_text(json.dumps(self._data, indent=2, default=str), encoding="utf-8")
            tmp.replace(self.path)

    # -- cursor ------------------------------------------------------------

    @property
    def cursor(self) -> Optional[str]:
        return self._data.get("cursor")

    def set_cursor(self, value: Optional[str]) -> None:
        if value:
            self._data["cursor"] = value

    # -- seen ids ----------------------------------------------------------

    @property
    def seen_ids(self) -> set:
        return set(self._data.get("seen_ids") or [])

    def mark_seen(self, ids: list) -> None:
        if not ids:
            return
        current = list(self._data.get("seen_ids") or [])
        known = set(current)
        for alert_id in ids:
            if alert_id and alert_id not in known:
                known.add(alert_id)
                current.append(alert_id)
        if len(current) > MAX_SEEN_IDS:
            current = current[-MAX_SEEN_IDS:]
        self._data["seen_ids"] = current

    # -- incidents ---------------------------------------------------------

    def next_incident_seq(self) -> int:
        seq = int(self._data.get("incident_seq") or 0) + 1
        self._data["incident_seq"] = seq
        return seq

    def record_incident(self, incident: dict[str, Any]) -> None:
        self._data["last_incident"] = incident

    def bump_runs(self) -> int:
        runs = int(self._data.get("runs") or 0) + 1
        self._data["runs"] = runs
        return runs

    # -- incident de-duplication -------------------------------------------

    def is_recent_key(self, key: str, window_seconds: float) -> bool:
        """True when the same incident key was handled inside the window."""
        if not key:
            return False
        now = datetime.now(timezone.utc).timestamp()
        for entry in self._data.get("recent_keys") or []:
            if entry.get("key") != key:
                continue
            try:
                seen_at = float(entry.get("ts") or 0)
            except (TypeError, ValueError):
                continue
            if now - seen_at <= window_seconds:
                return True
        return False

    def remember_key(self, key: str) -> None:
        if not key:
            return
        keys = list(self._data.get("recent_keys") or [])
        keys.append({"key": key, "ts": datetime.now(timezone.utc).timestamp()})
        self._data["recent_keys"] = keys[-200:]

    @property
    def data(self) -> dict[str, Any]:
        return dict(self._data)
