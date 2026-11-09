"""Data backends for the StreamSOC dashboard.

Two interchangeable backends keep the dashboard useful in every situation:

``ApiBackend``
    Talks to the existing FastAPI triage control plane on 127.0.0.1:8080.
    This is the live mode: it can queue new investigations and poll jobs.

``LocalBackend``
    Reads the generated Markdown/HTML reports and stores decisions in a local
    JSON file. This is the offline/demo mode, so the dashboard still works when
    Wazuh, the agent and the API are not running.

Both return the same case dictionaries, so the views never need to know which
backend is active.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from frontend.report_parser import (
    SEVERITY_RANK,
    aggregate,
    case_sort_key,
    load_case,
    load_cases,
    parse_markdown,
)

try:  # pragma: no cover - exercised only in live mode
    import httpx
except ImportError:  # pragma: no cover
    httpx = None  # type: ignore[assignment]


class BackendError(RuntimeError):
    """Raised when a backend cannot satisfy a request."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _severity_rank(severity: Optional[str]) -> int:
    return SEVERITY_RANK.get((severity or "unrated").strip().lower(), 0)


def _normalise_case(case: Dict[str, Any]) -> Dict[str, Any]:
    normalised = dict(case)
    normalised.setdefault("severity_rank", _severity_rank(normalised.get("severity")))
    normalised.setdefault("mitre_techniques", [])
    normalised.setdefault("mitre_tactics", {})
    normalised.setdefault("timeline", [])
    normalised.setdefault("timeline_count", 0)
    normalised.setdefault("max_level", 0)
    try:
        normalised["correlated_events_int"] = int(
            str(normalised.get("correlated_events") or 0).strip()
        )
    except (TypeError, ValueError):
        normalised["correlated_events_int"] = 0
    return normalised


class LocalBackend:
    mode = "local"

    def __init__(self, reports_dir: Path, decisions_path: Path) -> None:
        self.reports_dir = Path(reports_dir)
        self.decisions_path = Path(decisions_path)
        self._lock = threading.Lock()

    # -- decisions ---------------------------------------------------------
    def _load_decisions(self) -> Dict[str, Dict[str, Any]]:
        try:
            if not self.decisions_path.exists():
                return {}
            loaded = json.loads(self.decisions_path.read_text(encoding="utf-8"))
            return loaded if isinstance(loaded, dict) else {}
        except (OSError, ValueError):
            return {}

    def _write_decisions(self, data: Dict[str, Dict[str, Any]]) -> None:
        self.decisions_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.decisions_path.with_suffix(self.decisions_path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(self.decisions_path)

    def decisions(self) -> Dict[str, Dict[str, Any]]:
        with self._lock:
            return self._load_decisions()

    # -- read --------------------------------------------------------------
    def health(self) -> Dict[str, Any]:
        cases = self.list_cases()
        return {
            "status": "offline",
            "mode": "local",
            "version": "streamsoc-local",
            "reports_dir": str(self.reports_dir),
            "worker_alive": False,
            "queued_jobs": 0,
            "running_jobs": 0,
            "case_count": len(cases),
        }

    def list_cases(self, limit: int = 500) -> List[Dict[str, Any]]:
        cases = load_cases(self.reports_dir, self.decisions())
        cases.sort(key=case_sort_key, reverse=True)
        return cases[:limit]

    def get_case(self, incident_id: str) -> Optional[Dict[str, Any]]:
        report = load_case(self.reports_dir, incident_id, self.decisions())
        return _normalise_case(report) if report else None

    def get_report(self, incident_id: str, fmt: str = "markdown") -> Optional[str]:
        case = self.get_case(incident_id)
        if not case:
            return None
        if fmt == "html":
            html_path = case.get("report_html_path")
            if not html_path:
                return None
            try:
                return Path(html_path).read_text(encoding="utf-8", errors="replace")
            except OSError:
                return None
        return case.get("markdown")

    def record_decision(
        self, incident_id: str, decision: str, analyst: str, note: str
    ) -> Dict[str, Any]:
        if decision not in ("approved", "rejected"):
            raise BackendError("decision must be approved or rejected")
        if not self.get_case(incident_id):
            raise BackendError("case not found: %s" % incident_id)
        record = {
            "incident_id": incident_id,
            "decision": decision,
            "analyst": (analyst or "analyst").strip(),
            "note": (note or "").strip(),
            "decided_at": _now(),
        }
        with self._lock:
            data = self._load_decisions()
            data[incident_id] = record
            self._write_decisions(data)
        return record

    def metrics(self) -> Dict[str, Any]:
        summary = aggregate(self.list_cases())
        summary["generated_at"] = _now()
        summary["jobs"] = {"queued": 0, "running": 0, "succeeded": 0, "failed": 0}
        summary["mode"] = "local"
        return summary

    def list_jobs(self, limit: int = 20) -> List[Dict[str, Any]]:
        return []

    def submit_investigation(self, alert_id: str, force: bool = False) -> Dict[str, Any]:
        raise BackendError(
            "Investigations need the triage API, the Wazuh indexer and the agent. "
            "Start the API (python -m services.triage_api) and switch to API mode."
        )


class ApiBackend:
    mode = "api"

    def __init__(self, base_url: str, timeout: float = 15.0) -> None:
        if httpx is None:
            raise BackendError("httpx is not installed")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _client(self, timeout: Optional[float] = None) -> "httpx.Client":
        return httpx.Client(base_url=self.base_url, timeout=timeout or self.timeout)

    def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
        try:
            with self._client() as client:
                response = client.get(path, params=params)
                response.raise_for_status()
                return response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise BackendError(str(exc)) from exc

    def _post(self, path: str, payload: Dict[str, Any]) -> Any:
        try:
            with self._client(timeout=30.0) as client:
                response = client.post(path, json=payload)
                response.raise_for_status()
                return response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise BackendError(str(exc)) from exc

    def _text(self, path: str, params: Optional[Dict[str, Any]] = None) -> Optional[str]:
        try:
            with self._client() as client:
                response = client.get(path, params=params)
                response.raise_for_status()
                return response.text
        except httpx.HTTPError as exc:
            raise BackendError(str(exc)) from exc

    def available(self) -> bool:
        try:
            health = self.health()
        except BackendError:
            return False
        return health.get("status") in ("ok", "degraded")

    def health(self) -> Dict[str, Any]:
        data = self._get("/api/v1/health")
        data["mode"] = "api"
        return data

    def list_cases(self, limit: int = 500) -> List[Dict[str, Any]]:
        data = self._get("/api/v1/cases", {"limit": limit})
        # The list endpoint returns summaries. For a normal SOC queue we enrich
        # them from the detail endpoint so the overview, timeline and ATT&CK
        # charts have the same data as local mode. The cap avoids hundreds of
        # extra requests on very large deployments.
        enrich = len(data) <= 50
        cases = []
        for item in data:
            incident_id = item.get("incident_id")
            detail = self.get_case(incident_id) if enrich and incident_id else None
            cases.append(_normalise_case(detail or item))
        cases.sort(key=case_sort_key, reverse=True)
        return cases

    def get_case(self, incident_id: str) -> Optional[Dict[str, Any]]:
        try:
            data = self._get("/api/v1/cases/%s" % incident_id)
        except BackendError:
            return None
        markdown = data.get("markdown") or ""
        if markdown:
            parsed = parse_markdown(
                markdown,
                incident_id_hint=incident_id,
                decision=data.get("decision"),
            )
            for key in ("incident_id", "title", "severity", "confidence", "affected_host",
                        "source_address", "target_account", "detection_rule", "generated_at",
                        "report_path", "report_html_path", "summary", "decision"):
                if data.get(key) is not None:
                    parsed[key] = data[key]
            parsed["severity_rank"] = _severity_rank(parsed.get("severity"))
            return parsed
        return _normalise_case(data)

    def get_report(self, incident_id: str, fmt: str = "markdown") -> Optional[str]:
        try:
            return self._text(
                "/api/v1/cases/%s/report" % incident_id, {"format": fmt}
            )
        except BackendError:
            return None

    def record_decision(
        self, incident_id: str, decision: str, analyst: str, note: str
    ) -> Dict[str, Any]:
        return self._post(
            "/api/v1/cases/%s/decision" % incident_id,
            {
                "decision": decision,
                "analyst": analyst or "analyst",
                "note": note or "",
            },
        )

    def metrics(self) -> Dict[str, Any]:
        data = self._get("/api/v1/metrics")
        cases = self.list_cases()
        summary = aggregate(cases)
        summary.update(data)
        summary["mode"] = "api"
        return summary

    def list_jobs(self, limit: int = 20) -> List[Dict[str, Any]]:
        return self._get("/api/v1/jobs", {"limit": limit})

    def submit_investigation(self, alert_id: str, force: bool = False) -> Dict[str, Any]:
        return self._post(
            "/api/v1/investigations",
            {"alert_id": alert_id, "force": force},
        )


def build_backend(
    preference: str,
    api_url: str,
    reports_dir: Path,
    decisions_path: Path,
) -> Any:
    """Return the backend selected by the sidebar preference.

    ``auto`` tries the API first and falls back to local reports. ``api`` and
    ``local`` force one mode so a failure is visible instead of silent.
    """
    if preference == "Local reports":
        return LocalBackend(reports_dir, decisions_path)
    if preference == "Triage API":
        backend = ApiBackend(api_url)
        backend.health()
        return backend
    api = ApiBackend(api_url)
    if api.available():
        return api
    return LocalBackend(reports_dir, decisions_path)


def project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def default_paths() -> Dict[str, Path]:
    root = project_root()
    return {
        "reports_dir": root / "ai-agentic-soc" / "reports",
        "decisions_path": root / "data" / "triage_decisions.json",
        "evals_dir": root / "ai-agentic-soc" / "evals",
        "docs_dir": root / "reference",
    }


def default_api_url() -> str:
    return os.environ.get("TRIAGE_API_URL", "http://127.0.0.1:8080")
