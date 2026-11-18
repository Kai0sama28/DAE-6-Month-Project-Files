"""Optional TheHive case-management integration for analyst decisions.

The triage engine never executes containment. When an analyst records a
decision in the dashboard, this module mirrors that human gate into TheHive:
an approved incident gets a case (created on first approval), a decision
comment, and review tags. A rejected decision only updates a case that already
exists so rejected reports do not create case noise.

The integration is deliberately optional and failure-tolerant:

* No ``THEHIVE_*`` credentials -> :class:`DisabledTheHive` is used.
* TheHive unreachable -> the decision is still stored locally and the sync
  error is returned in the decision record.
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

try:  # pragma: no cover - dotenv is optional at runtime
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover
    load_dotenv = None  # type: ignore[assignment]

try:
    from agent.config import PROJECT_ROOT
except Exception:  # pragma: no cover - keeps the module importable standalone
    PROJECT_ROOT = Path(__file__).resolve().parents[2]

DEFAULT_URL = "http://localhost:9000"
TAG_BASE = "ai-agentic-soc"
SEVERITY_TO_THEHIVE = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return float(raw)
    except ValueError:
        return default


@dataclass
class TheHiveConfig:
    url: str = DEFAULT_URL
    api_key: Optional[str] = None
    user: Optional[str] = None
    password: Optional[str] = None
    organisation: Optional[str] = None
    verify: bool = True
    timeout: float = 10.0
    enabled: bool = True

    @classmethod
    def from_env(cls) -> Optional["TheHiveConfig"]:
        if load_dotenv is not None:
            load_dotenv(PROJECT_ROOT / ".env", override=False)
        enabled = _env_bool("THEHIVE_ENABLED", True)
        api_key = (os.environ.get("THEHIVE_API_KEY") or "").strip() or None
        user = (os.environ.get("THEHIVE_USER") or "").strip() or None
        password = os.environ.get("THEHIVE_PASSWORD") or None
        if not enabled or not (api_key or (user and password)):
            return None
        return cls(
            url=(os.environ.get("THEHIVE_URL") or DEFAULT_URL).rstrip("/"),
            api_key=api_key,
            user=user,
            password=password,
            organisation=(os.environ.get("THEHIVE_ORGANISATION") or "").strip()
            or None,
            verify=_env_bool("THEHIVE_VERIFY_TLS", True),
            timeout=_env_float("THEHIVE_TIMEOUT", 10.0),
        )


def _severity_int(severity: Optional[str]) -> int:
    return SEVERITY_TO_THEHIVE.get((severity or "").strip().lower(), 2)


def _tags_for(case: Any, decision: str) -> List[str]:
    tags = [TAG_BASE, "source:ai-triage", "incident:%s" % getattr(case, "incident_id", "")]
    severity = (getattr(case, "severity", None) or "").strip().lower()
    if severity:
        tags.append("severity:%s" % severity)
    tags.append("decision:%s" % decision)
    seen: List[str] = []
    for tag in tags:
        if tag and tag not in seen:
            seen.append(tag[:128])
    return seen


def _description(case: Any) -> str:
    lines = [
        "Automated triage report for incident **%s**." % getattr(case, "incident_id", ""),
        "",
        "**%s**" % (getattr(case, "title", None) or "AI triage incident"),
        "",
        "| Field | Value |",
        "|---|---|",
    ]
    for label, attribute in (
        ("Severity", "severity"),
        ("Analyst confidence", "confidence"),
        ("Affected host", "affected_host"),
        ("Source address", "source_address"),
        ("Detection rule", "detection_rule"),
        ("Correlated events", "correlated_events"),
    ):
        value = getattr(case, attribute, None)
        if value:
            lines.append("| %s | %s |" % (label, value))
    summary = getattr(case, "summary", None)
    if summary:
        lines.extend(["", summary])
    report_path = getattr(case, "report_path", None)
    if report_path:
        lines.extend(["", "Report: `%s`" % report_path])
    return "\n".join(lines)


class TheHiveClient:
    """Small, dependency-light client for the TheHive 5 case API."""

    enabled = True

    def __init__(
        self,
        config: TheHiveConfig,
        client: Optional[httpx.Client] = None,
    ) -> None:
        self.config = config
        self._owns_client = client is None
        self._client = client or httpx.Client(
            base_url=config.url,
            verify=config.verify,
            timeout=config.timeout,
        )

    @classmethod
    def from_env(cls) -> Optional["TheHiveClient"]:
        config = TheHiveConfig.from_env()
        return cls(config) if config else None

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def _auth_headers(self) -> Dict[str, str]:
        if self.config.api_key:
            return {"Authorization": "Bearer %s" % self.config.api_key}
        token = base64.b64encode(
            ("%s:%s" % (self.config.user, self.config.password)).encode("utf-8")
        ).decode("ascii")
        return {"Authorization": "Basic %s" % token}

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        headers = dict(self._auth_headers())
        headers.setdefault("Content-Type", "application/json")
        if self.config.organisation:
            headers["X-Organisation"] = self.config.organisation
        response = self._client.request(method, path, headers=headers, **kwargs)
        response.raise_for_status()
        if response.status_code == 204 or not response.content:
            return None
        return response.json()

    def ping(self) -> bool:
        try:
            self._request("GET", "/api/v1/user/current")
            return True
        except httpx.HTTPError:
            return False

    def find_case(self, incident_id: str) -> Optional[Dict[str, Any]]:
        data = self._request(
            "POST",
            "/api/v1/query",
            json={
                "query": [
                    {"_name": "listCase"},
                    {"_name": "page", "from": 0, "to": 200},
                ]
            },
        )
        cases = data if isinstance(data, list) else (data or {}).get("data", [])
        for case in cases:
            if not isinstance(case, dict):
                continue
            tags = case.get("tags") or []
            tag_values = [
                tag.get("value") if isinstance(tag, dict) else str(tag) for tag in tags
            ]
            haystack = " ".join(
                [
                    case.get("title") or "",
                    case.get("description") or "",
                    " ".join(tag_values),
                ]
            )
            if incident_id in haystack:
                return case
        return None

    def _create_case(self, case: Any, decision: str) -> Dict[str, Any]:
        title = "[%s] %s" % (
            getattr(case, "incident_id", ""),
            getattr(case, "title", None) or "AI triage incident",
        )
        payload = {
            "title": title[:512],
            "description": _description(case),
            "severity": _severity_int(getattr(case, "severity", None)),
            "tags": _tags_for(case, decision),
            "tlp": 2,
            "pap": 2,
        }
        return self._request("POST", "/api/v1/case", json=payload)

    def sync_decision(
        self,
        case: Any,
        decision: str,
        analyst: str,
        note: str,
        decided_at: str = "",
    ) -> Dict[str, Any]:
        incident_id = getattr(case, "incident_id", "")
        try:
            existing = self.find_case(incident_id)
            if existing is None and decision != "approved":
                return {
                    "status": "skipped",
                    "reason": "no TheHive case exists for this rejected decision",
                }

            if existing is None:
                created = self._create_case(case, decision)
                case_id = (created or {}).get("_id") or (created or {}).get("id")
                action = "created"
                case_number = (created or {}).get("number")
            else:
                case_id = existing.get("_id") or existing.get("id")
                action = "updated"
                case_number = existing.get("number")

            if not case_id:
                return {"status": "error", "error": "TheHive did not return a case id"}

            tags = _tags_for(case, decision)
            self._request(
                "PATCH",
                "/api/v1/case/%s" % case_id,
                json={"addTags": tags},
            )

            message = "\n".join(
                [
                    "**AI triage analyst decision: %s**" % decision,
                    "",
                    "- Incident: %s" % incident_id,
                    "- Analyst: %s" % analyst,
                    "- Decided at: %s" % (decided_at or "(unknown)"),
                    "- Note: %s" % (note or "(none)"),
                    "",
                    "Recorded through the StreamSOC triage dashboard. The AI-Agentic SOC "
                    "build records this human gate but does not execute containment.",
                ]
            )
            self._request(
                "POST",
                "/api/v1/case/%s/comment" % case_id,
                json={"message": message},
            )

            return {
                "status": action,
                "case_id": case_id,
                "case_number": case_number,
                "tags": tags,
            }
        except httpx.HTTPError as exc:
            return {
                "status": "error",
                "error": "%s: %s" % (type(exc).__name__, exc),
            }


class DisabledTheHive:
    """No-op client used when the integration is not configured."""

    enabled = False

    def close(self) -> None:
        return None

    def ping(self) -> bool:
        return False

    def find_case(self, incident_id: str) -> Optional[Dict[str, Any]]:
        return None

    def sync_decision(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            "status": "disabled",
            "reason": (
                "set THEHIVE_URL and THEHIVE_USER/THEHIVE_PASSWORD or "
                "THEHIVE_API_KEY (plus THEHIVE_ORGANISATION for non-admin orgs)"
            ),
        }
