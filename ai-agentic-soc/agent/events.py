"""Canonical event shape shared by the watcher, correlator and reporter.

Everything the agent reasons about is flattened into this small dict first, so
the LLM prompt, the timeline table and the correlation statistics all talk
about exactly the same facts.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from schemas.wazuh import WazuhAlert

PHASES = (
    "RECON",
    "AUTH_FAILURE",
    "AUTH_SUCCESS",
    "PRIVILEGE",
    "PERSISTENCE",
    "EXECUTION",
    "INTEGRITY",
    "SYSTEM",
    "OTHER",
)

PHASE_LABELS = {
    "RECON": "Reconnaissance / enumeration",
    "AUTH_FAILURE": "Authentication failures",
    "AUTH_SUCCESS": "Successful authentication",
    "PRIVILEGE": "Privilege escalation",
    "PERSISTENCE": "Persistence",
    "EXECUTION": "Command execution / session",
    "INTEGRITY": "File integrity change",
    "SYSTEM": "System / agent health",
    "OTHER": "Other activity",
}

# Rule-id -> phase. Only covers the rules this lab actually fires; anything
# unmapped falls back to group-based inference and then to OTHER.
RULE_PHASES: dict[str, str] = {
    "5700": "SYSTEM",
    "5701": "SYSTEM",
    "5702": "SYSTEM",
    "5710": "RECON",
    "5712": "RECON",
    "5715": "AUTH_SUCCESS",
    "5716": "AUTH_FAILURE",
    "5758": "AUTH_FAILURE",
    "5760": "AUTH_FAILURE",
    "5762": "AUTH_FAILURE",
    "5763": "AUTH_FAILURE",
    "5770": "AUTH_FAILURE",
    "5771": "AUTH_FAILURE",
    "5772": "AUTH_FAILURE",
    "5773": "AUTH_FAILURE",
    "5551": "AUTH_FAILURE",
    "40111": "AUTH_FAILURE",
    "40112": "AUTH_SUCCESS",
    "5401": "PRIVILEGE",
    "5402": "PRIVILEGE",
    "5403": "PRIVILEGE",
    "5404": "PRIVILEGE",
    "5501": "EXECUTION",
    "5502": "EXECUTION",
    "5503": "AUTH_FAILURE",
    "590": "INTEGRITY",
    "550": "INTEGRITY",
    "810": "INTEGRITY",
    "860": "INTEGRITY",
    "870": "INTEGRITY",
    "700": "SYSTEM",
    "701": "SYSTEM",
    "702": "SYSTEM",
    "703": "SYSTEM",
    "704": "SYSTEM",
    "504": "SYSTEM",
    "250": "SYSTEM",
    "520": "SYSTEM",
    "100030": "AUTH_SUCCESS",
    "100031": "AUTH_FAILURE",
    "100032": "INTEGRITY",
}

# Rule group fragment -> phase (lower-case match).
GROUP_PHASES: tuple[tuple[str, str], ...] = (
    ("authentication_failed", "AUTH_FAILURE"),
    ("authentication_success", "AUTH_SUCCESS"),
    ("sshd", "AUTH_FAILURE"),
    ("pam", "EXECUTION"),
    ("sudo", "PRIVILEGE"),
    ("syscheck", "INTEGRITY"),
    ("integrity", "INTEGRITY"),
    ("vulnerability-detector", "INTEGRITY"),
    ("sca", "INTEGRITY"),
    ("mitre_attack", "OTHER"),
)

_SRC_IP_KEYS = ("srcip", "src_ip", "srcip", "source_ip")
_USER_KEYS = ("dstuser", "user", "username", "duser", "srcuser", "target_user")


def _first(data: dict[str, Any], keys: tuple[str, ...]) -> Optional[str]:
    for key in keys:
        value = data.get(key)
        if value:
            return str(value)
    return None


def _parse_ts(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    text = value.strip()
    if text.endswith("+0000"):
        text = text[:-5] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def classify_phase(rule_id: Optional[str], groups: list[str]) -> str:
    """Map a Wazuh rule to an attack phase."""
    if rule_id:
        mapped = RULE_PHASES.get(str(rule_id))
        if mapped:
            return mapped
    for group in groups or []:
        lowered = str(group).lower()
        for fragment, phase in GROUP_PHASES:
            if fragment in lowered:
                return phase
    return "OTHER"


def event_from_wazuh(alert: WazuhAlert) -> dict[str, Any]:
    """Flatten a Wazuh alert into the canonical event dict."""
    rule = alert.rule
    agent = alert.agent
    data = alert.data or {}

    mitre_ids: list[str] = []
    mitre_tactics: list[str] = []
    mitre_names: list[str] = []
    if rule and rule.mitre:
        mitre_ids = [m for m in (rule.mitre.id or []) if m]
        mitre_tactics = [t for t in (rule.mitre.tactic or []) if t]
        mitre_names = [t for t in (rule.mitre.technique or []) if t]

    groups = list(rule.groups) if rule and rule.groups else []
    rule_id = str(rule.id) if rule and rule.id else ""
    level = int(rule.level) if rule and rule.level else 0
    firedtimes = int((rule.firedtimes or 0)) if rule and rule.firedtimes else 0

    src_ip = _first(data, _SRC_IP_KEYS)
    if not src_ip and alert.full_log:
        parts = alert.full_log.split()
        for idx, token in enumerate(parts):
            if token == "from" and idx + 1 < len(parts):
                src_ip = parts[idx + 1]
                break

    return {
        "id": str(alert.id or ""),
        "timestamp": alert.timestamp or "",
        "ts": _parse_ts(alert.timestamp),
        "rule_id": rule_id,
        "level": level,
        "title": (rule.description if rule and rule.description else "Unknown alert"),
        "groups": groups,
        "mitre": mitre_ids,
        "mitre_tactics": mitre_tactics,
        "mitre_names": mitre_names,
        "agent_id": (agent.id if agent else "") or "",
        "agent_name": (agent.name if agent else "") or "",
        "agent_ip": (agent.ip if agent else "") or "",
        "src_ip": src_ip or "",
        "dst_user": _first(data, _USER_KEYS) or "",
        "firedtimes": firedtimes,
        "location": alert.location or "",
        "full_log": (alert.full_log or "")[:2000],
        "data": {k: v for k, v in list(data.items())[:25]},
        "phase": classify_phase(rule_id, groups),
    }


def event_sort_key(event: dict[str, Any]) -> tuple:
    ts = event.get("ts")
    return (
        ts.timestamp() if isinstance(ts, datetime) else 0.0,
        int(event.get("level") or 0),
        event.get("id") or "",
    )


def event_timestamp_text(event: dict[str, Any]) -> str:
    ts = event.get("ts")
    if isinstance(ts, datetime):
        return ts.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + "Z"
    return str(event.get("timestamp") or "unknown")
