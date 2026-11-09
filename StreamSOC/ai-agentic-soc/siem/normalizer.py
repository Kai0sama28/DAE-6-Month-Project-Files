from __future__ import annotations

from datetime import datetime
from typing import Any, Optional, Union

from schemas.alert import Alert, MitreTechnique, normalize_wazuh_level
from schemas.wazuh import WazuhAlert, WazuhRule, WazuhRuleMitre, WazuhAgent

__all__ = ["normalize_wazuh_alert"]

_SOURCE_LABEL = "wazuh"


def normalize_wazuh_alert(raw: Union[dict[str, Any], WazuhAlert]) -> Alert:
    alert = raw if isinstance(raw, WazuhAlert) else WazuhAlert.model_validate(raw)
    rule = alert.rule or WazuhRuleFallback()
    mitre = [MitreTechnique(
        technique_id=rule.mitre.id[0] if rule.mitre and rule.mitre.id else "",
        tactic=rule.mitre.tactic[0] if rule.mitre and rule.mitre.tactic else None,
    )] if rule.mitre and rule.mitre.id else []

    return Alert(
        alert_id=str(alert.id) if alert.id is not None else "",
        title=rule.description or "Unknown alert",
        description=alert.full_log or rule.description or "",
        severity=normalize_wazuh_level(rule.level),
        source=_SOURCE_LABEL,
        source_rule_id=str(rule.id),
        groups=list(rule.groups),
        mitre=mitre,
        source_ip=_extract_ip(alert),
        dst_user=_extract_user(alert),
        agent_id=alert.agent.id if alert.agent else None,
        agent_name=alert.agent.name if alert.agent else None,
        agent_ip=alert.agent.ip if alert.agent else None,
        raw_data=dict(alert.data) if alert.data else {},
        raw_message=alert.full_log or "",
        event_time=_coerce_time(alert.timestamp or ""),
    )


def _extract_ip(alert: WazuhAlert) -> Optional[str]:
    data = alert.data or {}
    for key in ("srcip", "src_ip", "dstip", "src"):
        if data.get(key):
            return str(data[key])
    if alert.full_log:
        for i, tok in enumerate(alert.full_log.split()):
            if tok in ("from",) and i + 1 < len(alert.full_log.split()):
                return alert.full_log.split()[i + 1]
    return None


def _extract_user(alert: WazuhAlert) -> Optional[str]:
    data = alert.data or {}
    for key in ("dstuser", "user", "username", "duser"):
        if data.get(key):
            return str(data[key])
    return None


def _coerce_time(iso: str) -> str:
    if not iso:
        return datetime.utcnow().isoformat()
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00")).isoformat()
    except ValueError:
        return iso


class WazuhRuleFallback:
    id = ""
    level = 0
    description = ""
    groups: list[str] = []
    mitre = None