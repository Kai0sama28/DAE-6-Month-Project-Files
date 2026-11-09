from __future__ import annotations

from datetime import datetime, timedelta
from typing import Callable, Optional, Tuple, Union

from pydantic import BaseModel, Field

from schemas import Alert, SiemEvidence, RelatedEvent

SiemProbe = Callable[[], list[RelatedEvent]]


class InvestigationBundle(BaseModel):
    alert: Alert
    identity: Optional[dict] = None
    login_history: list[dict] = Field(default_factory=list)
    risk_factors: Optional[dict] = None
    endpoint: Optional[dict] = None
    processes: list[dict] = Field(default_factory=list)
    network: list[dict] = Field(default_factory=list)
    files: list[dict] = Field(default_factory=list)
    siem: Optional[SiemEvidence] = None

    @property
    def evidence_summary(self) -> str:
        lines = [
            f"alert: {self.alert.title} (sev {self.alert.severity}/10)",
        ]
        if self.identity:
            lines.append(f"identity: {self.identity.get('username')} "
                         f"({self.identity.get('role')}, priv "
                         f"{self.identity.get('privilege_level')})")
        if self.risk_factors:
            lines.append(f"risk: {self.risk_factors.get('risk_level')} "
                         f"({len(self.risk_factors.get('factors', []))} factors)")
        if self.endpoint:
            lines.append(f"endpoint: {self.endpoint.get('hostname')} "
                         f"({self.endpoint.get('os')})")
        suspicious = [p for p in self.processes if p.get("suspicious")]
        if suspicious:
            lines.append(f"suspicious processes: {len(suspicious)}")
        if self.siem:
            lines.append(f"siem related events: {len(self.siem.related_events)}")
        return "\n".join(lines)


def gather_evidence(
    alert: Alert,
    identity: object,
    edr: object,
    siem_probe: Optional[SiemProbe] = None,
) -> InvestigationBundle:
    window_since = (alert.event_time - timedelta(hours=2)).isoformat()

    identity_data, login_history, risk = _gather_identity(alert, identity)
    endpoint, processes, network, files = _gather_endpoint(alert, edr, window_since)

    siem_evidence = None
    if siem_probe:
        related = siem_probe()
        siem_evidence = SiemEvidence(
            related_events=related,
            related_count=len(related),
        )

    return InvestigationBundle(
        alert=alert,
        identity=identity_data,
        login_history=login_history,
        risk_factors=risk,
        endpoint=endpoint,
        processes=processes,
        network=network,
        files=files,
        siem=siem_evidence,
    )


def _gather_identity(alert: Alert, identity) -> Tuple[Optional[dict], list[dict], Optional[dict]]:
    profile = None
    if alert.dst_user:
        try:
            profile = identity.get_user_by_username(alert.dst_user)
        except Exception:
            profile = None
    if not profile and alert.agent_name:
        for user in identity.list_users():
            if user.get("username", "").lower() in alert.agent_name.lower():
                profile = user
                break
    if not profile:
        return None, [], None

    user_id = profile["user_id"]
    history = identity.login_history(user_id, limit=50)
    risk = identity.risk_factors(user_id)
    return profile, history, risk


def _gather_endpoint(alert: Alert, edr, since: str) -> tuple:
    endpoint = None
    if alert.agent_name:
        for ep in edr.list_endpoints():
            if alert.agent_name.lower() in (ep.get("hostname", "") + ep.get("endpoint_id", "")).lower():
                endpoint = ep
                break
    if not endpoint and alert.agent_name:
        try:
            endpoint = edr.get_endpoint(alert.agent_name)
        except Exception:
            endpoint = None
    if not endpoint:
        return None, [], [], []

    eid = endpoint["endpoint_id"]
    try:
        processes = edr.processes(eid, limit=200, since=since)
    except Exception:
        processes = []
    try:
        network = edr.network(eid, limit=200, since=since)
    except Exception:
        network = []
    try:
        files = edr.files(eid, limit=200, since=since)
    except Exception:
        files = []
    return endpoint, processes, network, files