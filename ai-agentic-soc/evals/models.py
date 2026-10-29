"""Pydantic models for one evaluation case (an incident bundle)."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from schemas.wazuh import WazuhAlert


class IdentityEvidence(BaseModel):
    profiles: List[Dict[str, Any]] = Field(default_factory=list)
    login_events: List[Dict[str, Any]] = Field(default_factory=list)
    risk_factors: List[Dict[str, Any]] = Field(default_factory=list)


class EDREvidence(BaseModel):
    endpoints: List[Dict[str, Any]] = Field(default_factory=list)
    process_events: List[Dict[str, Any]] = Field(default_factory=list)
    network_events: List[Dict[str, Any]] = Field(default_factory=list)
    file_events: List[Dict[str, Any]] = Field(default_factory=list)


class SIEMEvidence(BaseModel):
    trigger_rule_id: str = ""
    trigger_level: int = 0
    correlated_alert_count: int = 0
    rule_counts: Dict[str, int] = Field(default_factory=dict)
    source_ips: List[str] = Field(default_factory=list)
    target_users: List[str] = Field(default_factory=list)
    burst_seconds: float = 0.0
    successful_logins: int = 0
    observation_window: str = ""


class EvalCase(BaseModel):
    case_id: str
    dataset_id: str = ""
    case_index: int
    label: str
    is_malicious: bool
    expected_severity: str
    expected_verdict: str
    expected_action: str
    expected_mitre: List[str] = Field(default_factory=list)
    difficulty: str = "medium"
    scenario: str
    title: str
    summary: str
    trigger_alert_id: str
    alerts: List[WazuhAlert] = Field(default_factory=list)
    identity: IdentityEvidence = Field(default_factory=IdentityEvidence)
    edr: EDREvidence = Field(default_factory=EDREvidence)
    siem: SIEMEvidence = Field(default_factory=SIEMEvidence)
    notes: str = ""

    @property
    def alert_count(self) -> int:
        return len(self.alerts)

    def trigger_alert(self) -> Optional[WazuhAlert]:
        for alert in self.alerts:
            if str(alert.id or "") == self.trigger_alert_id:
                return alert
        return None
