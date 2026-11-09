from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


def normalize_wazuh_level(level: int) -> int:
    return max(1, min(level, 10))


class MitreTechnique(BaseModel):
    technique_id: str = ""
    technique_name: str = ""
    tactic: Optional[str] = None
    tactic_id: Optional[str] = None


class Alert(BaseModel):
    alert_id: str = ""
    title: str
    description: str = ""
    severity: int = Field(ge=1, le=10)
    source: str = "wazuh"
    source_rule_id: str = ""
    groups: list[str] = Field(default_factory=list)
    mitre: list[MitreTechnique] = Field(default_factory=list)
    source_ip: Optional[str] = None
    dst_user: Optional[str] = None
    dst_host: Optional[str] = None
    agent_id: Optional[str] = None
    agent_name: Optional[str] = None
    agent_ip: Optional[str] = None
    raw_data: dict = Field(default_factory=dict)
    raw_message: str = ""
    event_time: datetime
    ingested_at: datetime = Field(default_factory=datetime.utcnow)

    @property
    def mitre_technique_ids(self) -> list[str]:
        return [t.technique_id for t in self.mitre if t.technique_id]

    @property
    def primary_technique(self) -> Optional[MitreTechnique]:
        return self.mitre[0] if self.mitre else None