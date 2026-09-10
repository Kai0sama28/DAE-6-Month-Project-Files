from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class WazuhRuleMitre(BaseModel):
    id: list[str] = Field(default_factory=list)
    tactic: list[str] = Field(default_factory=list)


class WazuhRule(BaseModel):
    id: str = ""
    level: int = 0
    description: str = ""
    groups: list[str] = Field(default_factory=list)
    mitre: Optional[WazuhRuleMitre] = None


class WazuhAgent(BaseModel):
    id: str = ""
    name: str = ""
    ip: str = ""


class WazuhAlert(BaseModel):
    id: Optional[str] = None
    timestamp: Optional[str] = None
    rule: Optional[WazuhRule] = None
    agent: Optional[WazuhAgent] = None
    data: dict[str, object] = Field(default_factory=dict)
    full_log: Optional[str] = None
    location: str = ""

    model_config = {"extra": "allow"}