from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class IdentityProfile(BaseModel):
    user_id: int
    username: str
    email: str
    full_name: str
    department: str
    role: str
    privilege_level: int
    mfa_enabled: bool
    default_country: str
    office_city: str
    last_known_ip: str = ""
    scenario: str = "normal"
    created_at: datetime = Field(default_factory=datetime.utcnow)


class LoginEvent(BaseModel):
    event_id: int = 0
    user_id: int
    ts: datetime
    ip: str
    country: str
    city: str
    success: bool
    auth_method: str = "password"
    user_agent: str = ""
    is_admin_action: bool = False


class RiskFactor(BaseModel):
    name: str
    level: str
    detail: str


class RiskFactors(BaseModel):
    user_id: int
    risk_level: str
    factors: list[RiskFactor] = Field(default_factory=list)