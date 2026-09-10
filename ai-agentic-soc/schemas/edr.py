from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class Endpoint(BaseModel):
    endpoint_id: str
    hostname: str
    os: str
    ip: str
    tags: list[str] = Field(default_factory=list)
    scenario: str = "normal"


class EndpointSummary(BaseModel):
    endpoint_id: str
    hostname: str
    os: str
    ip: str
    tags: list[str] = Field(default_factory=list)
    process_events_24h: int = 0
    suspicious_process_events_24h: int = 0
    flagged_indicators: list[str] = Field(default_factory=list)


class ProcessEvent(BaseModel):
    event_id: int = 0
    endpoint_id: str
    ts: datetime
    pid: int
    ppid: int = 0
    parent_name: str = ""
    name: str
    cmdline: str = ""
    user: str = ""
    integrity: str = "medium"
    suspicious: bool = False
    indicator: str = ""


class NetworkEvent(BaseModel):
    event_id: int = 0
    endpoint_id: str
    ts: datetime
    src_ip: str = ""
    dst_ip: str
    dst_port: int
    direction: str = "outbound"
    proto: str = "tcp"


class FileEvent(BaseModel):
    event_id: int = 0
    endpoint_id: str
    ts: datetime
    path: str
    action: str
    hash: Optional[str] = None