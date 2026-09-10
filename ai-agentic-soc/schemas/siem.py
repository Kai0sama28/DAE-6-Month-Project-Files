from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from .alert import Alert


class RelatedEvent(BaseModel):
    alert_id: str = ""
    event_time: datetime
    rule_id: str = ""
    title: str = ""
    severity: int = Field(ge=1, le=10)
    summary: str = ""


class SiemEvidence(BaseModel):
    related_events: list[RelatedEvent] = Field(default_factory=list)
    related_count: int = 0

    @property
    def normalized_alerts(self) -> list[Alert]:
        return [Alert(
            alert_id=e.alert_id,
            title=e.title,
            severity=e.severity,
            source_rule_id=e.rule_id,
            event_time=e.event_time,
            description=e.summary,
        ) for e in self.related_events]