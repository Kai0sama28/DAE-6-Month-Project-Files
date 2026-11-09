from __future__ import annotations

import os
import datetime

from sqlalchemy import Column, DateTime, Integer, String, Text, create_engine
from sqlalchemy.orm import Session, declarative_base

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./data/investigations.db")

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
Base = declarative_base()


class InvestigationRecord(Base):
    __tablename__ = "investigations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_id = Column(String, index=True)
    status = Column(String, default="pending")
    verdict = Column(String, default="")
    mitre_techniques = Column(Text, default="")
    risk_summary = Column(Text, default="")
    evidence_json = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow)


def init_db() -> None:
    Base.metadata.create_all(engine)


def get_session() -> Session:
    return Session(engine)