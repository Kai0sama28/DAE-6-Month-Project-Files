from __future__ import annotations

import os
import datetime

from sqlalchemy import Boolean, Column, DateTime, Integer, String, create_engine
from sqlalchemy.orm import Session, declarative_base

DATABASE_URL = os.environ.get("EDR_DATABASE_URL", "sqlite:///./data/edr.db")

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
Base = declarative_base()


class EndpointModel(Base):
    __tablename__ = "endpoints"

    endpoint_id = Column(String, primary_key=True)
    hostname = Column(String)
    os = Column(String)
    ip = Column(String)
    tags = Column(String, default="")
    scenario = Column(String, default="normal")


class ProcessEventModel(Base):
    __tablename__ = "process_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    endpoint_id = Column(String, index=True)
    ts = Column(DateTime, index=True)
    pid = Column(Integer)
    ppid = Column(Integer, default=0)
    parent_name = Column(String, default="")
    name = Column(String)
    cmdline = Column(String, default="")
    user = Column(String, default="")
    integrity = Column(String, default="medium")
    suspicious = Column(Boolean, default=False)
    indicator = Column(String, default="")


class NetworkEventModel(Base):
    __tablename__ = "network_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    endpoint_id = Column(String, index=True)
    ts = Column(DateTime, index=True)
    src_ip = Column(String, default="")
    dst_ip = Column(String)
    dst_port = Column(Integer)
    direction = Column(String, default="outbound")
    proto = Column(String, default="tcp")


class FileEventModel(Base):
    __tablename__ = "file_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    endpoint_id = Column(String, index=True)
    ts = Column(DateTime, index=True)
    path = Column(String)
    action = Column(String)
    hash = Column(String, default="")

def get_session() -> Session:
    return Session(engine)