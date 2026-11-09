from __future__ import annotations

import os
import datetime

from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String, create_engine
from sqlalchemy.orm import Session, declarative_base

DATABASE_URL = os.environ.get("IDENTITY_DATABASE_URL", "sqlite:///./data/identity.db")

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
Base = declarative_base()


class UserModel(Base):
    __tablename__ = "users"

    user_id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, index=True)
    email = Column(String)
    full_name = Column(String)
    department = Column(String)
    role = Column(String)
    privilege_level = Column(Integer)
    mfa_enabled = Column(Boolean)
    default_country = Column(String)
    office_city = Column(String)
    last_known_ip = Column(String, default="")
    scenario = Column(String, default="normal")
    created_at = Column(DateTime, default=datetime.datetime.utcnow)


class LoginEventModel(Base):
    __tablename__ = "login_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(Integer, index=True, default=0)
    user_id = Column(Integer, index=True)
    ts = Column(DateTime, index=True)
    ip = Column(String)
    country = Column(String)
    city = Column(String)
    success = Column(Boolean)
    auth_method = Column(String, default="password")
    user_agent = Column(String, default="")
    is_admin_action = Column(Boolean, default=False)


def get_session() -> Session:
    SessionLocal = Session(engine)
    return SessionLocal