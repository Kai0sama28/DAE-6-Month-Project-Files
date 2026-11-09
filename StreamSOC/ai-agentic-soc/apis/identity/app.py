from __future__ import annotations

import os
import random
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, Query, HTTPException
from sqlalchemy import desc

from schemas.identity import IdentityProfile

from .db import LoginEventModel, UserModel, Base, engine, get_session

app = FastAPI(title="Identity Mock API", version="0.1.0", root_path="")

SEED = 42


def _row_to_dict(row) -> dict:
    return {c.name: (getattr(row, c.name).isoformat()
                     if isinstance(getattr(row, c.name), datetime)
                     else getattr(row, c.name))
            for c in row.__table__.columns}


@app.on_event("startup")
def _startup():
    os.makedirs("data", exist_ok=True)
    Base.metadata.create_all(engine)
    session = get_session()
    try:
        if session.query(UserModel).count() == 0:
            rng = random.Random(SEED)
            from apis.identity.data_generator import seed_users, gen_login_history
            profiles = seed_users(rng=rng)
            for p in profiles:
                session.add(UserModel(**p.model_dump()))
            session.commit()
            for p in profiles:
                for ev in gen_login_history(p, rng=rng):
                    session.add(LoginEventModel(**ev.model_dump()))
            session.commit()
    finally:
        session.close()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/users")
def list_users(username: Optional[str] = None):
    session = get_session()
    try:
        q = session.query(UserModel)
        if username:
            q = q.filter(UserModel.username == username)
        return [_row_to_dict(u) for u in q.limit(200)]
    finally:
        session.close()


@app.get("/users/{user_id}")
def get_user(user_id: int):
    session = get_session()
    try:
        u = session.query(UserModel).get(user_id)
        if not u:
            raise HTTPException(status_code=404, detail="user not found")
        return _row_to_dict(u)
    finally:
        session.close()


@app.get("/users/{user_id}/login_history")
def login_history(user_id: int,
                  limit: int = Query(100, le=500),
                  since: Optional[datetime] = None):
    session = get_session()
    try:
        q = session.query(LoginEventModel).filter(LoginEventModel.user_id == user_id)
        if since:
            q = q.filter(LoginEventModel.ts >= since)
        rows = q.order_by(desc(LoginEventModel.ts)).limit(limit).all()
        return [_row_to_dict(r) for r in rows]
    finally:
        session.close()


@app.post("/users/{user_id}/login_events", status_code=201)
def add_login_event(user_id: int, event: dict):
    session = get_session()
    try:
        if not session.query(UserModel).get(user_id):
            raise HTTPException(status_code=404, detail="user not found")
        row = LoginEventModel(
            user_id=user_id,
            ts=datetime.fromisoformat(event["ts"]) if "ts" in event else datetime.utcnow(),
            ip=event.get("ip", "0.0.0.0"),
            country=event.get("country", ""),
            city=event.get("city", ""),
            success=event.get("success", True),
            auth_method=event.get("auth_method", "password"),
            user_agent=event.get("user_agent", ""),
            is_admin_action=event.get("is_admin_action", False),
        )
        session.add(row)
        session.commit()
        return {"event_id": row.event_id, "user_id": user_id}
    finally:
        session.close()


@app.get("/users/{user_id}/risk_factors")
def risk_factors(user_id: int):
    session = get_session()
    try:
        events = (session.query(LoginEventModel)
                  .filter(LoginEventModel.user_id == user_id)
                  .order_by(desc(LoginEventModel.ts))
                  .limit(500).all())
        return _compute_risk(user_id, events)
    finally:
        session.close()


def _compute_risk(user_id: int, events: list[LoginEventModel]) -> dict:
    now = datetime.utcnow()
    factors: list[dict] = []

    recent_failures = sum(1 for e in events
                          if not e.success and (now - e.ts) < timedelta(hours=24))
    if recent_failures > 0:
        factors.append({
            "name": "failed_logins_24h",
            "level": "high" if recent_failures > 10 else "medium",
            "detail": f"{recent_failures} failed login(s) in last 24h",
        })

    successes = [(e.ts, e.country) for e in events if e.success]
    for (ts1, c1), (ts2, c2) in zip(successes, successes[1:]):
        if c1 != c2 and abs((ts2 - ts1).total_seconds()) < 7200:
            factors.append({
                "name": "impossible_travel",
                "level": "high",
                "detail": f"Successful login from {c1} then {c2} within 2 hours",
            })
            break

    after_hours = sum(1 for e in events
                      if e.success and (e.ts.hour >= 20 or e.ts.hour < 7))
    if after_hours > 0:
        factors.append({
            "name": "after_hours_logins",
            "level": "medium",
            "detail": f"{after_hours} after-hours successful login(s)",
        })

    non_mfa_admin = sum(1 for e in events
                        if e.success and e.auth_method != "MFA"
                        and e.is_admin_action)
    if non_mfa_admin > 0:
        factors.append({
            "name": "admin_without_mfa",
            "level": "high" if non_mfa_admin > 3 else "medium",
            "detail": f"{non_mfa_admin} admin action(s) without MFA",
        })

    overall = ("high" if any(f["level"] == "high" for f in factors)
               else ("medium" if factors else "low"))
    return {"user_id": user_id, "risk_level": overall, "factors": factors}