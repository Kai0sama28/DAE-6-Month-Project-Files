from __future__ import annotations

from datetime import datetime

from fastapi.testclient import TestClient

from apis.identity.app import app


def _client():
    return TestClient(app)


def test_health():
    with _client() as c:
        assert c.get("/health").json() == {"status": "ok"}


def test_users_seeded():
    with _client() as c:
        users = c.get("/users").json()
        assert len(users) > 0
        assert users[0]["username"]


def test_get_user_by_id():
    with _client() as c:
        user = c.get("/users/1").json()
        assert user["user_id"] == 1
        assert user["role"]


def test_login_history():
    with _client() as c:
        history = c.get("/users/1/login_history", params={"limit": 100}).json()
        assert len(history) > 0
        assert history[0]["user_id"] == 1
        assert "ts" in history[0]


def test_risk_factors_track_injected_failures():
    with _client() as c:
        c.post("/users/1/login_events", json={
            "ts": datetime.utcnow().isoformat(),
            "ip": "203.0.113.77",
            "country": "RU",
            "city": "Moscow",
            "success": False,
        })
        for _ in range(12):
            c.post("/users/1/login_events", json={
                "ts": datetime.utcnow().isoformat(),
                "ip": "203.0.113.77",
                "country": "RU",
                "city": "Moscow",
                "success": False,
            })
        risk = c.get("/users/1/risk_factors").json()
        assert risk["risk_level"] in {"low", "medium", "high"}
        names = {f["name"] for f in risk["factors"]}
        assert "failed_logins_24h" in names
        failed = next(f for f in risk["factors"] if f["name"] == "failed_logins_24h")
        assert failed["level"] == "high"


def test_missing_user_404():
    with _client() as c:
        assert c.get("/users/99999").status_code == 404