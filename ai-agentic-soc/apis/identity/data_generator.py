from __future__ import annotations

from datetime import datetime, timedelta
import random

from typing import Optional

from schemas.identity import IdentityProfile, LoginEvent

FIRST_NAMES = [
    "Aisha", "Marcus", "Priya", "Tom", "Grace", "Dmitri", "Elena", "James",
    "Chloe", "Ravi", "Nadia", "Olivia", "Kofi", "Liam", "Mia", "Noah",
]
LAST_NAMES = [
    "Okonkwo", "Chen", "Patel", "Novak", "Rossi", "Kim", "Silva", "Brown",
    "Nguyen", "Khan", "O'Connor", "Weber", "Doe", "Sato", "Hansen", "Mensah",
]
USERNAMES = [
    "aokonkwo", "marcus.chen", "priya.patel", "tom.novak", "grace.rossi",
    "dmitri.kim", "elena.silva", "james.brown", "chloe.nguyen", "ravi.khan",
    "nadia.oconnor", "olivia.weber", "kofi.doe", "liam.sato", "mia.hansen",
    "noah.mensah",
]
DEPARTMENTS = ["Engineering", "Sales", "Finance", "HR", "Marketing", "Legal"]
ROLES = ["analyst", "engineer", "manager", "admin", "executive"]

COUNTRY_BY_CITY = {
    "London": "GB", "Paris": "FR", "Berlin": "DE", "Dublin": "IE",
    "New York": "US", "Austin": "US", "Toronto": "CA", "Sydney": "AU",
    "Singapore": "SG", "Amsterdam": "NL",
}

ATTACK_IPS = [
    ("Moscow", "RU"), ("São Paulo", "BR"), ("Frankfurt", "DE"),
    ("Beijing", "CN"), ("Kyiv", "UA"), ("Bangkok", "TH"),
]
PHISHING_IPS = [("New York", "US"), ("Frankfurt", "DE")]


def company_domain() -> str:
    return "meridian-security.example"


def _home_ip(country: str, rng: random.Random) -> str:
    # RFC 1918-ish style private-range-shaped, but unique per country for realism
    base = {c: str(100 + i) for i, c in enumerate(set(COUNTRY_BY_CITY.values()))}
    return f"10.11.{base.get(country, '10')}.{rng.randint(2, 254)}"


def seed_users(count: int = 16, rng: Optional[random.Random] = None) -> list[IdentityProfile]:
    rng = rng or random.Random()
    profiles: list[IdentityProfile] = []
    for i in range(count):
        fname = FIRST_NAMES[i % len(FIRST_NAMES)]
        lname = LAST_NAMES[i % len(LAST_NAMES)]
        username = USERNAMES[i % len(USERNAMES)]
        city = rng.choice(list(COUNTRY_BY_CITY.keys()))
        country = COUNTRY_BY_CITY[city]
        role = rng.choice(ROLES)
        privilege = 5 if role == "admin" else (4 if role == "executive" else rng.randint(1, 3))

        profiles.append(IdentityProfile(
            user_id=i + 1,
            username=username,
            email=f"{username}@{company_domain()}",
            full_name=f"{fname} {lname}",
            department=rng.choice(DEPARTMENTS),
            role=role,
            privilege_level=privilege,
            mfa_enabled=rng.random() < 0.6,
            default_country=country,
            office_city=city,
            last_known_ip=_home_ip(country, rng),
            scenario="normal",
        ))
    return profiles


def gen_login_history(profile: IdentityProfile, days: int = 30,
                      rng: Optional[random.Random] = None) -> list[LoginEvent]:
    rng = rng or random.Random()
    events = _normal_history(profile, days, rng)
    fn = {
        "credential-stuffing": _stuffing,
        "brute-force": _brute_force,
        "phishing-compromise": _phishing,
    }.get(profile.scenario)
    if fn:
        events = fn(profile, events, rng)
    return sorted(events, key=lambda e: e.ts)


def _normal_history(profile: IdentityProfile, days: int, rng) -> list[LoginEvent]:
    events: list[LoginEvent] = []
    now = datetime.utcnow()
    user_ip = profile.last_known_ip or _home_ip(profile.default_country, rng)
    for day in range(1, days + 1):
        if rng.random() < 0.15:
            continue
        ts = now - timedelta(days=days - day)
        ts = ts.replace(hour=rng.randint(8, 18), minute=rng.randint(0, 59),
                        second=rng.randint(0, 59), microsecond=0)
        events.append(LoginEvent(
            event_id=day, user_id=profile.user_id, ts=ts,
            ip=user_ip, country=profile.default_country, city=profile.office_city,
            success=rng.random() > 0.02,
            auth_method="MFA" if profile.mfa_enabled else "password",
            user_agent="Chrome/120",
        ))
    return events


def _append_attacks(events: list[LoginEvent], profile: IdentityProfile,
                    rng: random.Random, count: int, minutes_apart: int,
                    city: str, country: str, user_agent: str) -> list[LoginEvent]:
    now = datetime.utcnow()
    next_id = max((e.event_id for e in events), default=0) + 1
    start = now - timedelta(minutes=minutes_apart * count)
    ip = f"203.0.113.{rng.randint(2, 12)}"
    for i in range(count):
        events.append(LoginEvent(
            event_id=next_id + i, user_id=profile.user_id,
            ts=start + timedelta(minutes=i * minutes_apart),
            ip=ip, country=country, city=city, success=False,
            auth_method="password", user_agent=user_agent,
        ))
    return events


def _stuffing(profile, events, rng) -> list[LoginEvent]:
    return _append_attacks(events, profile, rng, 41, 2, "Moscow", "RU", "python-requests/2.31")


def _brute_force(profile, events, rng) -> list[LoginEvent]:
    return _append_attacks(events, profile, rng, 25, 3, "São Paulo", "BR", "kali-linux")


def _phishing(profile, events, rng) -> list[LoginEvent]:
    now = datetime.utcnow()
    next_id = max((e.event_id for e in events), default=0) + 1
    for i, (city, country) in enumerate(PHISHING_IPS):
        events.append(LoginEvent(
            event_id=next_id + i, user_id=profile.user_id,
            ts=now - timedelta(hours=2) + timedelta(minutes=30 * i),
            ip=f"198.51.100.{rng.randint(2, 20)}", country=country, city=city,
            success=True, auth_method="MFA" if profile.mfa_enabled else "password",
            user_agent="Windows PowerShell/5.1",
        ))
    return events