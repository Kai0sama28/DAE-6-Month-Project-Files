from __future__ import annotations

from siem.normalizer import normalize_wazuh_alert

BRUTE_FORCE_ALERT = {
    "id": "1726100520.123456",
    "timestamp": "2026-09-10T14:22:07.481+0000",
    "rule": {
        "id": "100010",
        "level": 10,
        "description": "SSHD brute force: multiple failed logins from same source in 2 minutes",
        "mitre": {"id": ["T1110"], "tactic": ["Credential Access"]},
        "groups": ["authentication_failures", "syslog", "sshd"],
    },
    "agent": {"id": "011", "name": "kali-lab-02", "ip": "10.11.3.57"},
    "data": {"srcip": "203.0.113.77", "srcport": 51422, "dstuser": "root"},
    "full_log": "sshd[2211]: Failed password for root from 203.0.113.77 port 51422 ssh2",
    "location": "ubuntu-lab-01->/var/log/auth.log",
}


def test_normalize_brute_force_alert():
    alert = normalize_wazuh_alert(BRUTE_FORCE_ALERT)
    assert alert.source == "wazuh"
    assert alert.source_rule_id == "100010"
    assert alert.severity == 10
    assert alert.source_ip == "203.0.113.77"
    assert alert.dst_user == "root"
    assert alert.agent_name == "kali-lab-02"
    assert alert.mitre_technique_ids == ["T1110"]
    assert alert.primary_technique.tactic == "Credential Access"
    assert alert.title == BRUTE_FORCE_ALERT["rule"]["description"]
    assert alert.raw_message.startswith("sshd[2211]")


def test_severity_clamped_to_10():
    raw = {**BRUTE_FORCE_ALERT, "rule": {**BRUTE_FORCE_ALERT["rule"], "level": 14}}
    assert normalize_wazuh_alert(raw).severity == 10
    raw_lo = {**BRUTE_FORCE_ALERT, "rule": {**BRUTE_FORCE_ALERT["rule"], "level": 0}}
    assert normalize_wazuh_alert(raw_lo).severity == 1


def test_normalize_minimal_alert_without_mitre():
    raw = {
        "id": "1",
        "timestamp": "2026-09-10T10:00:00Z",
        "rule": {"id": "3001", "level": 5, "description": "New file"},
        "data": {"username": "olivia.weber"},
    }
    alert = normalize_wazuh_alert(raw)
    assert alert.mitre == []
    assert alert.dst_user == "olivia.weber"
    assert alert.severity == 5
    assert alert.agent_name is None


def test_timestamp_parsing():
    alert = normalize_wazuh_alert(BRUTE_FORCE_ALERT)
    assert alert.event_time.year == 2026 and alert.event_time.month == 9