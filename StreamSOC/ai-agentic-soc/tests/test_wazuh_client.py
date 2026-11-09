from __future__ import annotations

import httpx

from siem.client import WazuhClient
from siem.normalizer import normalize_wazuh_alert

SAMPLE_ALERT = {
    "id": "1726100520.123456",
    "timestamp": "2026-09-10T14:22:07.481+0000",
    "rule": {
        "id": "100010",
        "level": 10,
        "description": "SSHD brute force detected",
        "mitre": {"id": ["T1110"]},
    },
    "agent": {"id": "011", "name": "kali-lab-02", "ip": "10.11.3.57"},
    "data": {"srcip": "203.0.113.77", "dstuser": "root"},
    "full_log": "Failed password for root from 203.0.113.77",
}

SAMPLE_AGENT = {"id": "011", "name": "kali-lab-02", "ip": "10.11.3.57"}


def _fake_wazuh():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/security/user/authenticate":
            return httpx.Response(200, json={"data": {"token": "JWTabc123"}})
        if request.url.path == "/security-events":
            return httpx.Response(200, json={"data": {"affected_items": [SAMPLE_ALERT]}})
        if request.url.path == "/agents":
            return httpx.Response(200, json={"data": {"affected_items": [SAMPLE_AGENT]}})
        return httpx.Response(404, json={"error": "not found"})

    transport = httpx.MockTransport(handler)
    return httpx.Client(transport=transport)


def test_authenticate_flow():
    client = WazuhClient(base_url="https://wazuh.test:55000",
                         username="admin", password="pw",
                         client=_fake_wazuh())
    token = client.authenticate()
    assert token == "JWTabc123"


def test_query_alerts_normalized():
    client = WazuhClient(base_url="https://wazuh.test:55000",
                         username="admin", password="pw",
                         client=_fake_wazuh())
    alerts = client.query_alerts(limit=1)
    assert len(alerts) == 1
    assert normalize_wazuh_alert(alerts[0]).source_ip == "203.0.113.77"


def test_list_agents():
    client = WazuhClient(base_url="https://wazuh.test:55000",
                         username="admin", password="pw",
                         client=_fake_wazuh())
    agents = client.list_agents()
    assert agents[0].name == "kali-lab-02"