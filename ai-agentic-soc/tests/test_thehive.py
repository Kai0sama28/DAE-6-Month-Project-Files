from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Dict, List, Tuple

import httpx
import pytest

from services.triage_api.thehive import (
    DisabledTheHive,
    TheHiveClient,
    TheHiveConfig,
)


def _case() -> SimpleNamespace:
    return SimpleNamespace(
        incident_id="SOC-20261026-001",
        title="Incident Report SOC-20261026-001",
        severity="High",
        confidence="High",
        affected_host="Kali",
        source_address="192.168.64.3",
        detection_rule="100002 (level 12)",
        correlated_events="44",
        summary="A brute-force attack was detected.",
        report_path="/tmp/reports/SOC-20261026-001.md",
    )


def _client(handler) -> Tuple[TheHiveClient, List[Tuple[str, str]], List[Dict[str, Any]]]:
    seen: List[Tuple[str, str]] = []
    payloads: List[Dict[str, Any]] = []

    def wrapped(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path))
        if request.content:
            import json

            payloads.append(json.loads(request.content.decode("utf-8")))
        else:
            payloads.append({})
        return handler(request)

    transport = httpx.MockTransport(wrapped)
    http_client = httpx.Client(base_url="http://thehive", transport=transport)
    config = TheHiveConfig(url="http://thehive", user="admin", password="secret")
    return TheHiveClient(config, client=http_client), seen, payloads


def test_sync_creates_case_tags_and_comment():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/query":
            return httpx.Response(200, json=[])
        if request.url.path == "/api/v1/case":
            return httpx.Response(201, json={"_id": "~2", "number": 2})
        if request.url.path == "/api/v1/case/~2":
            return httpx.Response(200, json={})
        if request.url.path == "/api/v1/case/~2/comment":
            return httpx.Response(201, json={"_id": "~c1"})
        return httpx.Response(404, json={"message": "unexpected"})

    client, seen, payloads = _client(handler)
    result = client.sync_decision(
        _case(), "approved", "Kyrell", "Containment approved.", "2026-10-26T12:00:00+00:00"
    )

    assert result["status"] == "created"
    assert result["case_id"] == "~2"
    assert result["case_number"] == 2
    assert "incident:SOC-20261026-001" in result["tags"]
    assert "decision:approved" in result["tags"]
    assert "severity:high" in result["tags"]
    assert seen == [
        ("POST", "/api/v1/query"),
        ("POST", "/api/v1/case"),
        ("PATCH", "/api/v1/case/~2"),
        ("POST", "/api/v1/case/~2/comment"),
    ]
    created = payloads[1]
    assert created["title"].startswith("[SOC-20261026-001]")
    assert created["severity"] == 3
    assert "incident:SOC-20261026-001" in created["tags"]
    assert "2026-10-26T12:00:00+00:00" in payloads[-1]["message"]
    assert "Containment approved." in payloads[-1]["message"]


def test_sync_updates_existing_case_without_recreating_it():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/query":
            return httpx.Response(
                200,
                json=[
                    {
                        "_id": "~9",
                        "number": 9,
                        "title": "[SOC-20261026-001] existing",
                        "description": "SOC-20261026-001",
                        "tags": ["incident:SOC-20261026-001"],
                    }
                ],
            )
        if request.url.path == "/api/v1/case/~9":
            return httpx.Response(200, json={})
        if request.url.path == "/api/v1/case/~9/comment":
            return httpx.Response(201, json={"_id": "~c2"})
        return httpx.Response(404, json={"message": "unexpected"})

    client, seen, _ = _client(handler)
    result = client.sync_decision(_case(), "rejected", "Kyrell", "False positive.", "now")

    assert result["status"] == "updated"
    assert result["case_id"] == "~9"
    assert result["case_number"] == 9
    assert ("POST", "/api/v1/case") not in seen
    assert ("PATCH", "/api/v1/case/~9") in seen
    assert ("POST", "/api/v1/case/~9/comment") in seen


def test_rejected_decision_without_case_is_skipped():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[])

    client, seen, _ = _client(handler)
    result = client.sync_decision(_case(), "rejected", "Kyrell", "False positive.", "now")

    assert result["status"] == "skipped"
    assert seen == [("POST", "/api/v1/query")]


def test_thehive_http_error_is_returned_not_raised():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"message": "boom"})

    client, _, _ = _client(handler)
    result = client.sync_decision(_case(), "approved", "Kyrell", "note", "now")

    assert result["status"] == "error"
    assert "HTTPStatusError" in result["error"]


def test_disabled_client_is_a_noop():
    result = DisabledTheHive().sync_decision(_case(), "approved", "Kyrell", "note", "now")
    assert result["status"] == "disabled"
    assert DisabledTheHive().ping() is False


def test_organisation_header_is_sent():
    seen: List[Any] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("X-Organisation"))
        return httpx.Response(200, json=[])

    http_client = httpx.Client(
        base_url="http://thehive", transport=httpx.MockTransport(handler)
    )
    config = TheHiveConfig(url="http://thehive", api_key="key", organisation="soc")
    client = TheHiveClient(config, client=http_client)

    assert client.find_case("SOC-20261026-001") is None
    assert seen == ["soc"]


def test_config_requires_credentials_and_can_be_disabled(monkeypatch):
    monkeypatch.setenv("THEHIVE_ENABLED", "false")
    assert TheHiveConfig.from_env() is None

    monkeypatch.setenv("THEHIVE_ENABLED", "true")
    monkeypatch.setenv("THEHIVE_URL", "http://hive:9000")
    monkeypatch.setenv("THEHIVE_USER", "analyst@example.test")
    monkeypatch.setenv("THEHIVE_PASSWORD", "not-a-real-secret")
    monkeypatch.setenv("THEHIVE_ORGANISATION", "soc")
    config = TheHiveConfig.from_env()
    assert config is not None
    assert config.url == "http://hive:9000"
    assert config.user == "analyst@example.test"
    assert config.organisation == "soc"
