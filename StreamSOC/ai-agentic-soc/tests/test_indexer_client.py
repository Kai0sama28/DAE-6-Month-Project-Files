from __future__ import annotations

import json

import httpx
import pytest

from siem.indexer_client import IndexerAPIError, IndexerClient
from siem.normalizer import normalize_wazuh_alert

SAMPLE_DOC = {
    "_index": "wazuh-alerts-4.x-2026.10.01",
    "_id": "m1N0-KABMZhxAQGafzID",
    "_source": {
        "@timestamp": "2026-10-01T16:25:00.643Z",
        "id": "1915635.198480",
        "timestamp": "2026-10-01T16:25:00.642+0000",
        "location": "journald",
        "rule": {
            "level": 10,
            "description": "sshd: brute force trying to get access to the system. Authentication failed.",
            "id": "5763",
            "groups": ["syslog", "sshd", "authentication_failures"],
            "mitre": {
                "technique": ["Brute Force"],
                "id": ["T1110"],
                "tactic": ["Credential Access"],
            },
        },
        "agent": {"id": "002", "name": "Kali", "ip": "192.168.64.3"},
        "data": {"srcip": "192.168.64.3", "dstuser": "labtester", "srcport": "58160"},
        "full_log": "Failed password for labtester from 192.168.64.3 port 58160 ssh2",
    },
}


def _fake_indexer(
    captured: list,
    search_response: dict = None,
    count_response: dict = None,
    doc_response: dict = None,
    search_status: int = 200,
    count_status: int = 200,
    cluster_status: int = 200,
) -> httpx.Client:
    search_response = search_response or {"hits": {"total": {"value": 1}, "hits": [SAMPLE_DOC]}}
    count_response = {"count": 7} if count_response is None else count_response
    doc_response = doc_response or {"found": True, "_source": SAMPLE_DOC["_source"]}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        path = request.url.path
        if path == "/_cluster/health":
            return httpx.Response(cluster_status, json={"status": "green"})
        if path.endswith("/_search"):
            return httpx.Response(search_status, json=search_response)
        if path.endswith("/_count"):
            return httpx.Response(count_status, json=count_response)
        if "/_doc/" in path:
            return httpx.Response(200, json=doc_response)
        return httpx.Response(404, json={"error": {"type": "index_not_found_exception"}})

    return httpx.Client(transport=httpx.MockTransport(handler))


def _client(captured: list = None, **kwargs) -> IndexerClient:
    return IndexerClient(
        base_url="https://indexer.test:9200",
        username="reader",
        password="pw",
        client=_fake_indexer(captured if captured is not None else [], **kwargs),
    )


def _sent_body(request: httpx.Request) -> dict:
    return json.loads(request.content.decode())


def test_query_alerts_returns_wazuh_alerts():
    client = _client()
    alerts = client.query_alerts(limit=5)
    assert len(alerts) == 1
    assert alerts[0].rule is not None
    assert alerts[0].rule.id == "5763"
    assert alerts[0].rule.level == 10
    assert alerts[0].agent is not None
    assert alerts[0].agent.name == "Kali"
    assert alerts[0].id == "1915635.198480"


def test_query_alerts_posts_dsl_for_filters():
    captured: list = []
    client = _client(captured)
    client.query_alerts(filters={"rule.id": "5763", "agent.id": "002"}, limit=5, offset=10)
    request = captured[-1]
    body = _sent_body(request)
    assert request.url.path == "/wazuh-alerts-*/_search"
    assert body["size"] == 5
    assert body["from"] == 10
    assert body["sort"] == [{"timestamp": {"order": "desc"}}]
    assert body["track_total_hits"] is True
    assert body["query"] == {
        "bool": {
            "filter": [
                {"term": {"rule.id": "5763"}},
                {"term": {"agent.id": "002"}},
            ]
        }
    }


def test_query_alerts_applies_time_window():
    captured: list = []
    client = _client(captured)
    client.query_alerts(since="2026-09-30T18:00:00+0000", until="2026-10-01T23:59:59+0000")
    clauses = _sent_body(captured[-1])["query"]["bool"]["filter"]
    assert clauses == [
        {"range": {"timestamp": {"gte": "2026-09-30T18:00:00+0000", "lte": "2026-10-01T23:59:59+0000"}}}
    ]


def test_query_alerts_without_arguments_matches_all():
    captured: list = []
    client = _client(captured)
    client.query_alerts()
    assert _sent_body(captured[-1])["query"] == {"match_all": {}}


def test_free_text_q_becomes_terms():
    captured: list = []
    client = _client(captured)
    client.query_alerts(q="rule.id=5763;agent.id=002")
    clauses = _sent_body(captured[-1])["query"]["bool"]["filter"]
    assert clauses == [{"term": {"rule.id": "5763"}}, {"term": {"agent.id": "002"}}]


def test_free_text_q_supports_not_equal():
    captured: list = []
    client = _client(captured)
    client.query_alerts(q="rule.id!=5710")
    clauses = _sent_body(captured[-1])["query"]["bool"]["filter"]
    assert clauses == [{"bool": {"must_not": [{"term": {"rule.id": "5710"}}]}}]


def test_free_text_q_rejects_unsupported_expression():
    client = _client()
    with pytest.raises(ValueError):
        client.query_alerts(q="rule.id:5763")


def test_list_filter_uses_terms_query():
    captured: list = []
    client = _client(captured)
    client.query_alerts(filters={"rule.id": ["5763", "5760"]})
    clauses = _sent_body(captured[-1])["query"]["bool"]["filter"]
    assert clauses == [{"terms": {"rule.id": ["5763", "5760"]}}]


def test_alerts_feed_the_existing_normalizer():
    client = _client()
    alert = normalize_wazuh_alert(client.query_alerts(limit=1)[0])
    assert alert.source == "wazuh"
    assert alert.source_rule_id == "5763"
    assert alert.source_ip == "192.168.64.3"
    assert alert.dst_user == "labtester"
    assert alert.agent_name == "Kali"
    assert alert.mitre_technique_ids == ["T1110"]
    assert alert.title.startswith("sshd: brute force")


def test_alert_id_falls_back_to_indexer_doc_id():
    source = dict(SAMPLE_DOC["_source"])
    source.pop("id")
    client = _client(search_response={"hits": {"total": {"value": 1}, "hits": [
        {"_index": "wazuh-alerts-4.x-2026.10.01", "_id": "doc-xyz", "_source": source}
    ]}})
    alerts = client.query_alerts(limit=1)
    assert alerts[0].id == "doc-xyz"


def test_count_alerts_uses_count_endpoint():
    captured: list = []
    client = _client(captured)
    assert client.count_alerts(filters={"rule.id": "5763"}) == 7
    request = captured[-1]
    assert request.url.path == "/wazuh-alerts-*/_count"
    assert _sent_body(request)["query"] == {"bool": {"filter": [{"term": {"rule.id": "5763"}}]}}


def test_get_alert_by_wazuh_alert_id():
    captured: list = []
    client = _client(captured)
    alert = client.get_alert("1915635.198480")
    assert alert is not None
    assert alert.rule is not None
    assert alert.rule.id == "5763"
    assert "/_doc/" not in captured[-1].url.path


def test_get_alert_falls_back_to_indexer_doc_id():
    captured: list = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        if request.url.path.endswith("/_search"):
            return httpx.Response(200, json={"hits": {"total": {"value": 0}, "hits": []}})
        return httpx.Response(200, json={"found": True, "_source": SAMPLE_DOC["_source"]})

    client = IndexerClient(
        base_url="https://indexer.test:9200",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    alert = client.get_alert("m1N0-KABMZhxAQGafzID")
    assert alert is not None
    assert alert.id == "1915635.198480"
    assert captured[-1].url.path == "/wazuh-alerts-*/_doc/m1N0-KABMZhxAQGafzID"


def test_get_alert_returns_none_when_missing():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/_search"):
            return httpx.Response(200, json={"hits": {"total": {"value": 0}, "hits": []}})
        return httpx.Response(404, json={"_index": "wazuh-alerts-*", "found": False})

    client = IndexerClient(
        base_url="https://indexer.test:9200",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    assert client.get_alert("missing-id") is None


def test_missing_index_yields_empty_results():
    not_found = {"error": {"type": "index_not_found_exception"}, "status": 404}
    client = _client(search_status=404, search_response=not_found, count_status=404,
                     count_response=not_found)
    assert client.query_alerts() == []
    assert client.count_alerts() == 0


def test_server_error_raises():
    client = _client(search_status=500, search_response={"error": "boom"})
    with pytest.raises(IndexerAPIError) as err:
        client.query_alerts()
    assert "500" in str(err.value)


def test_ping_reports_indexer_health():
    assert _client().ping() is True
    assert _client(cluster_status=503).ping() is True


def test_ping_is_false_when_indexer_is_unreachable():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    client = IndexerClient(
        base_url="https://indexer.test:9200",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    assert client.ping() is False


def test_credentials_come_from_environment(monkeypatch):
    monkeypatch.setenv("WAZUH_INDEXER_URL", "https://indexer.lab:9200/")
    monkeypatch.setenv("WAZUH_INDEXER_USER", "alert-reader")
    monkeypatch.setenv("WAZUH_INDEXER_PASSWORD", "s3cret")
    monkeypatch.setenv("WAZUH_INDEXER_INDEX", "wazuh-alerts-4.x-*")
    client = IndexerClient()
    assert client.base_url == "https://indexer.lab:9200"
    assert client.username == "alert-reader"
    assert client.password == "s3cret"
    assert client.index_pattern == "wazuh-alerts-4.x-*"
    client.close()