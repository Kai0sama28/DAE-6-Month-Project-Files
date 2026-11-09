from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

import httpx
import pytest

from agent.config import AgentConfig
from agent.correlation import build_window, correlate
from agent.events import classify_phase, event_from_wazuh
from agent.graph import build_graph, plan_pillars
from agent.llm import OpenRouterClient, OpenRouterError, extract_json_object
from agent.notifier import _applescript_escape, build_clickable_script
from agent.report import (
    build_analysis_prompt,
    build_incident_id,
    render_report,
    render_report_html,
    write_report,
    write_report_html,
)
from agent.state import AgentState
from agent.events import _parse_ts
from schemas.wazuh import WazuhAgent, WazuhAlert, WazuhRule, WazuhRuleMitre

UTC = timezone.utc


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def make_alert(
    alert_id: str,
    rule_id: str,
    level: int,
    description: str,
    timestamp: str,
    agent_id: str = "002",
    agent_ip: str = "192.168.64.3",
    src_ip: Optional[str] = "192.168.64.3",
    dst_user: Optional[str] = "labtester",
    groups: Optional[list] = None,
    mitre: Optional[list] = None,
    firedtimes: int = 0,
    full_log: str = "",
) -> WazuhAlert:
    return WazuhAlert(
        id=alert_id,
        timestamp=timestamp,
        rule=WazuhRule(
            id=rule_id,
            level=level,
            description=description,
            groups=groups if groups is not None else ["syslog", "sshd"],
            mitre=WazuhRuleMitre(id=mitre or [], tactic=[]) if mitre else None,
            firedtimes=firedtimes,
        ),
        agent=WazuhAgent(id=agent_id, name="Kali", ip=agent_ip),
        data={"srcip": src_ip, "dstuser": dst_user} if src_ip or dst_user else {},
        full_log=full_log or f"Oct 21 16:52:38 kali sshd[1]: event {alert_id}",
    )


class FakeIndexer:
    """Minimal stand-in for :class:`siem.indexer_client.IndexerClient`."""

    def __init__(self, alerts: list) -> None:
        self.alerts = alerts
        self.index_pattern = "wazuh-alerts-*"
        self.calls: list = []

    def query_alerts(self, q=None, filters=None, limit=100, offset=0,
                     since=None, until=None) -> list:
        self.calls.append({"filters": filters, "since": since, "until": until})
        result = []
        for alert in self.alerts:
            ts = _parse_ts(alert.timestamp)
            if since and ts is not None and ts < _parse_ts(since):
                continue
            if until and ts is not None and ts > _parse_ts(until):
                continue
            if filters:
                keep = True
                for field, value in filters.items():
                    if field == "agent.id":
                        actual = alert.agent.id if alert.agent else None
                    elif field == "data.srcip":
                        actual = (alert.data or {}).get("srcip")
                    elif field == "data.dstuser":
                        actual = (alert.data or {}).get("dstuser")
                    elif field == "rule.groups":
                        actual = alert.rule.groups if alert.rule else []
                    else:
                        actual = None
                    if isinstance(actual, list):
                        keep = keep and value in actual
                    else:
                        keep = keep and actual == value
                if not keep:
                    continue
            result.append(alert)
        return result[:limit]

    def get_alert(self, alert_id: str) -> Optional[WazuhAlert]:
        for alert in self.alerts:
            if alert.id == alert_id:
                return alert
        return None

    def ping(self) -> bool:
        return True


# ---------------------------------------------------------------------------
# OpenRouter client
# ---------------------------------------------------------------------------

def _chat_response(content: str, **extra) -> dict:
    payload = {
        "id": "gen-1",
        "model": "nvidia/nemotron-3.5-lightning:free",
        "created": 1,
        "object": "chat.completion",
        "choices": [
            {
                "index": 0,
                "finish_reason": "stop",
                "message": {"role": "assistant", "content": content},
            }
        ],
        "usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150},
    }
    payload.update(extra)
    return payload


def test_openrouter_chat_returns_content():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["auth"] = request.headers.get("Authorization")
        captured["title"] = request.headers.get("X-Title")
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json=_chat_response("hello analyst"))

    client = OpenRouterClient(
        api_key="sk-or-test",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    result = client.chat([{"role": "user", "content": "hi"}], system="be terse")

    assert result.content == "hello analyst"
    assert result.prompt_tokens == 100
    assert result.completion_tokens == 50
    assert captured["url"] == "https://openrouter.ai/api/v1/chat/completions"
    assert captured["auth"] == "Bearer sk-or-test"
    assert captured["title"] == "AI-Agentic SOC Triage Engine"
    assert captured["body"]["model"] == "nvidia/nemotron-3.5-lightning:free"
    assert captured["body"]["messages"][0]["role"] == "system"


def test_openrouter_json_mode_sets_response_format():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json=_chat_response('{"severity": "High"}'))

    client = OpenRouterClient(
        api_key="sk-or-test",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    parsed = client.chat_json([{"role": "user", "content": "go"}])

    assert parsed == {"severity": "High"}
    assert captured["body"]["response_format"] == {"type": "json_object"}


def test_openrouter_json_repairs_prose_reply():
    """A prose reply is re-asked instead of failing the investigation."""
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(json.loads(request.content))
        if len(calls) == 1:
            return httpx.Response(200, json=_chat_response(
                "Sure! Here is the analysis: the attacker tried 34 passwords."
            ))
        return httpx.Response(200, json=_chat_response('{"severity": "High", "ok": true}'))

    client = OpenRouterClient(
        api_key="sk-or-test",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    parsed = client.chat_json([{"role": "user", "content": "analyse"}], model="m")

    assert parsed == {"severity": "High", "ok": True}
    assert len(calls) == 2
    assert calls[1]["messages"][-1]["role"] == "user"
    assert "ONLY the JSON object" in calls[1]["messages"][-1]["content"]
    assert client.last_usage["prompt_tokens"] == 200


def test_openrouter_json_repairs_truncated_object():
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(json.loads(request.content))
        if len(calls) == 1:
            return httpx.Response(200, json=_chat_response(
                '{"severity": "High", "executive_summary": "brute force'
            ))
        return httpx.Response(200, json=_chat_response('```json\n{"severity": "High"}\n```'))

    client = OpenRouterClient(
        api_key="sk-or-test",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    assert client.chat_json([{"role": "user", "content": "x"}], model="m") == {"severity": "High"}
    assert len(calls) == 2


def test_openrouter_retries_on_rate_limit():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] < 3:
            return httpx.Response(429, json={"error": {"message": "slow down"}})
        return httpx.Response(200, json=_chat_response("ok"))

    client = OpenRouterClient(
        api_key="sk-or-test",
        max_retries=3,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    result = client.chat([{"role": "user", "content": "go"}])

    assert result.content == "ok"
    assert calls["n"] == 3


def test_openrouter_raises_on_unauthorized():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": {"message": "no key"}})

    client = OpenRouterClient(
        api_key="bad",
        max_retries=1,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(OpenRouterError) as exc:
        client.chat([{"role": "user", "content": "go"}])
    assert exc.value.status_code == 401


def test_openrouter_falls_back_when_json_mode_rejected():
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if "response_format" in body:
            return httpx.Response(400, json={"error": {"message": "unsupported"}})
        return httpx.Response(200, json=_chat_response('{"severity": "Low"}'))

    client = OpenRouterClient(
        api_key="sk-or-test",
        max_retries=1,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    assert client.chat_json([{"role": "user", "content": "go"}]) == {"severity": "Low"}


@pytest.mark.parametrize(
    "text",
    [
        '{"a": 1}',
        '```json\n{"a": 1}\n```',
        'Here you go:\n{"a": 1}',
        '{"a": 1}\nHope that helps.',
        '```\n{"a": 1}\n```',
    ],
)
def test_extract_json_object_variants(text):
    assert extract_json_object(text) == {"a": 1}


def test_extract_json_object_rejects_garbage():
    assert extract_json_object("not json at all") is None
    assert extract_json_object("") is None


# ---------------------------------------------------------------------------
# events + correlation
# ---------------------------------------------------------------------------

def test_classify_phase_uses_rule_id_then_group():
    assert classify_phase("5760", ["syslog"]) == "AUTH_FAILURE"
    assert classify_phase("100002", ["sshd"]) == "AUTH_FAILURE"
    assert classify_phase("5402", ["sudo"]) == "PRIVILEGE"
    assert classify_phase("550", ["syscheck"]) == "INTEGRITY"
    assert classify_phase("40112", ["syslog"]) == "AUTH_SUCCESS"
    assert classify_phase("999999", ["some_random_group"]) == "OTHER"


def test_event_from_wazuh_extracts_fields():
    alert = make_alert(
        "1.1", "100002", 12, "Verified SSH brute force",
        "2026-10-21T16:52:39.293+0000", mitre=["T1110"], firedtimes=6,
    )
    event = event_from_wazuh(alert)

    assert event["id"] == "1.1"
    assert event["rule_id"] == "100002"
    assert event["level"] == 12
    assert event["src_ip"] == "192.168.64.3"
    assert event["dst_user"] == "labtester"
    assert event["agent_id"] == "002"
    assert event["mitre"] == ["T1110"]
    assert event["phase"] == "AUTH_FAILURE"
    assert event["firedtimes"] == 6
    assert isinstance(event["ts"], datetime)


def test_correlate_links_events_by_agent_source_and_user():
    base = datetime(2026, 10, 21, 16, 52, 39, tzinfo=UTC)
    trigger = event_from_wazuh(make_alert(
        "t1", "100002", 12, "brute force", "2026-10-21T16:52:39.293+0000",
    ))
    related = [
        trigger,
        event_from_wazuh(make_alert(
            "a1", "5760", 5, "sshd: authentication failed.",
            "2026-10-21T16:52:31.283+0000", firedtimes=3,
        )),
        event_from_wazuh(make_alert(
            "a2", "5715", 3, "sshd: session opened.",
            "2026-10-21T16:53:01.000+0000", src_ip="10.0.0.9", dst_user="root",
        )),
        event_from_wazuh(make_alert(
            "a3", "5402", 3, "sudo", "2026-10-21T16:51:00.000+0000",
            agent_id="007", agent_ip="10.11.1.232", src_ip="10.11.1.232",
            dst_user="admin",
        )),
    ]

    result = correlate(trigger, related, base - timedelta(minutes=30),
                       base + timedelta(minutes=15))

    assert result["event_count"] == 4
    relations = result["relation_counts"]
    assert relations["TRIGGER"] == 1
    assert relations["SAME_AGENT"] == 3          # a1, a2, trigger
    assert relations["SAME_SOURCE_IP"] == 2      # trigger + a1
    assert relations["SAME_USER"] == 2           # trigger + a1
    assert result["flags"]["auth_success_observed"] is True
    assert result["flags"]["source_equals_agent_ip"] is True
    assert len(result["timeline"]) == 4
    # timeline must be ordered oldest -> newest
    stamps = [entry["timestamp"] for entry in result["timeline"]]
    assert stamps == sorted(stamps)


def test_correlate_uses_max_firedtimes_not_sum():
    base = datetime(2026, 10, 21, 16, 52, 39, tzinfo=UTC)
    trigger = event_from_wazuh(make_alert(
        "t1", "100002", 12, "brute force", "2026-10-21T16:52:39.293+0000",
    ))
    related = [
        trigger,
        event_from_wazuh(make_alert(
            "f1", "5760", 5, "failed", "2026-10-21T16:52:31.283+0000", firedtimes=34,
        )),
        event_from_wazuh(make_alert(
            "f2", "5503", 5, "pam failed", "2026-10-21T16:52:30.283+0000", firedtimes=8,
        )),
    ]
    result = correlate(trigger, related, base - timedelta(minutes=30),
                       base + timedelta(minutes=15))

    assert result["flags"]["failed_attempt_count"] == 34
    assert result["flags"]["indexed_failure_events"] == 2
    assert result["flags"]["failed_attempt_counter_by_rule"] == {"5760": 34, "5503": 8}


def test_correlate_does_not_count_pam_session_as_fim():
    base = datetime(2026, 10, 21, 16, 52, 39, tzinfo=UTC)
    trigger = event_from_wazuh(make_alert(
        "t1", "100002", 12, "brute force", "2026-10-21T16:52:39.293+0000",
    ))
    related = [
        trigger,
        event_from_wazuh(make_alert(
            "s1", "5501", 3, "PAM: Login session opened.",
            "2026-10-21T16:52:30.283+0000",
        )),
    ]
    result = correlate(trigger, related, base - timedelta(minutes=30),
                       base + timedelta(minutes=15))

    assert result["flags"]["file_integrity_change_observed"] is False
    assert result["flags"]["session_activity_observed"] is True
    assert result["phase_counts"]["EXECUTION"] == 1


def test_build_window_uses_lookback_and_post():
    trigger = event_from_wazuh(make_alert(
        "t1", "100002", 12, "brute force", "2026-10-21T16:52:39.293+0000",
    ))
    start, end = build_window(trigger, lookback_minutes=30, post_minutes=15)
    assert (end - start) == timedelta(minutes=45)
    assert start.minute == 22
    assert end.minute == 7


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------

def _demo_correlation():
    base = datetime(2026, 10, 21, 16, 52, 39, tzinfo=UTC)
    trigger = event_from_wazuh(make_alert(
        "t1", "100002", 12, "Verified SSH brute force", "2026-10-21T16:52:39.293+0000",
        mitre=["T1110"], firedtimes=6,
    ))
    related = [
        trigger,
        event_from_wazuh(make_alert(
            "f1", "5760", 5, "sshd: authentication failed.",
            "2026-10-21T16:52:31.283+0000", firedtimes=34,
        )),
    ]
    return trigger, correlate(trigger, related, base - timedelta(minutes=30),
                              base + timedelta(minutes=15))


def test_render_report_contains_all_sections():
    trigger, correlation = _demo_correlation()
    content = render_report(
        incident_id="SOC-TEST-001",
        trigger=trigger,
        correlation=correlation,
        analysis={
            "executive_summary": "A brute force was observed.",
            "severity": "Medium",
            "severity_rationale": "Blocked, no success observed.",
            "confidence": "High",
            "attack_narrative": "The attacker tried 34 passwords.",
            "key_findings": ["34 failed attempts"],
            "mitre_mapping": [
                {"technique_id": "T1110", "technique_name": "Brute Force",
                 "tactic": "Credential Access", "evidence": "rule 100002"}
            ],
            "recommended_actions": [
                {"priority": "High", "action": "Block the source", "rationale": "brute force"}
            ],
            "containment_recommendations": ["sshd deny list"],
            "false_positive_assessment": "Not a false positive.",
            "data_gaps": ["No EDR telemetry"],
        },
        metrics={"mttd_seconds": 4.2, "triage_seconds": 9.1, "total_seconds": 13.3,
                 "manual_baseline_seconds": 2700, "time_saved_seconds": 2686.7},
        model="nvidia/nemotron-3.5-lightning:free",
        generated_at=datetime(2026, 10, 21, 18, 0, 0, tzinfo=UTC),
    )

    for heading in (
        "# Incident Report SOC-TEST-001",
        "## 1. Executive Summary",
        "## 2. Detection Facts",
        "## 3. Key Findings",
        "## 4. Log Correlation",
        "## 5. Incident Timeline",
        "## 6. Attack Narrative",
        "## 7. MITRE ATT&CK Mapping",
        "## 8. Risk Assessment",
        "## 9. Recommended Actions",
        "## 10. Evidence Gaps and Caveats",
        "## 11. Detection and Triage Metrics",
        "## 12. Provenance and Audit Trail",
    ):
        assert heading in content, heading

    assert "34 failed attempts" in content
    assert "T1110" in content
    assert "nvidia/nemotron-3.5-lightning:free" in content
    assert "recommendations only" in content


def test_render_report_without_llm_still_produces_a_report():
    trigger, correlation = _demo_correlation()
    content = render_report(
        incident_id="SOC-TEST-002",
        trigger=trigger,
        correlation=correlation,
        analysis=None,
        metrics={},
        model="deterministic-only (no LLM)",
    )
    assert "# Incident Report SOC-TEST-002" in content
    assert "narrative engine was unavailable" in content


def test_render_report_html_is_self_contained_and_escaped():
    trigger, correlation = _demo_correlation()
    html = render_report_html(
        incident_id="SOC-TEST-003",
        trigger=trigger,
        correlation=correlation,
        analysis={
            "executive_summary": "Brute force with <script>alert(1)</script> & quotes",
            "severity": "High",
            "confidence": "High",
            "attack_narrative": "18 failures.",
            "key_findings": ["18 failed attempts"],
            "mitre_mapping": [{"technique_id": "T1110", "technique_name": "Brute Force",
                               "tactic": "Credential Access", "evidence": "rule 100002"}],
            "recommended_actions": [{"priority": "High", "action": "Block source",
                                     "rationale": "brute force"}],
            "containment_recommendations": ["sshd deny list"],
            "false_positive_assessment": "Not a false positive.",
            "data_gaps": ["No EDR telemetry"],
        },
        metrics={"mttd_seconds": 4.2, "manual_baseline_seconds": 2700,
                 "time_saved_seconds": 2686.7, "run_id": "r1"},
        model="nvidia/nemotron-3.5-lightning:free",
        generated_at=datetime(2026, 10, 21, 18, 0, 0, tzinfo=UTC),
    )

    assert html.startswith("<!DOCTYPE html>")
    assert "</html>" in html
    # self-contained: no external assets or scripts
    assert "<script" not in html
    assert "http://" not in html and "https://" not in html
    # the injected markup must be escaped, never rendered
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    # key facts land in the HTML too
    assert "SOC-TEST-003" in html
    assert "T1110" in html
    assert "High" in html
    # section headers
    for heading in ("Executive Summary", "Incident Timeline", "MITRE ATT&amp;CK Mapping",
                    "Recommended Actions", "Provenance and Audit Trail"):
        assert heading in html


def test_render_report_html_without_llm():
    trigger, correlation = _demo_correlation()
    html = render_report_html(
        incident_id="SOC-TEST-004",
        trigger=trigger,
        correlation=correlation,
        analysis=None,
        metrics={},
        model="deterministic-only (no LLM)",
    )
    assert "Narrative engine unavailable" in html
    assert "SOC-TEST-004" in html


def test_write_report_html_creates_file_and_latest(tmp_path: Path):
    incident_id = build_incident_id(9, datetime(2026, 10, 21, tzinfo=UTC))
    path = write_report_html("<html></html>", tmp_path, incident_id)
    assert path.exists()
    assert path.suffix == ".html"
    assert (tmp_path / "LATEST.html").exists()


def test_clickable_script_prefers_html_report_for_open(tmp_path: Path):
    md = tmp_path / "SOC-X.md"
    html = tmp_path / "SOC-X.html"
    script = build_clickable_script("title", "msg", md, html_path=html)
    assert f'set reportPath to "{md}"' in script
    assert f'set openPath to "{html}"' in script
    assert "quoted form of openPath" in script
    assert "quoted form of reportPath" in script  # reveal still uses the md path


def test_write_report_creates_file_and_latest(tmp_path: Path):
    incident_id = build_incident_id(7, datetime(2026, 10, 21, tzinfo=UTC))
    path = write_report("# body", tmp_path, incident_id)
    assert path.exists()
    assert path.name == f"{incident_id}.md"
    assert (tmp_path / "LATEST.md").read_text(encoding="utf-8") == "# body"


def test_build_analysis_prompt_includes_facts():
    trigger, correlation = _demo_correlation()
    prompt = build_analysis_prompt(
        trigger, correlation, {"mttd_seconds": 3.0, "triage_seconds": 4.0}
    )
    assert "TRIGGER ALERT" in prompt
    assert "100002" in prompt
    assert "failed_attempt_count" in prompt
    assert "TIMELINE" in prompt


# ---------------------------------------------------------------------------
# supervisor plan + state + notifier
# ---------------------------------------------------------------------------

def test_plan_pillars_requires_identity_for_account_alerts():
    plan = plan_pillars({"dst_user": "labtester", "agent_name": "Kali", "phase": "AUTH_FAILURE"})
    assert plan["siem"]["required"] is True
    assert plan["identity"]["required"] is True
    assert plan["edr"]["required"] is True


def test_plan_pillars_skips_optional_pillars_for_plain_events():
    plan = plan_pillars({"dst_user": "", "agent_name": "", "phase": "SYSTEM"})
    assert plan["identity"]["required"] is False
    assert plan["edr"]["required"] is False


def test_agent_state_roundtrip(tmp_path: Path):
    path = tmp_path / "state.json"
    state = AgentState(path)
    assert state.cursor is None

    state.set_cursor("2026-10-21T16:52:39.293000+00:00")
    state.mark_seen(["a", "b"])
    state.mark_seen(["b", "c"])
    state.save()

    reloaded = AgentState(path)
    assert reloaded.cursor == "2026-10-21T16:52:39.293000+00:00"
    assert reloaded.seen_ids == {"a", "b", "c"}
    assert reloaded.next_incident_seq() == 1
    assert reloaded.next_incident_seq() == 2


def test_agent_state_dedupe_window():
    state = AgentState(Path("/tmp/ai-agentic-soc-tests/dedupe-state.json"))
    assert state.is_recent_key("002|1.2.3.4", 600) is False
    state.remember_key("002|1.2.3.4")
    assert state.is_recent_key("002|1.2.3.4", 600) is True
    assert state.is_recent_key("002|1.2.3.5", 600) is False


def test_applescript_escape():
    assert _applescript_escape('say "hi"') == 'say \\"hi\\"'


def test_clickable_dialog_script_compiles(tmp_path: Path):
    """The notification dialog must be valid AppleScript.

    A stray quote in the dialog text once made the script fail to compile,
    so the notification silently disappeared. `osacompile` is the check.
    """
    import shutil
    import subprocess

    if not shutil.which("osacompile"):
        pytest.skip("osacompile not available on this platform")

    report = tmp_path / "SOC-20261021-001.md"
    report.write_text("# report", encoding="utf-8")
    script = build_clickable_script(
        "AI-Agentic SOC",
        'Click test — "Open Report" opens the file.',
        report,
    )
    script_path = tmp_path / "dialog.applescript"
    script_path.write_text(script, encoding="utf-8")

    result = subprocess.run(
        ["osacompile", "-o", str(tmp_path / "dialog.scpt"), str(script_path)],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr


# ---------------------------------------------------------------------------
# graph end to end
# ---------------------------------------------------------------------------

def test_graph_runs_end_to_end_and_writes_a_report(tmp_path: Path):
    alerts = [
        make_alert("t1", "100002", 12, "Verified SSH brute force",
                   "2026-10-21T16:52:39.293+0000", mitre=["T1110"], firedtimes=6),
        make_alert("f1", "5760", 5, "sshd: authentication failed.",
                   "2026-10-21T16:52:31.283+0000", firedtimes=34),
        make_alert("f2", "5760", 5, "sshd: authentication failed.",
                   "2026-10-21T16:52:27.283+0000", firedtimes=33),
    ]
    indexer = FakeIndexer(alerts)
    config = AgentConfig(
        use_llm=False,
        reports_dir=tmp_path / "reports",
        state_file=tmp_path / "state.json",
        notify=False,
        min_rule_level=4,
    )
    store = AgentState(config.state_file)
    graph = build_graph(config, indexer, None, store)

    result = graph.invoke({
        "trigger": event_from_wazuh(alerts[0]),
        "detected_at": datetime.now(UTC).isoformat(),
        "skip_watch": True,
        "seen_ids": [],
        "pending": [],
        "errors": [],
        "query_count": 0,
    })

    assert result["status"] == "notified"
    assert result["report_path"]
    report = Path(result["report_path"])
    assert report.exists()
    body = report.read_text(encoding="utf-8")
    assert "Verified SSH brute force" in body
    # an HTML sibling report is produced for the dashboard / browser view
    assert result["report_html_path"]
    html_report = Path(result["report_html_path"])
    assert html_report.exists()
    assert html_report.suffix == ".html"
    html_body = html_report.read_text(encoding="utf-8")
    assert html_body.startswith("<!DOCTYPE html>")
    assert "SOC-" in html_body
    assert result["correlation"]["event_count"] == 3
    assert result["incident_id"].startswith("SOC-")


def test_graph_with_llm_produces_narrative_report(tmp_path: Path):
    """Full pipeline with a mock OpenRouter server standing in for the API.

    This exercises the exact code path a real `nvidia/nemotron-3.5-lightning:free`
    call takes: the same request body, the same JSON contract, the same
    rendering into the report.
    """
    analysis_payload = {
        "executive_summary": "A single source produced 18 failed SSH logins.",
        "severity": "High",
        "severity_rationale": "Level 12 correlation rule fired, no success observed.",
        "confidence": "High",
        "attack_narrative": "The source repeated failed passwords for 24 seconds.",
        "key_findings": ["No successful authentication followed the failures."],
        "mitre_mapping": [
            {
                "technique_id": "T1110",
                "technique_name": "Brute Force",
                "tactic": "Credential Access",
                "evidence": "rule 100002, 18 failed attempts",
            }
        ],
        "recommended_actions": [
            {"priority": "high", "action": "Block the source", "rationale": "active brute force"}
        ],
        "containment_recommendations": ["Rate-limit SSH on the target"],
        "false_positive_assessment": "Not a false positive; no successful login.",
        "data_gaps": ["Identity and EDR pillars were unavailable."],
    }
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        captured["auth"] = request.headers.get("Authorization")
        return httpx.Response(200, json=_chat_response(json.dumps(analysis_payload)))

    llm = OpenRouterClient(
        api_key="sk-or-test",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    alerts = [
        make_alert("t1", "100002", 12, "Verified SSH brute force",
                   "2026-10-21T16:52:39.293+0000", mitre=["T1110"], firedtimes=6),
    ]
    indexer = FakeIndexer(alerts)
    config = AgentConfig(
        use_llm=True,
        openrouter_api_key="sk-or-test",
        settle_seconds=0.0,
        reports_dir=tmp_path / "reports",
        state_file=tmp_path / "state.json",
        notify=False,
    )
    store = AgentState(config.state_file)
    graph = build_graph(config, indexer, llm, store)

    result = graph.invoke({"seen_ids": [], "pending": [], "errors": [],
                            "query_count": 0, "watch_cycles": 1})

    assert result["status"] == "notified"
    assert result["analysis"]["severity"] == "High"

    report = Path(result["report_path"]).read_text(encoding="utf-8")
    # the LLM narrative really landed in the Markdown
    assert "A single source produced 18 failed SSH logins." in report
    assert "**High**" in report
    assert "T1110" in report
    # the deterministic sections are still there
    assert "## 5. Incident Timeline" in report
    assert "## 11. Detection and Triage Metrics" in report
    # token accounting reached the report
    assert "Prompt tokens: 100" in report
    # the request really was an OpenRouter chat completion
    assert captured["body"]["model"] == "nvidia/nemotron-3.5-lightning:free"
    assert captured["auth"] == "Bearer sk-or-test"


def test_graph_falls_back_to_second_model(tmp_path: Path):
    """If the primary free model returns junk, the fallback still reports."""
    import agent.llm as llm_module

    captured_models = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        captured_models.append(body["model"])
        if body["model"] == "primary/junk:free":
            return httpx.Response(200, json=_chat_response("I cannot comply with JSON."))
        return httpx.Response(200, json=_chat_response(json.dumps({
            "executive_summary": "Fallback model wrote this.",
            "severity": "High",
            "severity_rationale": "Brute force detected.",
            "confidence": "Medium",
            "attack_narrative": "SSH guesses from one host.",
            "key_findings": ["18 failures"],
            "mitre_mapping": [],
            "recommended_actions": [],
            "containment_recommendations": [],
            "false_positive_assessment": "Unlikely.",
            "data_gaps": [],
        })))

    llm = OpenRouterClient(
        api_key="sk-or-test",
        model="primary/junk:free",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    alerts = [
        make_alert("fb1", "5760", 5, "sshd: authentication failed.",
                   "2026-10-21T16:52:31.283+0000"),
    ]
    indexer = FakeIndexer(alerts)
    config = AgentConfig(
        use_llm=True,
        openrouter_api_key="sk-or-test",
        openrouter_model="primary/junk:free",
        openrouter_fallback_models=("backup/good:free",),
        settle_seconds=0.0,
        reports_dir=tmp_path / "reports",
        state_file=tmp_path / "state.json",
        notify=False,
    )
    store = AgentState(config.state_file)
    graph = build_graph(config, indexer, llm, store)

    result = graph.invoke({"seen_ids": [], "pending": [], "errors": [],
                            "query_count": 0, "watch_cycles": 1})

    assert result["status"] == "notified"
    assert result["analysis"]["executive_summary"] == "Fallback model wrote this."
    assert result["metrics"]["llm_model_used"] == "backup/good:free"
    assert "backup/good:free" in captured_models
    assert "backup/good:free" in Path(result["report_path"]).read_text(encoding="utf-8")


def test_trigger_floor_keeps_low_level_context_out_of_the_queue(tmp_path: Path):
    """Level-5 noise is correlated but must not start an investigation."""
    alerts = [
        make_alert("noise1", "5503", 5, "pam_unix: authentication failure",
                   "2026-10-21T16:52:31.283+0000"),
    ]
    indexer = FakeIndexer(alerts)
    config = AgentConfig(
        use_llm=False,
        trigger_min_level=10,
        settle_seconds=0.0,
        reports_dir=tmp_path / "reports",
        state_file=tmp_path / "state.json",
        notify=False,
    )
    store = AgentState(config.state_file)
    graph = build_graph(config, indexer, None, store)

    first = graph.invoke({"seen_ids": [], "pending": [], "errors": [],
                          "query_count": 0, "watch_cycles": 1})

    assert first["status"] == "idle"
    assert first.get("report_path") is None
    assert [p["id"] for p in first["pending"]] == ["noise1"]

    # the aggregate rule lands seconds later -> now the agent investigates,
    # and the level-5 event is still in the correlation window
    alerts.append(make_alert(
        "verdict", "100002", 12, "Verified SSH brute force",
        "2026-10-21T16:52:39.293+0000",
    ))
    second = graph.invoke({**first, "watch_cycles": 2})

    assert second["status"] == "notified"
    assert second["trigger"]["id"] == "verdict"
    report = Path(second["report_path"]).read_text(encoding="utf-8")
    assert "noise1" not in report  # the id is internal, but the event is counted
    assert "5503" in report


def test_llm_budget_stops_runaway_requests():
    """A hung model must not stall the daemon past its budget."""
    import time as _time

    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        _time.sleep(0.4)
        return httpx.Response(200, json=_chat_response('{"ok": true}'))

    client = OpenRouterClient(
        api_key="sk-or-test",
        timeout=10.0,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    deadline = _time.time() + 0.25
    with pytest.raises(OpenRouterError):
        client.chat_json(
            [{"role": "user", "content": "x"}],
            model="m",
            deadline=deadline,
            timeout=10.0,
        )
    assert len(calls) <= 1


def test_graph_watch_node_finds_new_alerts(tmp_path: Path):
    alerts = [
        make_alert("new1", "5760", 5, "sshd: authentication failed.",
                   "2026-10-21T16:52:31.283+0000"),
    ]
    indexer = FakeIndexer(alerts)
    config = AgentConfig(
        use_llm=False,
        settle_seconds=0.0,
        reports_dir=tmp_path / "reports",
        state_file=tmp_path / "state.json",
        notify=False,
    )
    store = AgentState(config.state_file)
    graph = build_graph(config, indexer, None, store)

    result = graph.invoke({"seen_ids": [], "pending": [], "errors": [],
                            "query_count": 0, "watch_cycles": 1})

    # the watcher fires, the pipeline runs to completion and a report lands
    assert result["status"] == "notified"
    assert result["report_path"]
    assert "new1" in result["seen_ids"]
    assert "sshd: authentication failed" in Path(result["report_path"]).read_text(
        encoding="utf-8"
    )


def test_correlate_splits_separate_bursts():
    """Two attacks from the same source must not be reported as one long attack."""
    trigger = event_from_wazuh(make_alert(
        "t2", "100002", 12, "Verified SSH brute force", "2026-10-21T16:55:00.000+0000",
    ))
    related = [
        trigger,
        event_from_wazuh(make_alert(
            "b1", "5760", 5, "sshd: authentication failed.",
            "2026-10-21T16:54:58.000+0000",
        )),
        # a separate burst, 10 minutes later
        event_from_wazuh(make_alert(
            "c1", "5760", 5, "sshd: authentication failed.",
            "2026-10-21T17:05:00.000+0000",
        )),
    ]

    result = correlate(trigger, related,
                       datetime(2026, 10, 21, 16, 30, tzinfo=UTC),
                       datetime(2026, 10, 21, 17, 30, tzinfo=UTC))

    assert result["burst_count"] == 2
    assert result["trigger_burst_event_count"] == 2
    assert result["trigger_burst_duration_seconds"] == pytest.approx(2.0)
    # the whole-window span is much longer than the actual attack burst
    assert result["duration_seconds"] > result["trigger_burst_duration_seconds"]
    burst_flags = {e["id"]: e["in_trigger_burst"] for e in result["timeline"]}
    assert burst_flags["t2"] is True
    assert burst_flags["b1"] is True
    assert burst_flags["c1"] is False


def test_graph_settles_then_triggers_on_highest_severity(tmp_path: Path):
    """The watcher must wait for Wazuh's aggregate rules before triaging.

    A level-5 PAM failure arrives first; the level-12 "multiple failed logins"
    correlation rule only fires a few seconds later. Triggering on the first
    event would report the wrong rule, so the agent settles first.
    """
    low = make_alert("low1", "5503", 5, "pam_unix: authentication failure",
                     "2026-10-21T16:52:20.000+0000")
    high = make_alert("high1", "100002", 12, "Verified SSH brute force",
                      "2026-10-21T16:52:36.000+0000")
    indexer = FakeIndexer([low])
    config = AgentConfig(
        use_llm=False,
        settle_seconds=0.05,
        reports_dir=tmp_path / "reports",
        state_file=tmp_path / "state.json",
        notify=False,
    )
    store = AgentState(config.state_file)
    graph = build_graph(config, indexer, None, store)

    first = graph.invoke({"seen_ids": [], "pending": [], "errors": [],
                          "query_count": 0, "watch_cycles": 1})
    assert first["status"] == "settling"
    assert not first.get("trigger")
    assert first["settle_until"]
    assert first["burst_start"]

    # the correlation rule lands while the agent is settling
    indexer.alerts.append(high)
    time.sleep(0.1)

    second = graph.invoke({"seen_ids": first["seen_ids"], "pending": first["pending"],
                           "errors": [], "query_count": 0, "watch_cycles": 2,
                           "settle_until": first["settle_until"],
                           "burst_start": first["burst_start"]})

    assert second["trigger"]["id"] == "high1"
    assert second["trigger"]["level"] == 12
    assert second["status"] == "notified"
