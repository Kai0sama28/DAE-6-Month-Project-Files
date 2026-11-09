from pathlib import Path

from frontend.report_parser import (
    aggregate,
    load_case,
    load_cases,
    parse_markdown,
    parse_report,
)

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "ai-agentic-soc" / "reports"
SAMPLE = REPORTS / "SOC-20261028-012.md"


def test_parse_real_report_extracts_core_fields():
    report = parse_report(SAMPLE)

    assert report["incident_id"] == "SOC-20261028-012"
    assert report["severity"] == "Medium"
    assert report["severity_rank"] == 2
    assert report["confidence"] == "Medium"
    assert report["affected_host"].startswith("Kali")
    assert report["detection_rule"].startswith("100032")
    assert report["timeline_count"] == 7
    assert report["attack_events"] == 7
    assert report["phase_counts"]["INTEGRITY"] == 7
    assert "T1098.004" in report["mitre_techniques"]
    assert report["detection_facts"]["Rule"].startswith("100032")
    assert report["recommendations"]
    assert report["markdown"].startswith("# Incident Report")


def test_parse_markdown_without_a_file():
    markdown = SAMPLE.read_text(encoding="utf-8")
    report = parse_markdown(markdown, incident_id_hint="SOC-20261028-012")

    assert report["incident_id"] == "SOC-20261028-012"
    assert report["report_path"] is None
    assert report["report_html_path"] is None
    assert report["timeline"]


def test_load_cases_merges_decisions():
    decision = {
        "incident_id": "SOC-20261028-012",
        "decision": "approved",
        "analyst": "kai",
        "note": "verified",
        "decided_at": "2026-11-06T00:00:00+00:00",
    }
    cases = load_cases(REPORTS, {"SOC-20261028-012": decision})

    assert len(cases) >= 10
    selected = next(case for case in cases if case["incident_id"] == "SOC-20261028-012")
    assert selected["decision"]["decision"] == "approved"
    assert selected["decision"]["analyst"] == "kai"


def test_load_case_rejects_bad_ids():
    assert load_case(REPORTS, "../etc/passwd") is None
    assert load_case(REPORTS, "SOC-00000000-000") is None


def test_aggregate_counts_mitre_and_severity():
    cases = load_cases(REPORTS)
    summary = aggregate(cases)

    assert summary["total"] == len(cases)
    assert summary["by_severity"]
    assert summary["by_decision"]["pending"] == len(cases)
    assert summary["by_tactic"]
    assert summary["correlated_events"] >= 0
