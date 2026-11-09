from pathlib import Path

import pytest

from frontend.backends import BackendError, LocalBackend

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "ai-agentic-soc" / "reports"


def _backend(tmp_path: Path) -> LocalBackend:
    return LocalBackend(REPORTS, tmp_path / "decisions.json")


def test_local_backend_reads_reports(tmp_path):
    backend = _backend(tmp_path)

    health = backend.health()
    assert health["mode"] == "local"
    assert health["case_count"] >= 10

    cases = backend.list_cases()
    assert cases
    assert all(case["incident_id"].startswith("SOC-") for case in cases)

    case = backend.get_case("SOC-20261028-012")
    assert case is not None
    assert case["severity"] == "Medium"
    assert case["timeline"]


def test_local_backend_records_and_persists_decision(tmp_path):
    backend = _backend(tmp_path)

    record = backend.record_decision(
        "SOC-20261028-012", "approved", "kai", "validated in the lab"
    )
    assert record["decision"] == "approved"
    assert record["analyst"] == "kai"

    reloaded = _backend(tmp_path)
    case = reloaded.get_case("SOC-20261028-012")
    assert case["decision"]["decision"] == "approved"
    assert case["decision"]["note"] == "validated in the lab"


def test_local_backend_rejects_invalid_decisions(tmp_path):
    backend = _backend(tmp_path)

    with pytest.raises(BackendError):
        backend.record_decision("SOC-20261028-012", "maybe", "kai", "")

    with pytest.raises(BackendError):
        backend.record_decision("SOC-00000000-000", "approved", "kai", "")


def test_local_backend_serves_markdown_and_html(tmp_path):
    backend = _backend(tmp_path)

    markdown = backend.get_report("SOC-20261028-012", "markdown")
    html = backend.get_report("SOC-20261028-012", "html")
    assert markdown and markdown.startswith("# Incident Report")
    assert html and "<!DOCTYPE html>" in html


def test_local_backend_cannot_queue_investigations(tmp_path):
    backend = _backend(tmp_path)

    with pytest.raises(BackendError):
        backend.submit_investigation("1792695015.328031")


def test_local_backend_metrics(tmp_path):
    backend = _backend(tmp_path)
    metrics = backend.metrics()

    assert metrics["mode"] == "local"
    assert metrics["total"] >= 10
    assert metrics["jobs"]["queued"] == 0
