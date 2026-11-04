from __future__ import annotations

from typing import Any, Dict, List, Optional

import pytest

from agent.config import AgentConfig
from evals import run_eval
from evals.generator import DEFAULT_SEED, generate_dataset
from evals.scoring import (
    _attack_score,
    evaluate_result,
    infer_recommended_action,
    infer_verdict,
    normalize_techniques,
    predicted_techniques,
    summarize,
)


def _case(label: str = "brute_force"):
    dataset = generate_dataset(seed=DEFAULT_SEED, dataset_id="soc-eval-pytest-runner")
    for case in dataset:
        if case.label == label:
            return case
    raise AssertionError(f"no case with label {label}")


class FakeLLM:
    """Returns a schema-shaped analysis without touching the network."""

    model = "fake/model"

    def __init__(self, analysis: Dict[str, Any]) -> None:
        self._analysis = analysis
        self.last_usage = {"prompt_tokens": 10, "completion_tokens": 20}

    def chat_json(
        self,
        messages,
        system: Optional[str] = None,
        model: Optional[str] = None,
        timeout: Optional[float] = None,
        deadline: Optional[float] = None,
    ) -> Dict[str, Any]:
        return dict(self._analysis)


def _analysis_for(case) -> Dict[str, Any]:
    if case.expected_action == "contain":
        actions = [{"priority": "High", "action": "Isolate the host and disable the account", "rationale": "x"}]
        assessment = "Confirmed malicious activity."
    elif case.expected_action == "escalate":
        actions = [{"priority": "High", "action": "Escalate to tier 2 for investigation", "rationale": "x"}]
        assessment = "Suspicious activity requiring escalation."
    else:
        actions = [{"priority": "Low", "action": "Monitor and close the alert", "rationale": "x"}]
        assessment = "No evidence of compromise; activity appears benign."
    return {
        "executive_summary": "summary",
        "severity": case.expected_severity.title(),
        "severity_rationale": "rationale",
        "confidence": "High",
        "recommended_action": case.expected_action,
        "attack_narrative": "narrative",
        "key_findings": ["finding"],
        "mitre_mapping": [
            {"technique_id": technique, "technique_name": "n", "tactic": "t", "evidence": "e"}
            for technique in case.expected_mitre
        ],
        "recommended_actions": actions,
        "containment_recommendations": [],
        "false_positive_assessment": assessment,
        "data_gaps": [],
    }


def test_normalize_techniques():
    assert normalize_techniques(["T1110.004", "t1110.004", "T1566"]) == [
        "T1110.004",
        "T1566",
    ]
    assert predicted_techniques({"mitre_mapping": [{"technique_id": "T1078"}]}) == ["T1078"]


def test_attack_scoring_handles_benign_and_partial_matches():
    assert _attack_score(["T1110.004"], ["T1110.004"])["correct"] is True
    assert _attack_score(["T1110.001"], ["T1110.004"])["correct"] is False
    assert _attack_score([], [])["correct"] is True
    assert _attack_score(["T1490"], [])["correct"] is False
    assert _attack_score(["T1110.004", "T1078"], ["T1110.004"])["exact"] is False


def test_recommendation_inference():
    contain = {"recommended_actions": [
        {"action": "Quarantine the endpoint and reset credentials", "rationale": ""}
    ]}
    escalate = {"recommended_actions": [
        {"action": "Escalate to the incident response team", "rationale": ""}
    ]}
    benign = {
        "severity": "Low",
        "false_positive_assessment": "No evidence of compromise; activity is benign.",
        "recommended_actions": [{"action": "Monitor the alert", "rationale": ""}],
    }
    assert infer_recommended_action(contain) == "contain"
    assert infer_recommended_action(escalate) == "escalate"
    assert infer_recommended_action(benign) == "monitor"
    assert infer_verdict(benign) == "benign"
    # An explicit engine classification wins over free-text heuristics.
    assert infer_recommended_action({
        "recommended_action": "escalate",
        "recommended_actions": [{"action": "Isolate the host", "rationale": ""}],
    }) == "escalate"
    # Blocking an external source is escalation, not host containment.
    assert infer_recommended_action({
        "false_positive_assessment": "Unlikely to be a false positive.",
        "recommended_actions": [{"action": "Block the source IPs", "rationale": ""}],
    }) == "escalate"


def test_case_indexer_returns_bundle_within_window():
    case = _case()
    indexer = run_eval.CaseIndexer(case.alerts)
    trigger = case.trigger_alert()
    assert indexer.ping() is True
    assert indexer.get_alert(trigger.id) is trigger
    assert indexer.get_alert("missing") is None
    returned = indexer.query_alerts(since="2000-01-01T00:00:00Z", limit=100)
    assert {alert.id for alert in returned} == {alert.id for alert in case.alerts}
    assert indexer.query_alerts(since="2999-01-01T00:00:00Z") == []


def test_run_case_scores_against_ground_truth(tmp_path, monkeypatch):
    case = _case("brute_force")
    monkeypatch.setattr(run_eval, "_make_llm", lambda config: FakeLLM(_analysis_for(case)))

    config = AgentConfig.from_env(load_dotenv_file=False)
    config.openrouter_api_key = "test-key"
    config.use_llm = True

    record = run_eval.run_case(
        case,
        trigger_alert=case.trigger_alert(),
        base_config=config,
        reports_dir=tmp_path / "reports",
        state_dir=tmp_path / "state",
        use_llm=True,
        run_key=case.case_id,
    )

    assert record["investigation_completed"] is True
    assert record["report_produced"] is True
    assert record["attack_correct"] is True
    assert record["recommendation_correct"] is True
    assert record["predicted_action"] == case.expected_action
    assert set(record["expected_mitre"]).issubset(set(record["predicted_mitre"]))
    assert record["processing_seconds"] >= 0.0
    assert record["correlated_events"] == len(case.alerts)


def test_evaluate_result_marks_missing_narrative_incomplete():
    case = _case("phishing")
    record = evaluate_result(case, {"report_path": "x.md"}, 1.5, analysis_source="llm")
    assert record["investigation_completed"] is False
    assert record["report_produced"] is True
    assert record["analysis_source"] == "none"
    assert record["scorable"] is False
    assert record["attack_correct"] is False
    assert record["recommendation_correct"] is False
    assert record["predicted_action"] == "unknown"


def test_summarize_reports_rates_and_times():
    case = _case()
    good = evaluate_result(case, {
        "analysis": _analysis_for(case),
        "report_path": "x.md",
        "correlation": {"event_count": 3, "flags": {}},
        "metrics": {},
        "status": "report_ready",
    }, 2.0)
    bad = dict(good)
    bad.update({"attack_correct": False, "recommendation_correct": False, "processing_seconds": 4.0})
    summary = summarize([good, bad])
    assert summary["total"] == 2
    assert summary["completed"] == 2
    assert summary["attack_accuracy_pct"] == 50.0
    assert summary["times"]["mean_seconds"] == 3.0
    assert summary["times"]["max_seconds"] == 4.0
