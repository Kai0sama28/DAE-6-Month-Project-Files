"""Scoring helpers for the labeled evaluation set.

These functions are deliberately pure: they take the ground truth from an
:class:`evals.models.EvalCase` and the agent's finished investigation result,
and return a flat, auditable record. Nothing here calls the LLM, the indexer or
the database, so the same scoring can be unit-tested offline.

Definitions
-----------
``investigation_completed``
    The agent reached the report stage *and* produced an LLM narrative. A
    deterministic-only report (LLM unavailable) is recorded as not completed
    because the ATT&CK / recommendation fields cannot be attributed to the
    engine's reasoning.

``attack_correct``
    At least one predicted ATT&CK technique matches one expected technique.
    For a benign case (no expected techniques) correctness means the engine
    claimed no techniques. ``attack_exact`` additionally requires the sets to
    be equal.

``recommendation_correct``
    The action inferred from the engine's recommendations exactly matches the
    case's expected action (``monitor`` / ``investigate`` / ``escalate`` /
    ``contain``). ``recommendation_lenient`` accepts an adjacent, safe action
    (e.g. containing when escalation was expected).
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

ACTIONS: Tuple[str, ...] = ("monitor", "investigate", "escalate", "contain")

_CONTAIN_TERMS = (
    "contain",
    "isolat",
    "quarantin",
    "disable the account",
    "disable account",
    "disable the user",
    "lock the account",
    "lock the user",
    "reset the password",
    "reset password",
    "reset credentials",
    "force password reset",
    "revoke",
    "terminate",
    "kill process",
    "suspend",
)

_ESCALATE_TERMS = (
    "escalat",
    "incident response",
    "notify",
    "alert the",
    "page the",
    "forensic",
    "law enforcement",
    "engage",
    "open a case",
    "block source",
    "block the source",
    "block the ip",
    "block these",
    "firewall deny",
    "deny list",
    "blackhole",
    "null route",
    "rate limit",
    "fail2ban",
    "sshguard",
    "threat intel",
    "share ioc",
)

_INVESTIGATE_TERMS = (
    "investigat",
    "verify",
    "validate",
    "review",
    "collect",
    "analys",
    "analyze",
    "audit",
    "corroborat",
    "interview",
)

_MONITOR_TERMS = (
    "monitor",
    "watch",
    "no action",
    "close the alert",
    "close as",
    "no further",
    "continue to",
)

_BENIGN_TERMS = (
    "false positive",
    "benign",
    "no malicious",
    "no evidence of compromise",
    "authorized",
    "authorised",
    "expected activity",
    "not malicious",
    "no indication of",
)

_TECHNIQUE_RE = re.compile(r"T\d{4}(?:\.\d{3})?", re.IGNORECASE)


def normalize_techniques(values: Optional[Iterable[Any]]) -> List[str]:
    """Return sorted, de-duplicated, upper-case ATT&CK technique ids."""
    found: Set[str] = set()
    for value in values or []:
        if value is None:
            continue
        for match in _TECHNIQUE_RE.findall(str(value)):
            found.add(match.upper())
    return sorted(found)


def predicted_techniques(analysis: Optional[Dict[str, Any]]) -> List[str]:
    """Extract technique ids from an LLM ``mitre_mapping`` block."""
    analysis = analysis or {}
    raw: List[Any] = []
    for row in analysis.get("mitre_mapping") or []:
        if isinstance(row, dict):
            raw.append(row.get("technique_id"))
        else:
            raw.append(row)
    return normalize_techniques(raw)


def _recommendation_text(analysis: Dict[str, Any]) -> str:
    chunks: List[str] = []
    for row in analysis.get("recommended_actions") or []:
        if isinstance(row, dict):
            chunks.extend(
                str(row.get(key) or "")
                for key in ("action", "rationale", "priority")
            )
        else:
            chunks.append(str(row))
    chunks.extend(str(item) for item in analysis.get("containment_recommendations") or [])
    return " ".join(chunks).lower()


_NEGATED_BENIGN_RE = re.compile(
    r"(?:not|isn't|is not|unlikely to be|no evidence of|low probability of|"
    r"low likelihood of|not necessarily)\s+(?:a\s+|an\s+)?"
    r"(?:false positive|benign|malicious|compromise)",
    re.IGNORECASE,
)


def looks_benign(analysis: Optional[Dict[str, Any]]) -> bool:
    """True when the narrative explicitly assesses the activity as benign."""
    analysis = analysis or {}
    assessment = str(analysis.get("false_positive_assessment") or "").lower()
    assessment = _NEGATED_BENIGN_RE.sub("", assessment)
    if any(term in assessment for term in _BENIGN_TERMS):
        return True
    severity = str(analysis.get("severity") or "").strip().lower()
    text = _recommendation_text(analysis)
    if severity in ("informational", "low") and any(
        term in text for term in _MONITOR_TERMS
    ) and not any(term in text for term in _CONTAIN_TERMS):
        return True
    return False


def infer_recommended_action(analysis: Optional[Dict[str, Any]]) -> str:
    """Map free-text recommendations onto the four expected action classes.

    Precedence is intentional: a benign assessment maps to ``monitor``; an
    explicit containment instruction maps to ``contain``; otherwise escalate,
    investigate and monitor keywords are checked in that order. If no keyword
    matches, severity provides a final conservative default.
    """
    analysis = analysis or {}
    explicit = str(analysis.get("recommended_action") or "").strip().lower()
    if explicit in ACTIONS:
        return explicit
    if looks_benign(analysis):
        return "monitor"

    text = _recommendation_text(analysis)
    if any(term in text for term in _CONTAIN_TERMS):
        return "contain"
    if any(term in text for term in _ESCALATE_TERMS):
        return "escalate"
    if any(term in text for term in _INVESTIGATE_TERMS):
        return "investigate"
    if any(term in text for term in _MONITOR_TERMS):
        return "monitor"

    severity = str(analysis.get("severity") or "").strip().lower()
    if severity in ("critical", "high"):
        return "escalate"
    if severity == "medium":
        return "investigate"
    return "monitor"


def infer_verdict(analysis: Optional[Dict[str, Any]]) -> str:
    """Coarse verdict derived from the narrative's false-positive assessment."""
    analysis = analysis or {}
    if looks_benign(analysis):
        return "benign"
    text = " ".join(
        [
            str(analysis.get("false_positive_assessment") or ""),
            _recommendation_text(analysis),
        ]
    ).lower()
    if "false positive" in text:
        return "false_positive"
    return "true_positive"


def _attack_score(
    predicted: Sequence[str],
    expected: Sequence[str],
) -> Dict[str, Any]:
    pred = set(predicted)
    exp = set(expected)
    if exp:
        matched = sorted(pred & exp)
        correct = bool(matched)
        exact = pred == exp
    else:
        matched = []
        correct = len(pred) == 0
        exact = len(pred) == 0
    return {
        "predicted": sorted(pred),
        "expected": sorted(exp),
        "matched": matched,
        "missed": sorted(exp - pred),
        "extra": sorted(pred - exp),
        "correct": correct,
        "exact": exact,
    }


def _recommendation_score(predicted: str, expected: str) -> Dict[str, Any]:
    accepted: Dict[str, Set[str]] = {
        "monitor": {"monitor", "investigate"},
        "investigate": {"investigate", "monitor", "escalate"},
        "escalate": {"escalate", "contain", "investigate"},
        "contain": {"contain", "escalate"},
    }
    return {
        "predicted": predicted,
        "expected": expected,
        "correct": predicted == expected,
        "lenient": predicted in accepted.get(expected, {expected}),
    }


def evaluate_result(
    case: Any,
    result: Optional[Dict[str, Any]],
    processing_seconds: float,
    *,
    analysis_source: str = "llm",
) -> Dict[str, Any]:
    """Build one flat evaluation record for a finished investigation.

    ``case`` is an :class:`evals.models.EvalCase`; ``result`` is the LangGraph
    state returned by ``graph.invoke`` (or ``None`` if the run crashed).
    """
    result = result or {}
    analysis = result.get("analysis") or {}
    correlation = result.get("correlation") or {}
    metrics = result.get("metrics") or {}
    report_path = result.get("report_path") or ""

    investigation_completed = bool(analysis) and bool(report_path)
    report_produced = bool(report_path)
    scorable = bool(analysis) or analysis_source == "deterministic"

    if analysis:
        analysis_source_label = analysis_source
        predicted_mitre = predicted_techniques(analysis)
        action = infer_recommended_action(analysis)
        verdict = infer_verdict(analysis)
    elif analysis_source == "deterministic":
        analysis_source_label = "deterministic"
        predicted_mitre = normalize_techniques(correlation.get("mitre_ids") or [])
        action = _deterministic_action(correlation)
        verdict = "benign" if action == "monitor" else "true_positive"
    else:
        analysis_source_label = "none"
        predicted_mitre = []
        action = "unknown"
        verdict = "unknown"

    if scorable:
        attack = _attack_score(predicted_mitre, case.expected_mitre)
        recommendation = _recommendation_score(action, case.expected_action)
    else:
        attack = {
            "predicted": [], "expected": sorted(case.expected_mitre),
            "matched": [], "missed": sorted(case.expected_mitre), "extra": [],
            "correct": False, "exact": False,
        }
        recommendation = {
            "predicted": "unknown", "expected": case.expected_action,
            "correct": False, "lenient": False,
        }

    attempts = metrics.get("llm_attempts") or []
    llm_seconds = round(
        sum(float(row.get("seconds") or 0) for row in attempts if isinstance(row, dict)),
        3,
    )

    return {
        "case_id": case.case_id,
        "dataset_id": case.dataset_id,
        "label": case.label,
        "scenario": case.scenario,
        "difficulty": case.difficulty,
        "expected_severity": case.expected_severity,
        "expected_verdict": case.expected_verdict,
        "expected_action": case.expected_action,
        "expected_mitre": list(case.expected_mitre),
        "investigation_completed": investigation_completed,
        "report_produced": report_produced,
        "analysis_source": analysis_source_label,
        "scorable": scorable,
        "status": result.get("status") or "",
        "predicted_verdict": verdict,
        "predicted_action": recommendation["predicted"],
        "recommendation_correct": recommendation["correct"],
        "recommendation_lenient": recommendation["lenient"],
        "predicted_mitre": attack["predicted"],
        "attack_correct": attack["correct"],
        "attack_exact": attack["exact"],
        "attack_matched": attack["matched"],
        "attack_missed": attack["missed"],
        "attack_extra": attack["extra"],
        "llm_severity": analysis.get("severity") or "",
        "llm_confidence": analysis.get("confidence") or "",
        "llm_model_used": metrics.get("llm_model_used") or "",
        "llm_attempts": attempts,
        "processing_seconds": round(float(processing_seconds), 3),
        "llm_seconds": llm_seconds,
        "engine_triage_seconds": round(float(metrics.get("triage_seconds") or 0.0), 3),
        "correlated_events": int(correlation.get("event_count") or 0),
        "errors": list(result.get("errors") or []),
        "report_path": report_path,
        "analysis": analysis,
        "correlation_summary": {
            "event_count": correlation.get("event_count"),
            "flags": correlation.get("flags") or {},
            "mitre_ids": correlation.get("mitre_ids") or [],
            "rule_counts": correlation.get("rule_counts") or [],
        },
    }


def _deterministic_action(correlation: Dict[str, Any]) -> str:
    """Best-effort action from correlation facts (used only without an LLM)."""
    flags = correlation.get("flags") or {}
    if (
        flags.get("file_integrity_change_observed")
        or flags.get("privilege_change_observed")
        or (flags.get("auth_success_observed") and flags.get("auth_failures_observed"))
    ):
        return "contain"
    if flags.get("auth_failures_observed"):
        return "escalate"
    return "monitor"


def summarize(records: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate per-case records into headline metrics and time statistics."""
    total = len(records)
    if not total:
        return {"total": 0, "by_label": {}, "times": {}}

    def rate(key: str) -> float:
        return round(100.0 * sum(1 for r in records if r.get(key)) / total, 1)

    times_all = sorted(float(r.get("processing_seconds") or 0.0) for r in records)
    times = sorted(
        float(r.get("processing_seconds") or 0.0)
        for r in records
        if r.get("investigation_completed")
    )

    def time_block(values: Sequence[float]) -> Dict[str, Any]:
        if not values:
            return {"count": 0}
        ordered = sorted(values)
        n = len(ordered)
        p95_index = min(n - 1, int(round(0.95 * (n - 1))))
        return {
            "count": n,
            "total_seconds": round(sum(ordered), 3),
            "mean_seconds": round(sum(ordered) / n, 3),
            "median_seconds": round(ordered[n // 2], 3),
            "min_seconds": round(ordered[0], 3),
            "max_seconds": round(ordered[-1], 3),
            "p95_seconds": round(ordered[p95_index], 3),
        }

    by_label: Dict[str, Dict[str, Any]] = {}
    for label in sorted({r.get("label") for r in records}):
        subset = [r for r in records if r.get("label") == label]
        n = len(subset)
        by_label[label] = {
            "cases": n,
            "completed": sum(1 for r in subset if r.get("investigation_completed")),
            "attack_correct": sum(1 for r in subset if r.get("attack_correct")),
            "attack_exact": sum(1 for r in subset if r.get("attack_exact")),
            "recommendation_correct": sum(
                1 for r in subset if r.get("recommendation_correct")
            ),
            "recommendation_lenient": sum(
                1 for r in subset if r.get("recommendation_lenient")
            ),
            "completion_rate_pct": round(
                100.0 * sum(1 for r in subset if r.get("investigation_completed")) / n, 1
            ),
            "attack_accuracy_pct": round(
                100.0 * sum(1 for r in subset if r.get("attack_correct")) / n, 1
            ),
            "recommendation_accuracy_pct": round(
                100.0 * sum(1 for r in subset if r.get("recommendation_correct")) / n, 1
            ),
            "times": time_block([
                float(r.get("processing_seconds") or 0.0)
                for r in subset if r.get("investigation_completed")
            ]),
            "times_all": time_block([
                float(r.get("processing_seconds") or 0.0) for r in subset
            ]),
        }

    expected_actions = sorted({r.get("expected_action") for r in records})
    predicted_actions = sorted({r.get("predicted_action") for r in records})
    confusion = {
        expected: {
            predicted: sum(
                1
                for r in records
                if r.get("expected_action") == expected
                and r.get("predicted_action") == predicted
            )
            for predicted in predicted_actions
        }
        for expected in expected_actions
    }

    return {
        "total": total,
        "completed": sum(1 for r in records if r.get("investigation_completed")),
        "completion_rate_pct": rate("investigation_completed"),
        "attack_correct": sum(1 for r in records if r.get("attack_correct")),
        "attack_accuracy_pct": rate("attack_correct"),
        "attack_exact": sum(1 for r in records if r.get("attack_exact")),
        "attack_exact_pct": rate("attack_exact"),
        "recommendation_correct": sum(
            1 for r in records if r.get("recommendation_correct")
        ),
        "recommendation_accuracy_pct": rate("recommendation_correct"),
        "recommendation_lenient": sum(
            1 for r in records if r.get("recommendation_lenient")
        ),
        "recommendation_lenient_pct": rate("recommendation_lenient"),
        "times": time_block(times),
        "times_all": time_block(times_all),
        "by_label": by_label,
        "confusion": confusion,
    }
