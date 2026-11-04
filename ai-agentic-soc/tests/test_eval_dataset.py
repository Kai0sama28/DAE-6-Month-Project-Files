from __future__ import annotations

import json
from collections import Counter

import pytest
from sqlalchemy import delete, select, text

from evals import (
    CASES_PER_LABEL,
    LABELS,
    create_eval_engine,
    dataset_summary,
    generate_dataset,
    label_counts,
    load_cases,
    read_jsonl,
    validate_dataset,
    write_jsonl,
)
from evals.generator import DEFAULT_SEED
from evals.store import alerts as alerts_table
from evals.store import cases as cases_table
from evals.store import datasets as datasets_table
from evals.taxonomy import ACTIONS, DIFFICULTIES, SEVERITIES, VERDICTS

TEST_DATASET_ID = "soc-eval-pytest"


@pytest.fixture(scope="module")
def dataset():
    return generate_dataset(seed=DEFAULT_SEED, dataset_id=TEST_DATASET_ID)


def test_dataset_has_fifty_cases_ten_per_label(dataset):
    assert len(dataset) == 50
    counts = Counter(case.label for case in dataset)
    assert counts == Counter({label: CASES_PER_LABEL for label in LABELS})
    assert sum(1 for case in dataset if case.is_malicious) == 40
    assert sum(1 for case in dataset if not case.is_malicious) == 10
    assert validate_dataset(dataset)["alert_count"] == sum(
        len(case.alerts) for case in dataset
    )


def test_every_case_is_a_well_formed_incident_bundle(dataset):
    seen_ids = set()
    for case in dataset:
        assert case.case_id not in seen_ids
        seen_ids.add(case.case_id)
        assert case.case_id.startswith("EVAL-")
        assert 1 <= len(case.alerts) <= 8
        assert case.alert_count == len(case.alerts)
        assert case.expected_severity in SEVERITIES
        assert case.expected_verdict in VERDICTS
        assert case.expected_action in ACTIONS
        assert case.difficulty in DIFFICULTIES
        assert case.identity.profiles
        assert case.edr.endpoints
        assert case.siem.correlated_alert_count == len(case.alerts)
        assert case.siem.trigger_rule_id
        assert case.siem.trigger_level > 0

        local_ids = [alert.id for alert in case.alerts]
        assert len(local_ids) == len(set(local_ids))
        trigger = case.trigger_alert()
        assert trigger is not None
        assert trigger.id == case.trigger_alert_id
        highest = max(alert.rule.level for alert in case.alerts if alert.rule)
        assert trigger.rule.level == highest


def test_labels_match_expected_triage_outcome(dataset):
    for case in dataset:
        if case.label == "benign":
            assert case.is_malicious is False
            assert case.expected_verdict in ("benign", "false_positive")
            assert case.expected_action == "monitor"
            assert case.expected_mitre == []
        else:
            assert case.is_malicious is True
            assert case.expected_verdict == "true_positive"
            assert case.expected_action in ("escalate", "contain")
        assert case.expected_severity in SEVERITIES


def test_generated_prose_does_not_leak_the_label(dataset):
    for case in dataset:
        prose = f"{case.title} {case.summary}".lower()
        for forbidden in (
            "credential stuffing", "credential-stuffing", "brute force",
            "brute-force", "phishing", "ransomware", "benign", "malicious",
            "ground truth", "false positive", "true positive",
        ):
            assert forbidden not in prose, f"{case.case_id} leaks {forbidden!r}"


def test_generation_is_deterministic():
    first = generate_dataset(seed=1234, dataset_id="determinism-check")
    second = generate_dataset(seed=1234, dataset_id="determinism-check")
    assert [c.model_dump(mode="json") for c in first] == [
        c.model_dump(mode="json") for c in second
    ]


def test_jsonl_roundtrip(dataset, tmp_path):
    path = write_jsonl(dataset, tmp_path / "eval.jsonl")
    loaded = read_jsonl(path)
    assert len(loaded) == len(dataset)
    assert [c.model_dump(mode="json") for c in loaded] == [
        c.model_dump(mode="json") for c in dataset
    ]
    # One JSON object per line.
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 50
    assert json.loads(lines[0])["case_id"] == dataset[0].case_id


def _postgres_engine_or_skip():
    pytest.importorskip("psycopg2")
    try:
        engine = create_eval_engine()
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return engine
    except Exception as exc:  # pragma: no cover - depends on local environment
        pytest.skip(f"PostgreSQL not available: {exc}")


def _cleanup(engine, dataset_id: str) -> None:
    with engine.begin() as conn:
        conn.execute(delete(alerts_table).where(alerts_table.c.dataset_id == dataset_id))
        conn.execute(delete(cases_table).where(cases_table.c.dataset_id == dataset_id))
        conn.execute(delete(datasets_table).where(datasets_table.c.dataset_id == dataset_id))


def test_postgres_stores_ground_truth_labels(dataset):
    engine = _postgres_engine_or_skip()
    try:
        counts = load_cases(
            dataset,
            engine=engine,
            dataset_id=TEST_DATASET_ID,
            seed=DEFAULT_SEED,
            split="test",
        )
        assert counts == {
            "datasets": 1,
            "cases": 50,
            "alerts": sum(len(case.alerts) for case in dataset),
        }

        summary = dataset_summary(engine, TEST_DATASET_ID)
        assert summary["cases"] == 50
        assert summary["alerts"] == counts["alerts"]
        assert summary["label_counts"] == {
            label: CASES_PER_LABEL for label in sorted(LABELS)
        }

        stored = label_counts(engine, TEST_DATASET_ID)
        assert stored == {label: CASES_PER_LABEL for label in sorted(LABELS)}

        # Every alert row carries the same label as its parent case.
        with engine.connect() as conn:
            mismatch = conn.execute(
                select(alerts_table.c.case_id)
                .join(
                    cases_table,
                    (alerts_table.c.dataset_id == cases_table.c.dataset_id)
                    & (alerts_table.c.case_id == cases_table.c.case_id),
                )
                .where(
                    cases_table.c.dataset_id == TEST_DATASET_ID,
                    alerts_table.c.label != cases_table.c.label,
                )
            ).all()
        assert mismatch == []
    finally:
        _cleanup(engine, TEST_DATASET_ID)
