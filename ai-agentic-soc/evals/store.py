"""Persistence for the labeled evaluation dataset.

Ground truth lives in PostgreSQL under a dedicated ``eval`` schema so it can
never be confused with the operational ``investigations`` table or with the
live Wazuh indexes. The same cases are also written as JSONL for diffing and
for consumption by evaluation harnesses that do not talk to Postgres.

Tables (schema ``eval``)::

    eval.datasets   one row per generated dataset (seed, case count, split)
    eval.cases      one row per incident bundle, including the label
    eval.alerts     one row per Wazuh-shaped alert document

``eval.cases.label`` is the ground truth. It is written by the generator and
is never updated by an agent.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKeyConstraint,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    create_engine,
    delete,
    func,
    insert,
    select,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.engine import Engine

from evals.generator import DEFAULT_DATASET_ID, DEFAULT_SEED
from evals.models import EvalCase

EVAL_SCHEMA = "eval"
DEFAULT_EVAL_DATABASE_URL = os.environ.get(
    "EVAL_DATABASE_URL", "postgresql+psycopg2:///soc_triage_db"
)

metadata = MetaData(schema=EVAL_SCHEMA)

datasets = Table(
    "datasets",
    metadata,
    Column("dataset_id", String(64), primary_key=True),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("seed", Integer, nullable=False),
    Column("case_count", Integer, nullable=False),
    Column("split", String(16), nullable=False, server_default="test"),
    Column("meta", JSONB, nullable=False, server_default=text("'{}'::jsonb")),
)

cases = Table(
    "cases",
    metadata,
    Column("dataset_id", String(64), primary_key=True),
    Column("case_id", String(64), primary_key=True),
    ForeignKeyConstraint(
        ["dataset_id"],
        [f"{EVAL_SCHEMA}.datasets.dataset_id"],
        ondelete="CASCADE",
    ),
    Column("case_index", Integer, nullable=False),
    Column("label", String(64), nullable=False, index=True),
    Column("is_malicious", Boolean, nullable=False),
    Column("expected_severity", String(16), nullable=False),
    Column("expected_verdict", String(32), nullable=False),
    Column("expected_action", String(16), nullable=False),
    Column("expected_mitre", JSONB, nullable=False),
    Column("difficulty", String(16), nullable=False),
    Column("scenario", String(96), nullable=False),
    Column("title", Text, nullable=False),
    Column("summary", Text, nullable=False),
    Column("trigger_alert_id", String(128), nullable=False),
    Column("alert_count", Integer, nullable=False),
    Column("split", String(16), nullable=False, server_default="test"),
    Column("notes", Text, nullable=False, server_default=""),
    Column("identity", JSONB, nullable=False),
    Column("edr", JSONB, nullable=False),
    Column("siem", JSONB, nullable=False),
)

alerts = Table(
    "alerts",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("dataset_id", String(64), nullable=False, index=True),
    Column("case_id", String(64), nullable=False, index=True),
    ForeignKeyConstraint(
        ["dataset_id", "case_id"],
        [f"{EVAL_SCHEMA}.cases.dataset_id", f"{EVAL_SCHEMA}.cases.case_id"],
        ondelete="CASCADE",
    ),
    Column("alert_index", Integer, nullable=False),
    Column("alert_id", String(128), nullable=False),
    Column("label", String(64), nullable=False, index=True),
    Column("timestamp_utc", String(40), nullable=False),
    Column("rule_id", String(16), nullable=False),
    Column("rule_level", Integer, nullable=False),
    Column("rule_description", Text, nullable=False),
    Column("rule_groups", JSONB, nullable=False),
    Column("agent_id", String(16), nullable=False),
    Column("agent_name", String(64), nullable=False),
    Column("agent_ip", String(64), nullable=False),
    Column("src_ip", String(64), nullable=False, server_default=""),
    Column("dst_user", String(64), nullable=False, server_default=""),
    Column("document", JSONB, nullable=False),
)


def create_eval_engine(database_url: Optional[str] = None) -> Engine:
    """Create an engine for the eval database (PostgreSQL by default)."""
    url = database_url or DEFAULT_EVAL_DATABASE_URL
    return create_engine(url, future=True, pool_pre_ping=True)


def init_schema(engine: Engine) -> None:
    """Create the ``eval`` schema and its tables if they do not exist."""
    with engine.begin() as conn:
        conn.execute(text(f'CREATE SCHEMA IF NOT EXISTS "{EVAL_SCHEMA}"'))
        metadata.create_all(conn)


def _case_row(case: EvalCase, split: str, dataset_id: str) -> Dict[str, Any]:
    return {
        "case_id": case.case_id,
        "dataset_id": dataset_id,
        "case_index": case.case_index,
        "label": case.label,
        "is_malicious": case.is_malicious,
        "expected_severity": case.expected_severity,
        "expected_verdict": case.expected_verdict,
        "expected_action": case.expected_action,
        "expected_mitre": case.expected_mitre,
        "difficulty": case.difficulty,
        "scenario": case.scenario,
        "title": case.title,
        "summary": case.summary,
        "trigger_alert_id": case.trigger_alert_id,
        "alert_count": case.alert_count,
        "split": split,
        "notes": case.notes,
        "identity": case.identity.model_dump(mode="json"),
        "edr": case.edr.model_dump(mode="json"),
        "siem": case.siem.model_dump(mode="json"),
    }


def _alert_rows(case: EvalCase, dataset_id: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for index, alert in enumerate(case.alerts, start=1):
        data = alert.data or {}
        src_ip = str(data.get("srcip") or "")
        dst_user = str(data.get("dstuser") or "")
        if isinstance(data.get("win"), dict):
            eventdata = data["win"].get("eventdata") or {}
            src_ip = src_ip or str(eventdata.get("ipAddress") or "")
            dst_user = dst_user or str(eventdata.get("targetUserName") or "")
        rule = alert.rule
        agent = alert.agent
        rows.append({
            "dataset_id": dataset_id,
            "case_id": case.case_id,
            "alert_index": index,
            "alert_id": str(alert.id or ""),
            "label": case.label,
            "timestamp_utc": str(alert.timestamp or ""),
            "rule_id": str(rule.id if rule else ""),
            "rule_level": int(rule.level if rule else 0),
            "rule_description": str(rule.description if rule else ""),
            "rule_groups": list(rule.groups) if rule else [],
            "agent_id": str(agent.id if agent else ""),
            "agent_name": str(agent.name if agent else ""),
            "agent_ip": str(agent.ip if agent else ""),
            "src_ip": src_ip,
            "dst_user": dst_user,
            "document": alert.model_dump(mode="json"),
        })
    return rows


def load_cases(
    case_list: Sequence[EvalCase],
    engine: Optional[Engine] = None,
    *,
    dataset_id: Optional[str] = None,
    seed: int = DEFAULT_SEED,
    split: str = "test",
    replace: bool = True,
) -> Dict[str, int]:
    """Load cases into ``eval.datasets`` / ``eval.cases`` / ``eval.alerts``.

    ``replace=True`` removes any previous rows for the same ``dataset_id`` so
    re-running the generator is idempotent. Labels are written as supplied by
    the generator; this function never derives or edits them.
    """
    if not case_list:
        raise ValueError("refusing to load an empty dataset")

    engine = engine or create_eval_engine()
    dataset_id = dataset_id or case_list[0].dataset_id or DEFAULT_DATASET_ID
    init_schema(engine)

    case_rows = [_case_row(case, split, dataset_id) for case in case_list]
    alert_rows: List[Dict[str, Any]] = []
    for case in case_list:
        alert_rows.extend(_alert_rows(case, dataset_id))

    with engine.begin() as conn:
        if replace:
            conn.execute(delete(alerts).where(alerts.c.dataset_id == dataset_id))
            conn.execute(delete(cases).where(cases.c.dataset_id == dataset_id))
            conn.execute(delete(datasets).where(datasets.c.dataset_id == dataset_id))

        conn.execute(insert(datasets).values(
            dataset_id=dataset_id,
            created_at=datetime.utcnow(),
            seed=int(seed),
            case_count=len(case_list),
            split=split,
            meta={
                "labels": sorted({case.label for case in case_list}),
                "source": "evals.generator",
            },
        ))
        conn.execute(insert(cases), case_rows)
        if alert_rows:
            conn.execute(insert(alerts), alert_rows)

    return {
        "datasets": 1,
        "cases": len(case_rows),
        "alerts": len(alert_rows),
    }


def label_counts(
    engine: Optional[Engine] = None,
    dataset_id: str = DEFAULT_DATASET_ID,
) -> Dict[str, int]:
    """Return ``{label: row_count}`` for one dataset."""
    engine = engine or create_eval_engine()
    stmt = (
        select(cases.c.label, func.count())
        .where(cases.c.dataset_id == dataset_id)
        .group_by(cases.c.label)
        .order_by(cases.c.label)
    )
    with engine.connect() as conn:
        return {label: int(count) for label, count in conn.execute(stmt)}


def dataset_summary(
    engine: Optional[Engine] = None,
    dataset_id: str = DEFAULT_DATASET_ID,
) -> Dict[str, Any]:
    """Return stored row counts for a dataset."""
    engine = engine or create_eval_engine()
    with engine.connect() as conn:
        case_count = conn.execute(
            select(func.count()).select_from(cases).where(cases.c.dataset_id == dataset_id)
        ).scalar_one()
        alert_count = conn.execute(
            select(func.count()).select_from(alerts).where(
                alerts.c.dataset_id == dataset_id
            )
        ).scalar_one()
    return {
        "dataset_id": dataset_id,
        "cases": int(case_count),
        "alerts": int(alert_count),
        "label_counts": label_counts(engine, dataset_id),
    }


def write_jsonl(case_list: Iterable[EvalCase], path: Path) -> Path:
    """Write one JSON object per case (deterministic key order)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for case in case_list:
            payload = case.model_dump(mode="json")
            handle.write(json.dumps(payload, sort_keys=True, ensure_ascii=True))
            handle.write("\n")
    return path


def read_jsonl(path: Path) -> List[EvalCase]:
    """Read a JSONL dataset back into validated :class:`EvalCase` objects."""
    path = Path(path)
    loaded: List[EvalCase] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                loaded.append(EvalCase.model_validate(json.loads(line)))
            except Exception as exc:  # pragma: no cover - defensive
                raise ValueError(f"{path}:{line_number}: invalid case: {exc}") from exc
    return loaded


def load_jsonl(
    path: Path,
    engine: Optional[Engine] = None,
    *,
    dataset_id: Optional[str] = None,
    seed: int = DEFAULT_SEED,
    split: str = "test",
    replace: bool = True,
) -> Dict[str, int]:
    """Load a JSONL file into PostgreSQL."""
    case_list = read_jsonl(path)
    return load_cases(
        case_list,
        engine=engine,
        dataset_id=dataset_id,
        seed=seed,
        split=split,
        replace=replace,
    )
