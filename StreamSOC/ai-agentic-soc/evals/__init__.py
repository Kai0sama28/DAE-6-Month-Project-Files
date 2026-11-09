"""Labeled evaluation dataset for the AI-Agentic SOC triage engine.

Ground-truth labels are assigned by the generator, never by the LLM. The
dataset is written as JSONL and can be loaded into PostgreSQL under the
``eval`` schema (see :mod:`evals.store`).
"""

from __future__ import annotations

from evals.generator import (
    CASES_PER_LABEL,
    DEFAULT_DATASET_ID,
    DEFAULT_SEED,
    generate_dataset,
    validate_dataset,
)
from evals.models import EvalCase
from evals.store import (
    create_eval_engine,
    dataset_summary,
    label_counts,
    load_cases,
    load_jsonl,
    read_jsonl,
    write_jsonl,
)
from evals.taxonomy import LABELS

__all__ = [
    "CASES_PER_LABEL",
    "DEFAULT_DATASET_ID",
    "DEFAULT_SEED",
    "EvalCase",
    "LABELS",
    "create_eval_engine",
    "dataset_summary",
    "generate_dataset",
    "label_counts",
    "load_cases",
    "load_jsonl",
    "read_jsonl",
    "validate_dataset",
    "write_jsonl",
]
