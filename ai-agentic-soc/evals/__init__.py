"""Labeled evaluation dataset for the AI-Agentic SOC triage engine.

Ground-truth labels are assigned by the generator, never by the LLM. The
dataset is written as JSONL and can be loaded into PostgreSQL under the
``eval`` schema (see :mod:`evals.store`).
"""

from __future__ import annotations

from evals.generator import generate_dataset
from evals.models import EvalCase

__all__ = ["EvalCase", "generate_dataset", "LABELS"]

from evals.taxonomy import LABELS
