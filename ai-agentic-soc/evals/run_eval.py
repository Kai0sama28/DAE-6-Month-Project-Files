"""Run the labeled evaluation set through the live investigation engine.

Each case is an incident bundle. The trigger alert (highest rule level, tie
broken by recency) is handed to the *real* agent graph
(``agent.graph.build_graph``) with an in-memory indexer adapter that replays
only that bundle. The graph therefore exercises the same supervisor, SIEM
correlation, LLM narrative and report stages as production; nothing about the
agent is re-implemented here.

Recorded per investigation:

* whether the investigation completed (LLM narrative + report produced)
* whether the predicted ATT&CK techniques match the ground truth
* whether the recommended action matches the ground truth
* processing time (wall clock, plus the engine's own triage timer)

Usage::

    python -m evals.run_eval                    # 50 trigger alerts, live LLM
    python -m evals.run_eval --no-llm           # deterministic baseline
    python -m evals.run_eval --limit 5          # smoke test
    python -m evals.run_eval --all-alerts       # every alert in every bundle
    python -m evals.run_eval --workers 3 --resume

Outputs (under ``evals/results/`` by default):

    <dataset>-evaluation.jsonl          raw per-case records
    <dataset>-evaluation.csv            flat table
    <dataset>-processing-times.csv      timing table
    <dataset>-EVALUATION.md             evaluation deliverable
    <dataset>-PROCESSING_TIMES.md       timing deliverable
    <dataset>-run-meta.json             run configuration and totals
    reports/                            per-case Markdown/HTML reports
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from unittest.mock import patch

from agent.config import AgentConfig
from agent.events import event_from_wazuh
from agent.graph import build_graph
from agent.llm import OpenRouterClient
from agent.state import AgentState
from evals.generator import DEFAULT_DATASET_ID
from evals.models import EvalCase
from evals.scoring import evaluate_result, summarize
from evals.store import read_jsonl
from schemas.wazuh import WazuhAlert

DEFAULT_DATASET_PATH = (
    Path(__file__).resolve().parent / "dataset" / f"{DEFAULT_DATASET_ID}.jsonl"
)
DEFAULT_RESULTS_DIR = Path(__file__).resolve().parent / "results"


# ---------------------------------------------------------------------------
# in-memory indexer: replay one incident bundle
# ---------------------------------------------------------------------------

class CaseIndexer:
    """Minimal stand-in for :class:`siem.indexer_client.IndexerClient`.

    The evaluation bundle is the incident. Any correlation query the agent
    issues is answered with the whole bundle (time-windowed), so the engine
    sees exactly the evidence a human reviewer was given -- no more, no less.
    """

    index_pattern = "eval-case-*"

    def __init__(self, alerts: Sequence[WazuhAlert]) -> None:
        self._alerts = list(alerts)

    def ping(self) -> bool:
        return True

    def close(self) -> None:
        return None

    def get_alert(self, alert_id: str) -> Optional[WazuhAlert]:
        for alert in self._alerts:
            if str(alert.id or "") == str(alert_id):
                return alert
        return None

    def query_alerts(
        self,
        q: Optional[str] = None,
        filters: Optional[dict] = None,
        limit: int = 100,
        offset: int = 0,
        since: Optional[str] = None,
        until: Optional[str] = None,
    ) -> List[WazuhAlert]:
        start = _parse_iso(since)
        end = _parse_iso(until)
        selected: List[WazuhAlert] = []
        for alert in self._alerts:
            ts = _parse_iso(alert.timestamp)
            if start is not None and ts is not None and ts < start:
                continue
            if end is not None and ts is not None and ts > end:
                continue
            selected.append(alert)
        return selected[offset: offset + max(0, int(limit))]


class _NoAgentsWazuhClient:
    """Avoid a live manager call while replaying offline bundles."""

    def __init__(self, *args, **kwargs) -> None:
        pass

    def list_agents(self, active_only: bool = True) -> list:
        return []

    def close(self) -> None:
        return None


def _parse_iso(value: Optional[str]):
    if not value:
        return None
    text = str(value).strip()
    if text.endswith("+0000"):
        text = text[:-5] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


# ---------------------------------------------------------------------------
# one investigation
# ---------------------------------------------------------------------------

def _make_llm(config: AgentConfig) -> Optional[OpenRouterClient]:
    if not (config.use_llm and config.openrouter_api_key):
        return None
    return OpenRouterClient(
        api_key=config.openrouter_api_key,
        model=config.openrouter_model,
        base_url=config.openrouter_base_url,
        temperature=config.llm_temperature,
        max_tokens=config.llm_max_tokens,
        timeout=config.llm_timeout_seconds,
        max_retries=config.llm_max_retries,
        http_referer=config.openrouter_http_referer,
        title=config.openrouter_title,
    )


def run_case(
    case: EvalCase,
    *,
    trigger_alert: Optional[WazuhAlert],
    base_config: AgentConfig,
    reports_dir: Path,
    state_dir: Path,
    use_llm: bool,
    run_key: str,
) -> Dict[str, Any]:
    """Run one investigation and score it. Safe to call from a worker thread."""
    if trigger_alert is None:
        return {
            "run_key": run_key,
            "case_id": case.case_id,
            "label": case.label,
            "investigation_completed": False,
            "attack_correct": False,
            "recommendation_correct": False,
            "processing_seconds": 0.0,
            "errors": ["case has no trigger alert"],
        }

    config = replace(
        base_config,
        reports_dir=reports_dir,
        state_file=state_dir / f"{run_key.replace('#', '_')}.json",
        notify=False,
        use_identity_api=False,
        use_edr_api=False,
        use_llm=use_llm,
    )
    state_store = AgentState(config.state_file)
    llm = _make_llm(config) if use_llm else None
    indexer = CaseIndexer(case.alerts)
    trigger = event_from_wazuh(trigger_alert)
    graph = build_graph(config, indexer, llm, state_store)

    initial: Dict[str, Any] = {
        "cursor": None,
        "seen_ids": [],
        "pending": [],
        "trigger": trigger,
        "detected_at": datetime.now(timezone.utc).isoformat(),
        "watch_cycles": 0,
        "skip_watch": True,
        "errors": [],
        "query_count": 0,
        "incident_id": case.case_id,
    }

    started = time.perf_counter()
    result: Dict[str, Any] = {}
    error: Optional[str] = None
    try:
        with patch("siem.client.WazuhClient", _NoAgentsWazuhClient):
            result = graph.invoke(initial)
    except Exception as exc:  # a crashed investigation is still a data point
        error = f"{type(exc).__name__}: {exc}"
    elapsed = time.perf_counter() - started

    if error:
        record = evaluate_result(case, {}, elapsed, analysis_source="none")
        record.update({
            "run_key": run_key,
            "trigger_alert_id": str(trigger_alert.id or ""),
            "investigation_completed": False,
            "analysis_source": "none",
            "errors": [error],
            "report_path": "",
        })
        return record

    record = evaluate_result(
        case,
        result,
        elapsed,
        analysis_source="llm" if use_llm else "deterministic",
    )
    record.update({
        "run_key": run_key,
        "trigger_alert_id": str(trigger_alert.id or ""),
        "trigger_rule_id": trigger.get("rule_id"),
        "trigger_level": trigger.get("level"),
    })
    return record


# ---------------------------------------------------------------------------
# output writers
# ---------------------------------------------------------------------------

def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def _json_default(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _append_jsonl(path: Path, record: Dict[str, Any], lock: threading.Lock) -> None:
    with lock:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=True, default=_json_default))
            handle.write("\n")


def _write_csv(path: Path, records: Sequence[Dict[str, Any]]) -> None:
    columns = [
        "run_key", "case_id", "trigger_alert_id", "trigger_rule_id", "trigger_level",
        "label", "scenario", "difficulty",
        "expected_severity", "expected_verdict", "expected_action",
        "investigation_completed", "report_produced", "analysis_source", "status",
        "predicted_action", "recommendation_correct", "recommendation_lenient",
        "expected_mitre", "predicted_mitre", "attack_correct", "attack_exact",
        "attack_matched", "attack_missed", "attack_extra",
        "llm_severity", "llm_confidence", "llm_model_used",
        "processing_seconds", "llm_seconds", "engine_triage_seconds",
        "correlated_events", "report_path", "errors",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for record in records:
            row = dict(record)
            for key in ("expected_mitre", "predicted_mitre", "attack_matched",
                        "attack_missed", "attack_extra", "errors"):
                value = row.get(key)
                if isinstance(value, (list, tuple)):
                    row[key] = ";".join(str(item) for item in value)
            writer.writerow(row)


def _fmt(value: Any) -> str:
    if isinstance(value, float):
        return f"{value:.3f}"
    if isinstance(value, (list, tuple)):
        return ", ".join(str(item) for item in value) if value else "-"
    return str(value) if value not in (None, "") else "-"


def _pct(numerator: int, denominator: int) -> str:
    if not denominator:
        return "n/a"
    return f"{100.0 * numerator / denominator:.1f}%"


def render_evaluation_markdown(
    records: Sequence[Dict[str, Any]],
    summary: Dict[str, Any],
    *,
    dataset_id: str,
    mode: str,
    model: str,
    generated_at: datetime,
) -> str:
    out: List[str] = []
    out.append(f"# Evaluation results — {dataset_id}")
    out.append("")
    out.append(f"- Generated: {generated_at.strftime('%Y-%m-%d %H:%M:%SZ')}")
    out.append(f"- Dataset: `{dataset_id}` ({summary['total']} investigations)")
    out.append(f"- Mode: {mode}" + (f" (`{model}`)" if model else ""))
    out.append("- Scope: one investigation per case (highest-severity alert = trigger)")
    out.append("")
    out.append("## Headline")
    out.append("")
    out.append("| Metric | Result | Rate |")
    out.append("|---|---:|---:|")
    out.append(
        f"| Investigation completed | {summary['completed']} / {summary['total']} | "
        f"{summary['completion_rate_pct']:.1f}% |"
    )
    out.append(
        f"| Correct ATT&CK (any expected technique) | {summary['attack_correct']} / "
        f"{summary['total']} | {summary['attack_accuracy_pct']:.1f}% |"
    )
    out.append(
        f"| Correct ATT&CK (exact set) | {summary['attack_exact']} / {summary['total']} | "
        f"{summary['attack_exact_pct']:.1f}% |"
    )
    out.append(
        f"| Correct recommendation (exact action) | {summary['recommendation_correct']} / "
        f"{summary['total']} | {summary['recommendation_accuracy_pct']:.1f}% |"
    )
    out.append(
        f"| Correct recommendation (lenient) | {summary['recommendation_lenient']} / "
        f"{summary['total']} | {summary['recommendation_lenient_pct']:.1f}% |"
    )
    out.append("")

    out.append("## By label")
    out.append("")
    out.append("| Label | Cases | Completed | ATT&CK correct | Recommendation correct | Exact ATT&CK |")
    out.append("|---|---:|---:|---:|---:|---:|")
    for label, block in summary["by_label"].items():
        out.append(
            f"| {label} | {block['cases']} | {block['completed']} "
            f"({block['completion_rate_pct']:.1f}%) | {block['attack_correct']} "
            f"({block['attack_accuracy_pct']:.1f}%) | {block['recommendation_correct']} "
            f"({block['recommendation_accuracy_pct']:.1f}%) | {block['attack_exact']} |"
        )
    out.append("")

    out.append("## Recommendation confusion matrix")
    out.append("")
    predicted_actions = sorted({
        action
        for row in summary["confusion"].values()
        for action in row
    })
    out.append("| Expected \\ Predicted | " + " | ".join(predicted_actions) + " |")
    out.append("|---|" + "---:|" * len(predicted_actions))
    for expected, row in summary["confusion"].items():
        out.append(
            f"| {expected} | " + " | ".join(str(row.get(a, 0)) for a in predicted_actions) + " |"
        )
    out.append("")

    failures = [
        r for r in records
        if not r.get("investigation_completed")
        or not r.get("attack_correct")
        or not r.get("recommendation_correct")
    ]
    out.append(f"## Investigations needing review ({len(failures)})")
    out.append("")
    if failures:
        out.append("| Case | Label | Completed | ATT&CK | Recommendation | Note |")
        out.append("|---|---|---|---|---|---|")
        for record in failures:
            notes: List[str] = []
            if not record.get("investigation_completed"):
                notes.append("no narrative")
            if not record.get("attack_correct"):
                notes.append(
                    f"expected {_fmt(record.get('expected_mitre'))}; "
                    f"got {_fmt(record.get('predicted_mitre'))}"
                )
            if not record.get("recommendation_correct"):
                notes.append(
                    f"expected {record.get('expected_action')}; "
                    f"got {record.get('predicted_action')}"
                )
            errors = record.get("errors") or []
            if errors:
                notes.append(str(errors[0])[:120])
            out.append(
                f"| {record.get('case_id')} | {record.get('label')} | "
                f"{'yes' if record.get('investigation_completed') else 'no'} | "
                f"{'yes' if record.get('attack_correct') else 'no'} | "
                f"{'yes' if record.get('recommendation_correct') else 'no'} | "
                f"{'; '.join(notes) or '-'} |"
            )
    else:
        out.append("None — every investigation completed and scored correctly.")
    out.append("")

    out.append("## Per-case results")
    out.append("")
    out.append("| Case | Label | Trigger rule | Expected action | Predicted action | ATT&CK match | Time (s) |")
    out.append("|---|---|---|---|---|---|---:|")
    for record in records:
        out.append(
            f"| {record.get('case_id')} | {record.get('label')} | "
            f"{_fmt(record.get('trigger_rule_id'))} | {record.get('expected_action')} | "
            f"{record.get('predicted_action')} | "
            f"{'yes' if record.get('attack_correct') else 'no'} | "
            f"{float(record.get('processing_seconds') or 0):.1f} |"
        )
    out.append("")

    incomplete = [r for r in records if not r.get("investigation_completed")]
    rate_limited = [
        r for r in incomplete
        if any("429" in str(error) for error in (r.get("errors") or []))
    ]
    out.append("## Run notes")
    out.append("")
    if incomplete:
        out.append(
            f"- {len(incomplete)} investigation(s) produced no narrative. Their "
            "ATT&CK/recommendation fields are marked incorrect and excluded from "
            "the reasoning-accuracy claim; deterministic correlation facts are "
            "still present in the saved report."
        )
    if rate_limited:
        out.append(
            f"- {len(rate_limited)} of those were blocked by the OpenRouter free-tier "
            "daily limit (`429 free-models-per-day`), not by an engine failure: "
            + ", ".join(str(r.get("case_id")) for r in rate_limited)
            + ". Re-run `python -m evals.run_eval --resume` after the quota resets."
        )
    if not incomplete:
        out.append("- Every investigation produced a narrative and a report.")
    out.append("")

    out.append("## Method and scoring")
    out.append("")
    out.append(
        "Every case was replayed through `agent.graph.build_graph` with an "
        "in-memory indexer containing only that incident bundle. The agent ran "
        "its normal supervisor, SIEM correlation, LLM narrative and report "
        "stages; identity/EDR HTTP mocks and desktop notifications were "
        "disabled so the run is reproducible offline."
    )
    out.append("")
    out.append(
        "- **Investigation completed** = the LLM narrative was produced and a "
        "report was written. A deterministic-only fallback report counts as not "
        "completed because no ATT&CK/recommendation reasoning is present."
    )
    out.append(
        "- **Correct ATT&CK** = the narrative's `mitre_mapping` contains at least "
        "one ground-truth technique. For benign cases it means the engine "
        "claimed no technique. *Exact* additionally requires set equality."
    )
    out.append(
        "- **Correct recommendation** = the action inferred from the narrative's "
        "recommended/containment actions equals the case's expected action "
        "(`monitor`/`investigate`/`escalate`/`contain`). *Lenient* accepts an "
        "adjacent safe action."
    )
    out.append(
        "- **Processing time** = wall clock around the agent graph invocation, "
        "including correlation and LLM latency. See `PROCESSING_TIMES.md`."
    )
    out.append("")
    return "\n".join(out)


def render_processing_markdown(
    records: Sequence[Dict[str, Any]],
    summary: Dict[str, Any],
    *,
    dataset_id: str,
    mode: str,
    model: str,
    generated_at: datetime,
) -> str:
    overall = summary["times"]
    out: List[str] = []
    out.append(f"# Processing times — {dataset_id}")
    out.append("")
    out.append(f"- Generated: {generated_at.strftime('%Y-%m-%d %H:%M:%SZ')}")
    out.append(f"- Investigations: {summary['total']}")
    out.append(f"- Mode: {mode}" + (f" (`{model}`)" if model else ""))
    out.append("")
    out.append("## Summary")
    out.append("")
    out.append("| Statistic | Seconds |")
    out.append("|---|---:|")
    out.append(f"| Total wall clock | {overall.get('total_seconds', 0):.1f} |")
    out.append(f"| Mean | {overall.get('mean_seconds', 0):.1f} |")
    out.append(f"| Median | {overall.get('median_seconds', 0):.1f} |")
    out.append(f"| p95 | {overall.get('p95_seconds', 0):.1f} |")
    out.append(f"| Min | {overall.get('min_seconds', 0):.1f} |")
    out.append(f"| Max | {overall.get('max_seconds', 0):.1f} |")
    out.append("")
    out.append(
        f"_Statistics cover the {summary.get('completed', 0)} completed "
        f"investigation(s) across {summary['total']} runs. Failed/no-narrative "
        "attempts are listed in the per-investigation table but excluded from "
        "the mean/median/p95._"
    )
    out.append("")
    out.append("## By label")
    out.append("")
    out.append("| Label | N (completed) | Mean (s) | Median (s) | p95 (s) | Min (s) | Max (s) |")
    out.append("|---|---:|---:|---:|---:|---:|---:|")
    for label, block in summary["by_label"].items():
        times = block["times"]
        out.append(
            f"| {label} | {times.get('count', 0)} | {times.get('mean_seconds', 0):.1f} | "
            f"{times.get('median_seconds', 0):.1f} | {times.get('p95_seconds', 0):.1f} | "
            f"{times.get('min_seconds', 0):.1f} | {times.get('max_seconds', 0):.1f} |"
        )
    out.append("")
    out.append("## Per-investigation times")
    out.append("")
    out.append("| Case | Label | Wall clock (s) | LLM attempts (s) | Correlated events |")
    out.append("|---|---|---:|---:|---:|")
    for record in sorted(
        records, key=lambda r: float(r.get("processing_seconds") or 0.0), reverse=True
    ):
        out.append(
            f"| {record.get('case_id')} | {record.get('label')} | "
            f"{float(record.get('processing_seconds') or 0):.1f} | "
            f"{float(record.get('llm_seconds') or 0):.1f} | "
            f"{int(record.get('correlated_events') or 0)} |"
        )
    out.append("")
    out.append("## Notes")
    out.append("")
    out.append(
        "Wall clock is measured around `graph.invoke` and includes the LLM "
        "request, retries/fallbacks and deterministic correlation. `LLM "
        "attempts` is the sum of the individual model attempt durations "
        "recorded by the agent; when a model fails and falls back, wall clock "
        "is larger than a single successful attempt."
    )
    out.append("")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# orchestration
# ---------------------------------------------------------------------------

def _selected_runs(
    cases: Sequence[EvalCase],
    all_alerts: bool,
) -> List[Tuple[str, EvalCase, Optional[WazuhAlert]]]:
    runs: List[Tuple[str, EvalCase, Optional[WazuhAlert]]] = []
    for case in cases:
        if all_alerts:
            for alert in case.alerts:
                runs.append((f"{case.case_id}#{alert.id}", case, alert))
        else:
            runs.append((case.case_id, case, case.trigger_alert()))
    return runs


def _load_existing_records(path: Path) -> Dict[str, Dict[str, Any]]:
    """Read an existing results JSONL, keeping the last record per run key."""
    records: Dict[str, Dict[str, Any]] = {}
    if not path.exists():
        return records
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except ValueError:
                continue
            key = payload.get("run_key") or payload.get("case_id")
            if key:
                records[key] = payload
    return records


def _rescore_records(
    records: Sequence[Dict[str, Any]],
    cases: Dict[str, EvalCase],
) -> List[Dict[str, Any]]:
    """Recompute scores from stored JSONL records without re-running the LLM."""
    rescored: List[Dict[str, Any]] = []
    for previous in records:
        case = cases.get(str(previous.get("case_id") or ""))
        if case is None:
            rescored.append(previous)
            continue
        correlation = previous.get("correlation_summary") or {}
        result = {
            "analysis": previous.get("analysis") or {},
            "correlation": {
                "event_count": correlation.get("event_count"),
                "flags": correlation.get("flags") or {},
                "mitre_ids": correlation.get("mitre_ids") or [],
            },
            "metrics": {
                "llm_model_used": previous.get("llm_model_used") or "",
                "llm_attempts": previous.get("llm_attempts") or [],
                "triage_seconds": previous.get("engine_triage_seconds") or 0.0,
            },
            "report_path": previous.get("report_path") or "",
            "status": previous.get("status") or "",
            "errors": previous.get("errors") or [],
        }
        source = "deterministic" if previous.get("analysis_source") == "deterministic" else "llm"
        record = evaluate_result(
            case,
            result,
            float(previous.get("processing_seconds") or 0.0),
            analysis_source=source,
        )
        record.update({
            "run_key": previous.get("run_key") or case.case_id,
            "trigger_alert_id": previous.get("trigger_alert_id") or "",
            "trigger_rule_id": previous.get("trigger_rule_id") or "",
            "trigger_level": previous.get("trigger_level") or 0,
        })
        rescored.append(record)
    return rescored


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="evals.run_eval",
        description="Run the labeled evaluation set through the investigation engine",
    )
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET_PATH,
                        help=f"JSONL dataset (default: {DEFAULT_DATASET_PATH})")
    parser.add_argument("--outdir", type=Path, default=DEFAULT_RESULTS_DIR,
                        help=f"results directory (default: {DEFAULT_RESULTS_DIR})")
    parser.add_argument("--limit", type=int, default=None,
                        help="run at most N investigations (smoke testing)")
    parser.add_argument("--case", action="append", default=None,
                        help="run only these case ids (repeatable)")
    parser.add_argument("--workers", type=int, default=1,
                        help="parallel investigations (default: 1)")
    parser.add_argument("--no-llm", action="store_true",
                        help="deterministic baseline; no OpenRouter calls")
    parser.add_argument("--all-alerts", action="store_true",
                        help="investigate every alert, not just each case trigger")
    parser.add_argument("--resume", action="store_true",
                        help="skip investigations already present in the JSONL")
    parser.add_argument("--rescore", action="store_true",
                        help="recompute scores/reports from existing JSONL; no engine calls")
    args = parser.parse_args(argv)

    if not args.dataset.exists():
        print(f"dataset not found: {args.dataset}", file=sys.stderr)
        return 2

    cases = read_jsonl(args.dataset)
    if args.case:
        wanted = set(args.case)
        cases = [case for case in cases if case.case_id in wanted]
    if not cases:
        print("no cases selected", file=sys.stderr)
        return 2

    base_config = AgentConfig.from_env()
    use_llm = bool(base_config.openrouter_api_key) and not args.no_llm
    mode = "live LLM" if use_llm else "deterministic (no LLM)"
    model = base_config.openrouter_model if use_llm else ""

    outdir = Path(args.outdir)
    reports_dir = outdir / "reports"
    state_dir = outdir / "_state"
    reports_dir.mkdir(parents=True, exist_ok=True)
    state_dir.mkdir(parents=True, exist_ok=True)

    dataset_id = cases[0].dataset_id or DEFAULT_DATASET_ID
    slug = f"{dataset_id}-{'all-alerts' if args.all_alerts else 'cases'}-{'llm' if use_llm else 'deterministic'}"
    jsonl_path = outdir / f"{slug}-evaluation.jsonl"
    csv_path = outdir / f"{slug}-evaluation.csv"
    times_csv_path = outdir / f"{slug}-processing-times.csv"
    eval_md_path = outdir / f"{slug}-EVALUATION.md"
    times_md_path = outdir / f"{slug}-PROCESSING_TIMES.md"
    meta_path = outdir / f"{slug}-run-meta.json"

    if args.rescore:
        if not jsonl_path.exists():
            print(f"results not found: {jsonl_path}", file=sys.stderr)
            return 2
        previous = _load_existing_records(jsonl_path)
        records = _rescore_records(
            list(previous.values()),
            {case.case_id: case for case in cases},
        )
        records.sort(key=lambda r: str(r.get("run_key") or r.get("case_id")))
        summary = summarize(records)
        generated_at = datetime.now(timezone.utc)
        _atomic_write(
            jsonl_path,
            "".join(
                json.dumps(record, ensure_ascii=True, default=_json_default) + "\n"
                for record in records
            ),
        )
        _write_csv(csv_path, records)
        _write_csv(
            times_csv_path,
            [
                {
                    "run_key": r.get("run_key"),
                    "case_id": r.get("case_id"),
                    "label": r.get("label"),
                    "processing_seconds": r.get("processing_seconds"),
                    "llm_seconds": r.get("llm_seconds"),
                    "engine_triage_seconds": r.get("engine_triage_seconds"),
                    "correlated_events": r.get("correlated_events"),
                }
                for r in records
            ],
        )
        _atomic_write(
            eval_md_path,
            render_evaluation_markdown(
                records, summary,
                dataset_id=dataset_id, mode=mode, model=model,
                generated_at=generated_at,
            ),
        )
        _atomic_write(
            times_md_path,
            render_processing_markdown(
                records, summary,
                dataset_id=dataset_id, mode=mode, model=model,
                generated_at=generated_at,
            ),
        )
        _atomic_write(meta_path, json.dumps({
            "dataset_id": dataset_id,
            "mode": mode,
            "model": model,
            "scope": "all-alerts" if args.all_alerts else "case-trigger",
            "rescored_at": generated_at.isoformat(),
            "runs": len(records),
            "summary": summary,
            "outputs": {
                "jsonl": str(jsonl_path),
                "csv": str(csv_path),
                "processing_times_csv": str(times_csv_path),
                "evaluation_markdown": str(eval_md_path),
                "processing_times_markdown": str(times_md_path),
            },
        }, indent=2, ensure_ascii=True, default=_json_default))
        print(f"rescored {len(records)} records")
        print(f"completed: {summary['completed']} / {summary['total']}")
        print(f"ATT&CK correct:          {summary['attack_correct']} / {summary['total']} "
              f"({summary['attack_accuracy_pct']:.1f}%)")
        print(f"Recommendation correct:  {summary['recommendation_correct']} / {summary['total']} "
              f"({summary['recommendation_accuracy_pct']:.1f}%)")
        return 0

    existing: Dict[str, Dict[str, Any]] = (
        _load_existing_records(jsonl_path) if args.resume else {}
    )
    runs = _selected_runs(cases, args.all_alerts)
    if existing:
        # Retry runs that never produced a narrative; keep completed ones.
        runs = [
            run for run in runs
            if not existing.get(run[0], {}).get("investigation_completed")
        ]
    if args.limit is not None:
        runs = runs[: max(0, args.limit)]
    if not runs:
        print("nothing to run (all selected investigations already complete)")
        return 0

    # Always start from a clean JSONL unless resuming; otherwise old and new
    # records with different modes would be mixed together.
    if not args.resume and jsonl_path.exists():
        jsonl_path.unlink()

    started_at = datetime.now(timezone.utc)
    print(f"dataset:   {dataset_id}")
    print(f"cases:     {len(cases)}")
    print(f"runs:      {len(runs)}")
    print(f"mode:      {mode}" + (f" ({model})" if model else ""))
    print(f"workers:   {max(1, args.workers)}")
    print(f"output:    {outdir}")
    print("")

    write_lock = threading.Lock()
    records: List[Dict[str, Any]] = list(existing.values())
    failures = 0

    def task(run: Tuple[str, EvalCase, Optional[WazuhAlert]]) -> Dict[str, Any]:
        run_key, case, alert = run
        return run_case(
            case,
            trigger_alert=alert,
            base_config=base_config,
            reports_dir=reports_dir,
            state_dir=state_dir,
            use_llm=use_llm,
            run_key=run_key,
        )

    workers = max(1, int(args.workers))
    if workers == 1:
        iterator = (task(run) for run in runs)
        for index, record in enumerate(iterator, start=1):
            _append_jsonl(jsonl_path, record, write_lock)
            records.append(record)
            _report_progress(index, len(runs), record)
    else:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(task, run): run for run in runs}
            for index, future in enumerate(as_completed(futures), start=1):
                try:
                    record = future.result()
                except Exception as exc:  # pragma: no cover - defensive
                    failures += 1
                    run_key, case, alert = futures[future]
                    record = {
                        "run_key": run_key,
                        "case_id": case.case_id,
                        "label": case.label,
                        "investigation_completed": False,
                        "attack_correct": False,
                        "recommendation_correct": False,
                        "processing_seconds": 0.0,
                        "errors": [f"{type(exc).__name__}: {exc}"],
                    }
                _append_jsonl(jsonl_path, record, write_lock)
                records.append(record)
                _report_progress(index, len(runs), record)

    # Resume runs can append a retried record after the original one. Keep the
    # newest record per run key and rewrite the JSONL so the deliverable is
    # free of duplicates.
    deduped: Dict[str, Dict[str, Any]] = {}
    for record in records:
        key = str(record.get("run_key") or record.get("case_id"))
        deduped[key] = record
    records = list(deduped.values())
    _atomic_write(
        jsonl_path,
        "".join(
            json.dumps(record, ensure_ascii=True, default=_json_default) + "\n"
            for record in records
        ),
    )

    records.sort(key=lambda r: str(r.get("run_key") or r.get("case_id")))
    summary = summarize(records)
    generated_at = datetime.now(timezone.utc)

    _write_csv(csv_path, records)
    _write_csv(
        times_csv_path,
        [
            {
                "run_key": r.get("run_key"),
                "case_id": r.get("case_id"),
                "label": r.get("label"),
                "processing_seconds": r.get("processing_seconds"),
                "llm_seconds": r.get("llm_seconds"),
                "engine_triage_seconds": r.get("engine_triage_seconds"),
                "correlated_events": r.get("correlated_events"),
            }
            for r in records
        ],
    )
    _atomic_write(
        eval_md_path,
        render_evaluation_markdown(
            records, summary,
            dataset_id=dataset_id, mode=mode, model=model, generated_at=generated_at,
        ),
    )
    _atomic_write(
        times_md_path,
        render_processing_markdown(
            records, summary,
            dataset_id=dataset_id, mode=mode, model=model, generated_at=generated_at,
        ),
    )

    meta = {
        "dataset_id": dataset_id,
        "dataset_path": str(args.dataset),
        "mode": mode,
        "model": model,
        "workers": workers,
        "scope": "all-alerts" if args.all_alerts else "case-trigger",
        "started_at": started_at.isoformat(),
        "finished_at": generated_at.isoformat(),
        "duration_seconds": round((generated_at - started_at).total_seconds(), 3),
        "runs": len(records),
        "failures": failures,
        "summary": summary,
        "outputs": {
            "jsonl": str(jsonl_path),
            "csv": str(csv_path),
            "processing_times_csv": str(times_csv_path),
            "evaluation_markdown": str(eval_md_path),
            "processing_times_markdown": str(times_md_path),
        },
    }
    _atomic_write(meta_path, json.dumps(meta, indent=2, ensure_ascii=True, default=_json_default))

    print("")
    print(f"completed: {summary['completed']} / {summary['total']}")
    print(f"ATT&CK correct:          {summary['attack_correct']} / {summary['total']} "
          f"({summary['attack_accuracy_pct']:.1f}%)")
    print(f"Recommendation correct:  {summary['recommendation_correct']} / {summary['total']} "
          f"({summary['recommendation_accuracy_pct']:.1f}%)")
    print(f"mean processing time:    {summary['times'].get('mean_seconds', 0):.1f}s "
          f"(median {summary['times'].get('median_seconds', 0):.1f}s)")
    print("")
    print(f"results:   {eval_md_path}")
    print(f"times:     {times_md_path}")
    print(f"jsonl:     {jsonl_path}")
    return 0 if failures == 0 else 1


def _report_progress(index: int, total: int, record: Dict[str, Any]) -> None:
    status = "ok" if record.get("investigation_completed") else "no-narrative"
    print(
        f"[{index:>3}/{total}] {record.get('case_id'):<16} "
        f"{record.get('label'):<22} "
        f"attack={'y' if record.get('attack_correct') else 'n'} "
        f"rec={'y' if record.get('recommendation_correct') else 'n'} "
        f"{float(record.get('processing_seconds') or 0):6.1f}s {status}",
        flush=True,
    )


if __name__ == "__main__":
    raise SystemExit(main())
