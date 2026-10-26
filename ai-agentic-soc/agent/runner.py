"""Background triage agent — entry point.

Usage::

    python -m agent.runner                 # run the watcher daemon (foreground)
    python -m agent.runner --once          # one watch cycle, then exit
    python -m agent.runner --investigate 1792606605.46868   # investigate one alert now
    python -m agent.runner --no-llm        # deterministic report only (no API calls)
    python -m agent.runner --status        # show the persisted state

The daemon keeps polling the Wazuh indexer. The moment Wazuh writes a new
alert, the agent correlates it with every related log, builds the timeline,
asks NVIDIA Nemotron 3.5 Lightning (via OpenRouter) to write the analyst narrative,
saves the Markdown report and fires a desktop notification.
"""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from agent.config import AgentConfig
from agent.events import event_from_wazuh
from agent.graph import build_graph
from agent.llm import OpenRouterClient
from agent.state import AgentState
from siem.indexer_client import IndexerClient

_STOP = {"requested": False}


def _handle_signal(signum, frame) -> None:  # pragma: no cover - signal path
    _STOP["requested"] = True
    print(f"\n[agent] signal {signum} received — shutting down after this cycle", flush=True)


def _log(message: str) -> None:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    print(f"[{stamp}] {message}", flush=True)


def build_clients(config: AgentConfig, use_llm: bool) -> tuple:
    indexer = IndexerClient()
    llm = None
    if use_llm:
        if config.openrouter_api_key:
            llm = OpenRouterClient(
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
        else:
            _log("WARNING: OPENROUTER_API_KEY not set — running deterministic-only mode")
    return indexer, llm


def investigate_now(
    config: AgentConfig,
    indexer: IndexerClient,
    llm: Optional[OpenRouterClient],
    state_store: AgentState,
    trigger: dict[str, Any],
) -> dict[str, Any]:
    """Run the investigation half of the graph against a specific alert."""
    graph = build_graph(config, indexer, llm, state_store)
    initial: dict[str, Any] = {
        "cursor": state_store.cursor,
        "seen_ids": [],
        "pending": [],
        "trigger": trigger,
        "detected_at": datetime.now(timezone.utc).isoformat(),
        "watch_cycles": 0,
        "skip_watch": True,
        "errors": [],
        "query_count": 0,
    }
    return graph.invoke(initial)


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="agent.runner",
        description="AI-Agentic SOC background triage agent (Wazuh -> correlate -> timeline -> report -> notify)",
    )
    parser.add_argument("--once", action="store_true",
                        help="run a single watch cycle and exit")
    parser.add_argument("--investigate", metavar="ALERT_ID",
                        help="immediately investigate one existing Wazuh alert id")
    parser.add_argument("--no-llm", action="store_true",
                        help="disable the LLM (deterministic report only)")
    parser.add_argument("--interval", type=float, default=None,
                        help="override the poll interval in seconds")
    parser.add_argument("--min-level", type=int, default=None,
                        help="override the minimum rule level that triggers triage")
    parser.add_argument("--settle", type=float, default=None,
                        help="seconds to wait for related alerts before correlating")
    parser.add_argument("--status", action="store_true",
                        help="print the persisted agent state and exit")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%SZ",
    )
    # httpx logs every indexer/OpenRouter request at INFO; keep the daemon log
    # readable for a human watching it.
    logging.getLogger("httpx").setLevel(logging.WARNING)

    config = AgentConfig.from_env()
    if args.interval is not None:
        config.poll_interval_seconds = args.interval
    if args.min_level is not None:
        config.min_rule_level = args.min_level
    if args.settle is not None:
        config.settle_seconds = args.settle
    if args.no_llm:
        config.use_llm = False

    state_store = AgentState(config.state_file)

    if args.status:
        data = state_store.data
        data["seen_ids_count"] = len(data.get("seen_ids") or [])
        data.pop("seen_ids", None)
        print(data)
        return 0

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    indexer, llm = build_clients(config, use_llm=not args.no_llm)

    _log(f"agent starting — model={config.openrouter_model!r} "
         f"poll={config.poll_interval_seconds}s min_level={config.min_rule_level} "
         f"reports={config.reports_dir}")

    try:
        if not indexer.ping():
            _log("ERROR: Wazuh indexer is not reachable — check WAZUH_INDEXER_* settings")
            return 2
        _log(f"indexer OK ({indexer.base_url}, pattern {indexer.index_pattern})")
    except Exception as exc:
        _log(f"ERROR: indexer check failed: {exc}")
        return 2

    if llm is None:
        reason = config.missing_llm_reason() or "LLM disabled"
        _log(f"LLM disabled: {reason} — reports will be deterministic-only")

    # -- ad-hoc investigation of one existing alert ------------------------
    if args.investigate:
        try:
            alert = indexer.get_alert(args.investigate)
        except Exception as exc:
            _log(f"ERROR: could not fetch alert {args.investigate}: {exc}")
            return 2
        if alert is None:
            _log(f"ERROR: alert {args.investigate} not found in the indexer")
            return 2
        trigger = event_from_wazuh(alert)
        _log(f"investigating alert {trigger['id']} (rule {trigger['rule_id']})")
        result = investigate_now(config, indexer, llm, state_store, trigger)
        _log(f"report: {result.get('report_path')}")
        if result.get("report_html_path"):
            _log(f"report (html): {result.get('report_html_path')}")
        return 0

    # -- daemon loop --------------------------------------------------------
    graph = build_graph(config, indexer, llm, state_store)
    state_store.bump_runs()
    state_store.save()

    # On a cold start only react to alerts that appear from now on, so the
    # agent does not immediately "re-investigate" the lab's history.
    if state_store.cursor is None:
        cursor = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat()
        state_store.set_cursor(cursor)
        state_store.save()
        _log(f"cold start — cursor initialised to {cursor}")

    cycles = 0
    pending: list = []
    settle_until: Optional[str] = None
    burst_start: Optional[str] = None
    while not _STOP["requested"]:
        cycles += 1
        try:
            result = graph.invoke({
                "cursor": state_store.cursor,
                "seen_ids": list(state_store.seen_ids),
                "pending": pending,
                "watch_cycles": cycles,
                "query_count": 0,
                "errors": [],
                "settle_until": settle_until,
                "burst_start": burst_start,
            })
        except Exception as exc:
            _log(f"ERROR: agent cycle failed: {exc}")
            time.sleep(config.poll_interval_seconds)
            continue

        state_store.set_cursor(result.get("cursor"))
        state_store.mark_seen(result.get("seen_ids") or [])
        state_store.save()
        pending = list(result.get("pending") or [])
        settle_until = result.get("settle_until")
        burst_start = result.get("burst_start")

        status = result.get("status")
        if status == "settling":
            _log(f"settling — waiting for correlation rules "
                 f"(until {settle_until}, candidates queued: {len(pending)})")
        if status == "triggered":
            trigger = result.get("trigger") or {}
            _log(
                f"TRIGGER rule {trigger.get('rule_id')} level {trigger.get('level')} "
                f"on {trigger.get('agent_name')} — correlating"
            )
        if result.get("report_path"):
            _log(f"REPORT {result.get('incident_id')} -> {result.get('report_path')}")
            if result.get("report_html_path"):
                _log(f"REPORT (html) -> {result.get('report_html_path')}")
            analysis = result.get("analysis") or {}
            if analysis.get("severity"):
                _log(f"severity={analysis['severity']} confidence={analysis.get('confidence')}")
            metrics = result.get("metrics") or {}
            _log(
                f"MTTD={metrics.get('mttd_seconds', 0):.1f}s "
                f"burst={metrics.get('burst_mttd_seconds', 0):.1f}s "
                f"triage={metrics.get('triage_seconds', 0):.1f}s "
                f"events={(result.get('correlation') or {}).get('event_count', 0)}"
            )
        for error in result.get("errors") or []:
            _log(f"  ! {error}")

        if args.once:
            break

        time.sleep(config.poll_interval_seconds)

    _log("agent stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
