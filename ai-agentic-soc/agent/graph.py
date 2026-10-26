"""LangGraph workflow for the background triage agent.

One graph invocation == one full agent cycle:

``watch`` → ``supervisor`` → (``identity`` → ``edr``) → ``siem`` → ``timeline``
→ ``reason`` → ``report`` → ``notify``

``watch`` returns immediately when there is nothing new, so the runner can
drive the graph in a loop and get a continuously-running daemon. The
``supervisor`` node decides which evidence pillars the alert actually needs
and records the plan in the state, so every decision is auditable.
"""

from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from langgraph.graph import END, START, StateGraph
from typing_extensions import TypedDict

from agent.correlation import build_window, correlate
from agent.events import event_from_wazuh
from agent.llm import OpenRouterClient, OpenRouterError
from agent.report import (
    ANALYSIS_SYSTEM_PROMPT,
    build_analysis_prompt,
    build_incident_id,
    evidence_hash,
    prompt_hash,
    render_report,
    render_report_html,
    write_report,
    write_report_html,
)
from siem.indexer_client import IndexerClient

logger = logging.getLogger("agent.graph")


class TriageState(TypedDict, total=False):
    """State carried across the agent's nodes."""

    # watcher
    cursor: Optional[str]
    seen_ids: list
    pending: list
    trigger: Optional[dict]
    detected_at: Optional[str]
    watch_cycles: int
    skip_watch: bool
    settle_until: Optional[str]
    burst_start: Optional[str]

    # supervisor
    plan: dict
    pillars: dict

    # evidence
    correlation: dict
    identity_context: dict
    edr_context: dict
    agents: list

    # output
    analysis: dict
    metrics: dict
    incident_id: str
    report_path: str
    report_html_path: str
    status: str
    errors: list
    query_count: int


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    text = value.strip()
    if text.endswith("+0000"):
        text = text[:-5] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def plan_pillars(trigger: dict[str, Any]) -> dict[str, Any]:
    """Decide which evidence pillars this alert needs.

    Deterministic on purpose: the decision is recorded in the state and shown
    in the report, so a reviewer can check the agent's reasoning.
    """
    rule_id = str(trigger.get("rule_id") or "")
    groups = [str(g).lower() for g in (trigger.get("groups") or [])]
    phase = trigger.get("phase", "OTHER")

    user_related = bool(trigger.get("dst_user")) or any(
        token in " ".join(groups) for token in ("authentication", "pam", "sudo")
    )
    endpoint_related = bool(trigger.get("agent_name")) or phase in (
        "EXECUTION",
        "INTEGRITY",
        "PERSISTENCE",
    )

    return {
        "siem": {
            "required": True,
            "reason": "every investigation starts from the SIEM alert history",
        },
        "identity": {
            "required": user_related,
            "reason": "alert involves an account or authentication" if user_related
                      else "no account context in the alert",
        },
        "edr": {
            "required": endpoint_related,
            "reason": "endpoint activity may explain the alert" if endpoint_related
                      else "no endpoint context in the alert",
        },
    }


# --------------------------------------------------------------------------
# graph construction
# --------------------------------------------------------------------------

def build_graph(config: Any, indexer: IndexerClient, llm: Optional[OpenRouterClient],
                state_store: Any) -> Any:
    """Build the compiled LangGraph workflow."""

    def watch(state: TriageState) -> dict:
        """Poll the indexer for alerts we have not seen yet."""
        errors: list = list(state.get("errors") or [])

        # An externally supplied trigger (e.g. `runner --investigate <id>`)
        # bypasses polling entirely.
        if state.get("skip_watch"):
            return {"status": "triggered", "errors": errors}

        query_count = int(state.get("query_count") or 0)

        seen = set(state.get("seen_ids") or [])
        cursor = state.get("cursor")
        try:
            fresh = indexer.query_alerts(
                since=cursor,
                limit=200,
            )
            query_count += 1
        except Exception as exc:  # indexer down / TLS / auth
            errors.append(f"indexer query failed: {exc}")
            return {"errors": errors, "status": "watch_error",
                    "watch_cycles": int(state.get("watch_cycles") or 0) + 1}

        events = [event_from_wazuh(alert) for alert in fresh]
        new_events = [e for e in events if e.get("id") and e["id"] not in seen]

        # Advance the cursor to the newest alert we have seen, minus a small
        # safety margin so alerts sharing a timestamp are never skipped.
        newest_ts: Optional[datetime] = None
        for event in events:
            ts = event.get("ts")
            if isinstance(ts, datetime) and (newest_ts is None or ts > newest_ts):
                newest_ts = ts
        new_cursor = cursor
        if newest_ts is not None:
            new_cursor = (newest_ts - timedelta(seconds=5)).isoformat()

        pending = list(state.get("pending") or [])
        # Drop events that belong to an incident we already reported, so a
        # leftover burst can never trigger a duplicate investigation.
        dedupe_window = config.dedupe_window_minutes * 60
        pending = [
            e for e in pending
            if not state_store.is_recent_key(_incident_key(e), dedupe_window)
        ]
        for event in new_events:
            if event["id"] not in {p.get("id") for p in pending}:
                pending.append(event)

        # Bound the context buffer so a long quiet period between incidents
        # cannot grow memory (or the next prompt) without limit.
        if len(pending) > 500:
            pending = sorted(
                pending, key=lambda e: e.get("timestamp") or ""
            )[-500:]

        # Trigger selection: highest rule level wins; ties broken by recency.
        # `pending` keeps every collected event (including level-5 failures) so
        # the correlation window stays complete, but only alerts at or above
        # `trigger_min_level` are allowed to start a new investigation.
        trigger_floor = max(
            int(config.min_rule_level), int(getattr(config, "trigger_min_level", 0) or 0)
        )
        candidates = [
            e for e in pending
            if int(e.get("level") or 0) >= trigger_floor
        ]
        trigger = None
        if candidates:
            ranked = sorted(
                candidates,
                key=lambda e: (int(e.get("level") or 0), e.get("timestamp") or ""),
            )
            for candidate in reversed(ranked):
                key = _incident_key(candidate)
                if state_store.is_recent_key(key, dedupe_window):
                    continue
                trigger = candidate
                break

        # --- settle window -------------------------------------------------
        # Wazuh's correlation rules (e.g. 100002 "multiple failed logins",
        # level 12) fire *after* the individual level-5 failure events. If we
        # trigger on the first event we would triage a rule-5 PAM failure
        # instead of the brute-force verdict, and the report would miss the
        # rest of the burst. So we wait `settle_seconds` for the aggregate
        # rules to land, then re-rank and trigger on the highest severity.
        now = _now()
        burst_start = state.get("burst_start")
        if trigger is not None and not burst_start:
            # Latency is measured from the first event *of this burst*, which
            # is usually the first level-5 failure, not the level-12 verdict.
            related = [
                e for e in pending
                if e.get("id") == trigger.get("id")
                or (trigger.get("src_ip") and e.get("src_ip") == trigger.get("src_ip"))
                or (trigger.get("agent_id") and e.get("agent_id") == trigger.get("agent_id"))
            ]
            starts = [
                e.get("ts") for e in related
                if isinstance(e.get("ts"), datetime)
            ]
            if starts:
                earliest = min(starts)
                if earliest.tzinfo is None:
                    earliest = earliest.replace(tzinfo=timezone.utc)
                burst_start = earliest.isoformat()

        base_state = {
            "pending": pending,
            "cursor": new_cursor,
            "seen_ids": sorted(seen | set(e["id"] for e in new_events if e.get("id"))),
            "query_count": query_count,
            "errors": errors,
            "watch_cycles": int(state.get("watch_cycles") or 0) + 1,
        }

        if trigger is not None and config.settle_seconds > 0:
            deadline = _parse_iso(state.get("settle_until"))
            if deadline is None:
                deadline = now + timedelta(seconds=config.settle_seconds)
                return {
                    **base_state,
                    "status": "settling",
                    "settle_until": deadline.isoformat(),
                    "burst_start": burst_start,
                }
            if now < deadline:
                return {
                    **base_state,
                    "status": "settling",
                    "settle_until": deadline.isoformat(),
                    "burst_start": burst_start,
                }

        if trigger is not None:
            # Everything else stays pending for the next cycle.
            pending = [e for e in pending if e.get("id") != trigger.get("id")]
            detected_at = _now()
            new_ids = [e["id"] for e in new_events]
            return {
                **base_state,
                "pending": pending,
                "trigger": trigger,
                "detected_at": detected_at.isoformat(),
                "settle_until": None,
                "burst_start": burst_start,
                "status": "triggered",
            }

        return {
            **base_state,
            "status": "idle",
            "settle_until": None,
        }

    def supervisor(state: TriageState) -> dict:
        trigger = state.get("trigger") or {}
        plan = plan_pillars(trigger)
        return {"plan": plan, "status": "planned"}

    def identity_pillar(state: TriageState) -> dict:
        plan = state.get("plan") or {}
        if not (plan.get("identity") or {}).get("required"):
            return {"identity_context": {"available": False, "reason": "not required"}}
        if not config.use_identity_api:
            return {"identity_context": {"available": False, "reason": "disabled"}}
        try:
            from apis.clients import IdentityClient

            client = IdentityClient()
            trigger = state.get("trigger") or {}
            username = trigger.get("dst_user")
            context: dict[str, Any] = {"available": True}
            if username:
                profile = client.get_user_by_username(username)
                if profile:
                    context["profile"] = profile
                    history = client.login_history(profile["user_id"], limit=25)
                    context["login_history"] = history[-10:]
                    context["risk_factors"] = client.risk_factors(profile["user_id"])
            client.close()
            return {"identity_context": context}
        except Exception as exc:
            return {"identity_context": {"available": False, "reason": str(exc)[:200]}}

    def edr_pillar(state: TriageState) -> dict:
        plan = state.get("plan") or {}
        if not (plan.get("edr") or {}).get("required"):
            return {"edr_context": {"available": False, "reason": "not required"}}
        if not config.use_edr_api:
            return {"edr_context": {"available": False, "reason": "disabled"}}
        try:
            from apis.clients import EDRClient

            client = EDRClient()
            trigger = state.get("trigger") or {}
            hostname = trigger.get("agent_name") or ""
            context: dict[str, Any] = {"available": True, "endpoints": []}
            for endpoint in client.list_endpoints():
                haystack = f"{endpoint.get('hostname', '')}{endpoint.get('endpoint_id', '')}".lower()
                if hostname and hostname.lower() in haystack:
                    context["endpoints"].append(endpoint)
                    eid = endpoint["endpoint_id"]
                    context["processes"] = client.processes(eid, limit=50)[-10:]
                    context["network"] = client.network(eid, limit=50)[-10:]
                    context["files"] = client.files(eid, limit=50)[-10:]
                    break
            client.close()
            return {"edr_context": context}
        except Exception as exc:
            return {"edr_context": {"available": False, "reason": str(exc)[:200]}}

    def siem_pillar(state: TriageState) -> dict:
        """Pull every related event from the indexer and correlate it."""
        trigger = state.get("trigger") or {}
        window_start, window_end = build_window(
            trigger, config.lookback_minutes, config.post_window_minutes
        )
        query_count = int(state.get("query_count") or 0)
        errors: list = list(state.get("errors") or [])

        filters: list[dict] = []
        if trigger.get("agent_id"):
            filters.append({"agent.id": trigger["agent_id"]})
        if trigger.get("src_ip"):
            filters.append({"data.srcip": trigger["src_ip"]})
        if trigger.get("dst_user"):
            filters.append({"data.dstuser": trigger["dst_user"]})
        for group in (trigger.get("groups") or [])[:4]:
            filters.append({"rule.groups": group})

        collected: dict[str, dict] = {}
        for filt in filters:
            try:
                alerts = indexer.query_alerts(
                    filters=filt,
                    since=window_start.isoformat(),
                    until=window_end.isoformat(),
                    limit=config.max_correlated_alerts,
                )
                query_count += 1
            except Exception as exc:
                errors.append(f"correlation query failed for {filt}: {exc}")
                continue
            for alert in alerts:
                event = event_from_wazuh(alert)
                if event.get("id"):
                    collected[event["id"]] = event

        # The trigger itself must always be part of the correlation set.
        if trigger.get("id"):
            collected.setdefault(trigger["id"], trigger)

        correlation = correlate(
            trigger,
            list(collected.values()),
            window_start,
            window_end,
            burst_gap_seconds=config.burst_gap_seconds,
        )

        agents: list = []
        try:
            from siem.client import WazuhClient

            wc = WazuhClient()
            for agent in wc.list_agents():
                agents.append({
                    "id": agent.get("id"),
                    "name": agent.get("name"),
                    "ip": agent.get("ip"),
                    "version": agent.get("version"),
                    "status": agent.get("status"),
                })
            wc.close()
        except Exception:
            agents = []

        pillars = {
            "SIEM (Wazuh indexer, real)": f"available — {len(collected)} event(s) correlated",
            "Identity (mock Okta-shaped API)": _pillar_status(state.get("identity_context")),
            "EDR (mock Falcon-shaped API)": _pillar_status(state.get("edr_context")),
        }

        # Everything we correlated is now handled — do not let the next poll
        # cycle treat those alerts as brand new.
        seen = set(state.get("seen_ids") or [])
        seen.update(collected.keys())
        state_store.remember_key(_incident_key(trigger))

        return {
            "correlation": correlation,
            "agents": agents,
            "pillars": pillars,
            "seen_ids": sorted(seen),
            "query_count": query_count,
            "errors": errors,
            "status": "correlated",
        }

    def timeline_node(state: TriageState) -> dict:
        correlation = state.get("correlation") or {}
        return {"status": "timeline_ready",
                "metrics": {**(state.get("metrics") or {}),
                            "timeline_events": len(correlation.get("timeline") or [])}}

    def reason_node(state: TriageState) -> dict:
        """Ask the LLM to narrate the deterministic evidence pack."""
        trigger = state.get("trigger") or {}
        correlation = state.get("correlation") or {}
        metrics = state.get("metrics") or {}

        detected_at = _parse_iso(state.get("detected_at")) or _now()
        alert_ts = trigger.get("ts")
        if isinstance(alert_ts, datetime):
            if alert_ts.tzinfo is None:
                alert_ts = alert_ts.replace(tzinfo=timezone.utc)
            mttd = max(0.0, (detected_at - alert_ts).total_seconds())
        else:
            mttd = 0.0
        metrics = {**metrics, "mttd_seconds": mttd}

        # Honest end-to-end latency: measured from the *first* alert of the
        # burst, not from the aggregate rule that eventually triggered triage.
        burst_start = _parse_iso(state.get("burst_start"))
        if burst_start is not None:
            metrics["burst_mttd_seconds"] = max(
                0.0, (detected_at - burst_start).total_seconds()
            )
            metrics["settle_seconds_configured"] = float(config.settle_seconds)

        if llm is None:
            reason_text = config.missing_llm_reason() or "no LLM client configured"
            return {"analysis": {}, "metrics": metrics,
                    "errors": list(state.get("errors") or []) + [f"LLM skipped: {reason_text}"],
                    "status": "reason_skipped"}

        prompt = build_analysis_prompt(
            trigger,
            correlation,
            metrics,
            agents=state.get("agents"),
            max_events=config.max_events_in_prompt,
        )

        # Free-tier routes are flaky on strict JSON. Try the primary model,
        # then each configured fallback, and record which one answered.
        models = [llm.model]
        for fallback in getattr(config, "openrouter_fallback_models", ()) or ():
            if fallback not in models:
                models.append(fallback)

        analysis: dict = {}
        last_error: Optional[Exception] = None
        used_model = llm.model
        # Hard wall-clock budget for the whole narrative step. A stalled or
        # rate-limited free route must never freeze the daemon: once the
        # budget is gone we ship the deterministic report instead.
        budget = float(getattr(config, "llm_budget_seconds", 300.0) or 300.0)
        deadline = time.time() + budget
        attempts: list = []
        for candidate in models:
            remaining = deadline - time.time()
            if remaining <= 5:
                last_error = last_error or RuntimeError("LLM budget exhausted")
                break
            started = time.time()
            try:
                analysis = llm.chat_json(
                    [{"role": "user", "content": prompt}],
                    system=ANALYSIS_SYSTEM_PROMPT,
                    model=candidate,
                    timeout=min(float(getattr(config, "llm_timeout_seconds", 150.0)),
                                remaining),
                    deadline=deadline,
                )
                used_model = candidate
                last_error = None
                attempts.append({
                    "model": candidate,
                    "seconds": round(time.time() - started, 1),
                    "result": "ok",
                })
                break
            except OpenRouterError as exc:
                last_error = exc
                attempts.append({
                    "model": candidate,
                    "seconds": round(time.time() - started, 1),
                    "result": f"failed: {exc}"[:300],
                })
                detail = ""
                payload = getattr(exc, "payload", None) or {}
                if payload.get("finish_reason"):
                    detail += f" finish_reason={payload['finish_reason']}"
                head = (payload.get("content") or "").strip().replace("\n", " ")[:240]
                if head:
                    detail += f" head={head!r}"
                logger.warning("LLM model %s failed after %.1fs: %s%s",
                               candidate, time.time() - started, exc, detail)

        if last_error is not None or not analysis:
            logger.error("narrative engine unavailable after %d attempt(s) — "
                         "writing deterministic report only", len(attempts) or 1)
            return {
                "analysis": {},
                "metrics": {**metrics, "prompt_sha256": prompt_hash(prompt),
                            "llm_attempts": attempts},
                "errors": list(state.get("errors") or [])
                          + [f"LLM failed: {last_error or 'empty response'}"],
                "status": "reason_failed",
            }

        usage = llm.last_usage or {}
        metrics = {
            **metrics,
            "llm_model_used": used_model,
            "llm_attempts": attempts,
            "prompt_sha256": prompt_hash(prompt),
            "prompt_tokens": int(usage.get("prompt_tokens") or 0),
            "completion_tokens": int(usage.get("completion_tokens") or 0),
        }
        return {"analysis": analysis, "metrics": metrics, "status": "reasoned"}

    def report_node(state: TriageState) -> dict:
        trigger = state.get("trigger") or {}
        correlation = state.get("correlation") or {}
        analysis = state.get("analysis") or {}
        metrics = dict(state.get("metrics") or {})

        detected_at = _parse_iso(state.get("detected_at")) or _now()
        ready_at = _now()
        metrics["triage_seconds"] = max(0.0, (ready_at - detected_at).total_seconds())
        metrics["total_seconds"] = metrics["triage_seconds"] + metrics.get("mttd_seconds", 0.0)
        metrics["manual_baseline_seconds"] = float(config.manual_baseline_minutes * 60)
        metrics["time_saved_seconds"] = max(
            0.0, metrics["manual_baseline_seconds"] - metrics["total_seconds"]
        )
        metrics["poll_interval_seconds"] = config.poll_interval_seconds
        metrics["indexer_queries"] = int(state.get("query_count") or 0)
        metrics["run_id"] = state.get("run_id") or str(uuid.uuid4())
        metrics["evidence_sha256"] = evidence_hash({
            "trigger": trigger,
            "timeline": correlation.get("timeline"),
            "flags": correlation.get("flags"),
        })
        metrics["index_pattern"] = indexer.index_pattern

        incident_id = state.get("incident_id") or build_incident_id(
            state_store.next_incident_seq()
        )

        content = render_report(
            incident_id=incident_id,
            trigger=trigger,
            correlation=correlation,
            analysis=analysis,
            metrics=metrics,
            model=metrics.get("llm_model_used")
            or (llm.model if llm is not None else "deterministic-only (no LLM)"),
            generated_at=ready_at,
            agents=state.get("agents"),
            evidence_pillars=state.get("pillars"),
        )
        path = write_report(content, config.reports_dir, incident_id)

        html_path: Optional[Path] = None
        try:
            html_content = render_report_html(
                incident_id=incident_id,
                trigger=trigger,
                correlation=correlation,
                analysis=analysis,
                metrics=metrics,
                model=metrics.get("llm_model_used")
                or (llm.model if llm is not None else "deterministic-only (no LLM)"),
                generated_at=ready_at,
                agents=state.get("agents"),
                evidence_pillars=state.get("pillars"),
            )
            html_path = write_report_html(html_content, config.reports_dir, incident_id)
        except Exception as exc:
            logger.warning("HTML report rendering failed: %s", exc)

        state_store.record_incident({
            "incident_id": incident_id,
            "report": str(path),
            "report_html": str(html_path) if html_path else None,
            "at": ready_at.isoformat(),
            "trigger_rule": trigger.get("rule_id"),
            "severity": analysis.get("severity"),
        })
        state_store.save()

        return {
            "incident_id": incident_id,
            "report_path": str(path),
            "report_html_path": str(html_path) if html_path else "",
            "metrics": metrics,
            "status": "report_ready",
        }

    def notify_node(state: TriageState) -> dict:
        if not config.notify:
            return {"status": "notified"}
        try:
            from agent.notifier import notify_report_ready

            trigger = state.get("trigger") or {}
            analysis = state.get("analysis") or {}
            severity = analysis.get("severity") or "Unrated"
            html_path = state.get("report_html_path") or ""
            message = (
                f"{state.get('incident_id')} — {severity} — rule "
                f"{trigger.get('rule_id')} on {trigger.get('agent_name')}. "
                f"Report ready ({html_path or state.get('report_path')})"
            )
            notify_report_ready(
                title=config.notify_title,
                message=message,
                report_path=state.get("report_path") or None,
                sound=config.notify_sound,
                clickable=config.notify_open_report,
                html_path=Path(html_path) if html_path else None,
            )
        except Exception as exc:
            return {"status": "notified",
                    "errors": list(state.get("errors") or []) + [f"notification failed: {exc}"]}
        return {"status": "notified"}

    graph = StateGraph(TriageState)
    graph.add_node("watch", watch)
    graph.add_node("supervisor", supervisor)
    graph.add_node("identity", identity_pillar)
    graph.add_node("edr", edr_pillar)
    graph.add_node("siem", siem_pillar)
    graph.add_node("timeline", timeline_node)
    graph.add_node("reason", reason_node)
    graph.add_node("report", report_node)
    graph.add_node("notify", notify_node)

    graph.add_edge(START, "watch")
    graph.add_conditional_edges(
        "watch",
        lambda state: "investigate" if state.get("trigger") else "wait",
        {"investigate": "supervisor", "wait": END},
    )
    graph.add_edge("supervisor", "identity")
    graph.add_edge("identity", "edr")
    graph.add_edge("edr", "siem")
    graph.add_edge("siem", "timeline")
    graph.add_edge("timeline", "reason")
    graph.add_edge("reason", "report")
    graph.add_edge("report", "notify")
    graph.add_edge("notify", END)

    return graph.compile()


def _pillar_status(context: Optional[dict]) -> str:
    if not context:
        return "not queried"
    if not context.get("available"):
        return f"unavailable — {context.get('reason', 'unknown')}"
    return "available"


def _incident_key(event: dict[str, Any]) -> str:
    """Group key used to avoid re-reporting the same incident twice."""
    agent = event.get("agent_id") or event.get("agent_name") or "unknown"
    source = event.get("src_ip") or "-"
    return f"{agent}|{source}"
