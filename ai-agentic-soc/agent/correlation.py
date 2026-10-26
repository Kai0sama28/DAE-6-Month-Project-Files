"""Deterministic correlation of Wazuh alerts into a single incident view.

The agent's claim is "one analyst, thousands of logs, one timeline". That
claim only holds if the *facts* are extracted in code and the LLM is only
allowed to narrate them. This module therefore does all the counting,
grouping and linking; :mod:`agent.report` turns the result into Markdown and
the LLM adds the narrative on top.

Correlation relations (an event can carry several):

``SAME_AGENT``      same monitored endpoint as the trigger
``SAME_SOURCE_IP``  same source address as the trigger (the attacker pivot)
``SAME_USER``       same target account as the trigger
``SAME_RULE_GROUP`` same Wazuh rule group (same detection family)
``PRIOR``           earlier than the trigger, inside the lookback window
``POST``            later than the trigger, inside the post window
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional

from agent.events import PHASE_LABELS, event_sort_key, event_timestamp_text

# Rules that mean "a credential was actually used", independent of the
# correlation rule that fired.
SUCCESS_RULE_IDS = {"5715", "40112", "100030"}
FAILURE_RULE_IDS = {"5760", "5763", "5712", "5758", "5551", "40111", "100031", "5503"}
FIM_RULE_IDS = {"550", "590", "810", "860", "870"}
PRIVILEGE_RULE_IDS = {"5401", "5402", "5403", "5404"}
SESSION_RULE_IDS = {"5501", "5502"}
SELF_SOURCE_RULE_IDS = {"100002"}


def relations_for(event: dict[str, Any], trigger: dict[str, Any]) -> list[str]:
    """Return the correlation relations between ``event`` and ``trigger``."""
    relations: list[str] = []
    if event.get("id") and event.get("id") == trigger.get("id"):
        relations.append("TRIGGER")

    if trigger.get("agent_id") and event.get("agent_id") == trigger.get("agent_id"):
        relations.append("SAME_AGENT")
    if trigger.get("src_ip") and event.get("src_ip") == trigger.get("src_ip"):
        relations.append("SAME_SOURCE_IP")
    if trigger.get("dst_user") and event.get("dst_user") == trigger.get("dst_user"):
        relations.append("SAME_USER")

    trigger_groups = set(trigger.get("groups") or [])
    event_groups = set(event.get("groups") or [])
    if trigger_groups and (trigger_groups & event_groups):
        relations.append("SAME_RULE_GROUP")

    event_ts = event.get("ts")
    trigger_ts = trigger.get("ts")
    if isinstance(event_ts, datetime) and isinstance(trigger_ts, datetime):
        if event_ts < trigger_ts:
            relations.append("PRIOR")
        elif event_ts > trigger_ts:
            relations.append("POST")
    return relations


def correlate(
    trigger: dict[str, Any],
    related: Iterable[dict[str, Any]],
    window_start: Optional[datetime] = None,
    window_end: Optional[datetime] = None,
    burst_gap_seconds: float = 120.0,
) -> dict[str, Any]:
    """Correlate ``related`` events against ``trigger``.

    Returns a plain dict so it can be serialised into the LangGraph state
    and into the report.
    """
    related = list(related)
    trigger_id = trigger.get("id")

    by_id: dict[str, dict[str, Any]] = {}
    for event in related:
        enriched = dict(event)
        enriched["relations"] = relations_for(enriched, trigger)
        key = enriched.get("id") or f"anon-{id(enriched)}"
        by_id[key] = enriched

    events = sorted(by_id.values(), key=event_sort_key)

    # --- scope the window -------------------------------------------------
    scoped: list[dict[str, Any]] = []
    for event in events:
        ts = event.get("ts")
        if window_start and isinstance(ts, datetime) and ts < window_start:
            continue
        if window_end and isinstance(ts, datetime) and ts > window_end:
            continue
        scoped.append(event)
    events = scoped

    relation_counts = Counter()
    for event in events:
        for relation in event.get("relations") or []:
            relation_counts[relation] += 1

    phase_counts = Counter(event.get("phase", "OTHER") for event in events)
    rule_counts = Counter(
        (event.get("rule_id") or "?", event.get("title") or "Unknown alert",
         int(event.get("level") or 0))
        for event in events
    )
    agent_counts = Counter(
        (event.get("agent_id") or "?", event.get("agent_name") or "unknown")
        for event in events
    )
    source_counts = Counter(event.get("src_ip") or "-" for event in events)
    user_counts = Counter(event.get("dst_user") or "-" for event in events)

    phases_present = [phase for phase in PHASE_LABELS if phase_counts.get(phase)]

    # --- attack narrative flags (deterministic, not LLM-invented) ---------
    success_events = [e for e in events if e.get("rule_id") in SUCCESS_RULE_IDS]
    failure_events = [e for e in events if e.get("rule_id") in FAILURE_RULE_IDS]
    privilege_events = [e for e in events if e.get("rule_id") in PRIVILEGE_RULE_IDS]
    session_events = [e for e in events if e.get("rule_id") in SESSION_RULE_IDS]
    fim_events = [e for e in events if e.get("rule_id") in FIM_RULE_IDS]

    # Wazuh's `rule.firedtimes` is a cumulative per-rule counter, so the
    # attempt volume is the highest counter value, not the sum. Several
    # decoders (sshd / PAM / syslog-auth) can report the same underlying
    # attempt, so the distinct attempt *moments* are reported alongside.
    firedtimes_by_rule: dict[str, int] = {}
    for event in failure_events:
        rid = str(event.get("rule_id") or "?")
        value = int(event.get("firedtimes") or 0)
        if value > firedtimes_by_rule.get(rid, 0):
            firedtimes_by_rule[rid] = value
    total_failures = max(firedtimes_by_rule.values()) if firedtimes_by_rule else 0

    failure_moments = {
        (
            event_timestamp_text(event)[:19],
            event.get("src_ip") or "-",
            event.get("dst_user") or "-",
        )
        for event in failure_events
    }

    mitre_ids: list[str] = []
    mitre_tactics: list[str] = []
    mitre_names: list[str] = []
    for event in events:
        for technique in event.get("mitre") or []:
            if technique not in mitre_ids:
                mitre_ids.append(technique)
        for tactic in event.get("mitre_tactics") or []:
            if tactic not in mitre_tactics:
                mitre_tactics.append(tactic)
        for name in event.get("mitre_names") or []:
            if name not in mitre_names:
                mitre_names.append(name)

    timestamps = [e["ts"] for e in events if isinstance(e.get("ts"), datetime)]
    first_seen = min(timestamps) if timestamps else None
    last_seen = max(timestamps) if timestamps else None
    duration = (last_seen - first_seen).total_seconds() if first_seen and last_seen else 0.0

    # --- burst delineation -------------------------------------------------
    # A correlation window can contain several *separate* attack bursts (the
    # same attacker coming back later). Splitting on a silence gap keeps the
    # reported "attack duration" honest instead of stretching it across
    # unrelated activity.
    bursts = _split_bursts(events, burst_gap_seconds)
    trigger_burst: dict[str, Any] = {}
    for burst in bursts:
        if trigger_id and any(e.get("id") == trigger_id for e in burst["events"]):
            trigger_burst = burst
            break
    if not trigger_burst and bursts:
        trigger_burst = bursts[-1]
    burst_start = trigger_burst.get("start")
    burst_end = trigger_burst.get("end")
    burst_duration = (
        (burst_end - burst_start).total_seconds()
        if isinstance(burst_start, datetime) and isinstance(burst_end, datetime)
        else 0.0
    )
    burst_ids = {e.get("id") for e in trigger_burst.get("events") or []}
    for entry in events:
        entry["in_trigger_burst"] = entry.get("id") in burst_ids

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        grouped[event.get("phase", "OTHER")].append(event)

    timeline = [
        {
            "id": event.get("id", ""),
            "timestamp": event_timestamp_text(event),
            "ts": event.get("ts"),
            "phase": event.get("phase", "OTHER"),
            "phase_label": PHASE_LABELS.get(event.get("phase", "OTHER"), "Other activity"),
            "rule_id": event.get("rule_id", ""),
            "level": event.get("level", 0),
            "title": event.get("title", ""),
            "agent": event.get("agent_name") or event.get("agent_id") or "",
            "src_ip": event.get("src_ip", ""),
            "dst_user": event.get("dst_user", ""),
            "firedtimes": event.get("firedtimes", 0),
            "relations": event.get("relations") or [],
            "in_trigger_burst": bool(event.get("in_trigger_burst")),
            "log": event.get("full_log", ""),
        }
        for event in events
    ]

    return {
        "trigger": trigger,
        "events": events,
        "timeline": timeline,
        "event_count": len(events),
        "relation_counts": dict(relation_counts),
        "phase_counts": dict(phase_counts),
        "phases_present": phases_present,
        "rule_counts": [
            {"rule_id": rid, "title": title, "level": level, "count": count}
            for (rid, title, level), count in rule_counts.most_common()
        ],
        "agent_counts": [
            {"agent_id": aid, "agent_name": aname, "count": count}
            for (aid, aname), count in agent_counts.most_common()
        ],
        "source_counts": dict(source_counts.most_common(10)),
        "user_counts": dict(user_counts.most_common(10)),
        "window_start": window_start,
        "window_end": window_end,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "duration_seconds": duration,
        "burst_count": len(bursts),
        "bursts": [
            {
                "index": i,
                "start": b.get("start"),
                "end": b.get("end"),
                "event_count": len(b.get("events") or []),
                "is_trigger_burst": b is trigger_burst,
            }
            for i, b in enumerate(bursts, start=1)
        ],
        "trigger_burst_start": burst_start,
        "trigger_burst_end": burst_end,
        "trigger_burst_duration_seconds": burst_duration,
        "trigger_burst_event_count": len(trigger_burst.get("events") or []),
        "mitre_ids": mitre_ids,
        "mitre_tactics": mitre_tactics,
        "mitre_names": mitre_names,
        "flags": {
            "auth_success_observed": bool(success_events),
            "auth_failures_observed": bool(failure_events),
            "failed_attempt_count": total_failures,
            "failed_attempt_counter_by_rule": firedtimes_by_rule,
            "indexed_failure_events": len(failure_events),
            "distinct_failure_moments": len(failure_moments),
            "privilege_change_observed": bool(privilege_events),
            "file_integrity_change_observed": bool(fim_events),
            "session_activity_observed": bool(session_events),
            "source_equals_agent_ip": bool(
                trigger.get("src_ip") and trigger.get("src_ip") == trigger.get("agent_ip")
            ),
            "success_events": len(success_events),
            "privilege_events": len(privilege_events),
            "fim_events": len(fim_events),
        },
    }


def build_window(
    trigger: dict[str, Any],
    lookback_minutes: int,
    post_minutes: int,
) -> tuple[datetime, datetime]:
    """Return the (start, end) correlation window around a trigger event."""
    ts = trigger.get("ts")
    if not isinstance(ts, datetime):
        now = datetime.now(timezone.utc)
        return now - timedelta(minutes=lookback_minutes), now + timedelta(minutes=post_minutes)
    return (
        ts - timedelta(minutes=lookback_minutes),
        ts + timedelta(minutes=post_minutes),
    )


def _split_bursts(
    events: list[dict[str, Any]],
    gap_seconds: float = 120.0,
) -> list[dict[str, Any]]:
    """Split a chronologically sorted event list into bursts.

    A new burst starts when the silence between two consecutive events is
    longer than ``gap_seconds``. That keeps "attack duration" scoped to the
    activity that actually belongs together.
    """
    bursts: list[dict[str, Any]] = []
    current: list[dict[str, Any]] = []
    previous_ts: Optional[datetime] = None

    for event in events:
        ts = event.get("ts")
        if not isinstance(ts, datetime):
            continue
        if previous_ts is not None and (ts - previous_ts).total_seconds() > gap_seconds:
            bursts.append({"events": current})
            current = []
        current.append(event)
        previous_ts = ts

    if current:
        bursts.append({"events": current})

    for burst in bursts:
        stamps = [e["ts"] for e in burst["events"] if isinstance(e.get("ts"), datetime)]
        burst["start"] = min(stamps) if stamps else None
        burst["end"] = max(stamps) if stamps else None
    return bursts
