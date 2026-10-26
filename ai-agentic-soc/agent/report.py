"""Incident report generation.

The report is built in two halves:

* **Deterministic sections** (facts): every count, timestamp, rule id and
  relation comes from :mod:`agent.correlation`. These can be re-derived from
  the indexer by a reviewer.
* **Narrative sections** (interpretation): the LLM writes the executive
  summary, the attack story, the MITRE mapping and the recommendations.

That split is deliberate — the LLM is never allowed to invent a fact, only to
explain the facts it was given. If the LLM call fails, the report is still
produced from the deterministic half alone.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from agent.events import PHASE_LABELS

SEVERITY_ORDER = ["Informational", "Low", "Medium", "High", "Critical"]

ANALYSIS_SYSTEM_PROMPT = """\
You are the senior analyst of an AI-agentic SOC triage engine. You receive a
Wazuh alert together with a deterministic correlation of every related log
event that the agent retrieved from the SIEM. Your job is to write the
analyst-facing part of the incident report.

Hard rules:
1. Use ONLY the events, counts, timestamps, rule ids, IPs, users and hosts
   provided. Never invent an event, a timestamp, an IP, a user or a technique.
2. If the evidence does not establish something, say so explicitly in
   `data_gaps` or `false_positive_assessment`. A brute-force that was blocked
   must never be described as a successful compromise.
3. `severity` must be exactly one of: Informational, Low, Medium, High, Critical.
4. `confidence` must be exactly one of: High, Medium, Low.
5. `mitre_mapping` must only contain ATT&CK techniques that appear in the
   provided evidence or are the standard mapping for the observed activity.
6. `recommended_actions` and `containment_recommendations` are ADVICE ONLY.
   The engine never executes containment automatically; a human analyst approves.
7. Be concise and specific. No filler, no restating the prompt.
8. Write plain prose. Do not use markdown headings inside string values.

Return a single JSON object with exactly these keys:
{
  "executive_summary": string,
  "severity": string,
  "severity_rationale": string,
  "confidence": string,
  "attack_narrative": string,
  "key_findings": [string],
  "mitre_mapping": [{"technique_id": string, "technique_name": string,
                     "tactic": string, "evidence": string}],
  "recommended_actions": [{"priority": string, "action": string, "rationale": string}],
  "containment_recommendations": [string],
  "false_positive_assessment": string,
  "data_gaps": [string]
}
"""


def _fmt_ts(value: Any) -> str:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + "Z"
    return str(value or "unknown")


def _human_duration(seconds: float) -> str:
    seconds = max(0.0, float(seconds))
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, secs = divmod(int(seconds), 60)
    if minutes < 60:
        return f"{minutes}m {secs:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes:02d}m {secs:02d}s"


def build_incident_id(sequence: int, when: Optional[datetime] = None) -> str:
    when = when or datetime.now(timezone.utc)
    return f"SOC-{when.strftime('%Y%m%d')}-{sequence:03d}"


def build_analysis_prompt(
    trigger: dict[str, Any],
    correlation: dict[str, Any],
    metrics: dict[str, Any],
    agents: Optional[list[dict[str, Any]]] = None,
    max_events: int = 250,
) -> str:
    """Render the evidence pack the LLM reasons over."""
    flags = correlation.get("flags") or {}
    lines: list[str] = []

    lines.append("## TRIGGER ALERT")
    lines.append(f"- alert id: {trigger.get('id') or 'n/a'}")
    lines.append(f"- timestamp (UTC): {trigger.get('timestamp') or 'n/a'}")
    lines.append(f"- rule: {trigger.get('rule_id')} (level {trigger.get('level')}) - {trigger.get('title')}")
    lines.append(f"- rule groups: {', '.join(trigger.get('groups') or []) or 'none'}")
    lines.append(f"- agent: {trigger.get('agent_name')} (id {trigger.get('agent_id')}, ip {trigger.get('agent_ip')})")
    lines.append(f"- source ip: {trigger.get('src_ip') or 'n/a'}")
    lines.append(f"- target user: {trigger.get('dst_user') or 'n/a'}")
    lines.append(f"- MITRE: {', '.join(trigger.get('mitre') or []) or 'none tagged on the rule'}")
    if trigger.get("full_log"):
        lines.append(f"- raw log: {trigger['full_log'][:600]}")

    lines.append("")
    lines.append("## CORRELATION FACTS (computed, do not recompute)")
    lines.append(f"- correlated events: {correlation.get('event_count')}")
    lines.append(
        "- relations: "
        + (", ".join(f"{k}={v}" for k, v in (correlation.get("relation_counts") or {}).items()) or "none")
    )
    lines.append(
        "- events per phase: "
        + (", ".join(f"{k}={v}" for k, v in (correlation.get("phase_counts") or {}).items()) or "none")
    )
    lines.append("- events per rule:")
    for row in (correlation.get("rule_counts") or [])[:20]:
        lines.append(
            f"    - rule {row['rule_id']} (level {row.get('level', '?')}) "
            f"x{row['count']}: {row['title']}"
        )
    lines.append("- source addresses seen: " + (", ".join(
        f"{ip} x{count}" for ip, count in (correlation.get("source_counts") or {}).items()) or "none"))
    lines.append("- accounts seen: " + (", ".join(
        f"{user} x{count}" for user, count in (correlation.get("user_counts") or {}).items()) or "none"))
    lines.append(
        f"- observation window: {_fmt_ts(correlation.get('first_seen'))} -> "
        f"{_fmt_ts(correlation.get('last_seen'))} "
        f"({_human_duration(correlation.get('duration_seconds') or 0)})"
    )
    lines.append("- deterministic flags:")
    for key, value in flags.items():
        lines.append(f"    - {key}: {value}")
    lines.append(
        "  NOTE: failed_attempt_count is the highest rule.firedtimes counter among the "
        "failure rules (firedtimes is cumulative per rule and must NOT be summed). "
        "indexed_failure_events counts alert documents; distinct_failure_moments counts "
        "unique (second, source, user) tuples. Wazuh decodes the same failed login "
        "through sshd, PAM and syslog-auth, so the three numbers differ legitimately. "
        "Quote the right one for the claim you make."
    )
    if flags.get("source_equals_agent_ip"):
        lines.append(
            "  NOTE: the source IP equals the monitored host's own IP, so these attempts "
            "were generated on the monitored endpoint itself, not from a separate remote "
            "host. Do not describe the source as an external attacker."
        )
    if correlation.get("mitre_ids"):
        lines.append(
            "- MITRE techniques present in the correlated events: "
            + ", ".join(correlation["mitre_ids"])
        )
    if agents:
        lines.append("- monitored agents: " + "; ".join(
            f"{a.get('name')} (id {a.get('id')}, ip {a.get('ip')}, {a.get('status')})"
            for a in agents[:10]
        ))

    lines.append("")
    lines.append("## TIMELINE (UTC, oldest first)")
    timeline = correlation.get("timeline") or []
    for entry in timeline[:max_events]:
        marker = " *" if "TRIGGER" in (entry.get("relations") or []) else ""
        lines.append(
            f"- {entry['timestamp']} | {entry['phase']} | rule {entry['rule_id']} "
            f"lvl {entry['level']} | {entry['title']} | agent={entry['agent']} "
            f"src={entry['src_ip'] or '-'} user={entry['dst_user'] or '-'}"
            f"{' | firedtimes=' + str(entry['firedtimes']) if entry.get('firedtimes') else ''}"
            f"{marker}"
        )
    if len(timeline) > max_events:
        lines.append(f"- ... {len(timeline) - max_events} further events omitted from this prompt")

    lines.append("")
    lines.append("## DETECTION LATENCY")
    lines.append(f"- Wazuh alert time to agent detection: {_human_duration(metrics.get('mttd_seconds') or 0)}")
    lines.append(f"- agent detection to report ready: {_human_duration(metrics.get('triage_seconds') or 0)}")

    return "\n".join(lines)


def render_report(
    incident_id: str,
    trigger: dict[str, Any],
    correlation: dict[str, Any],
    analysis: Optional[dict[str, Any]],
    metrics: dict[str, Any],
    model: str,
    generated_at: Optional[datetime] = None,
    agents: Optional[list[dict[str, Any]]] = None,
    evidence_pillars: Optional[dict[str, Any]] = None,
) -> str:
    """Render the final Markdown incident report."""
    generated_at = generated_at or datetime.now(timezone.utc)
    analysis = analysis or {}
    flags = correlation.get("flags") or {}

    out: list[str] = []
    out.append(f"# Incident Report {incident_id}")
    out.append("")
    out.append(
        f"> **Generated by:** AI-Agentic SOC Triage Engine "
        f"(automated triage, human-in-the-loop)  ")
    out.append(f"> **Generated at (UTC):** {_fmt_ts(generated_at)}  ")
    out.append(f"> **Reasoning model:** `{model}`  ")
    out.append(f"> **Report status:** DRAFT — requires analyst review before any response action")
    out.append("")

    # --- 1. executive summary -------------------------------------------
    out.append("## 1. Executive Summary")
    out.append("")
    summary = (analysis.get("executive_summary") or "").strip()
    if not summary:
        summary = (
            f"Automated triage detected Wazuh rule {trigger.get('rule_id')} "
            f"(level {trigger.get('level')}) on agent {trigger.get('agent_name')} at "
            f"{_fmt_ts(trigger.get('ts'))}. {correlation.get('event_count', 0)} related events "
            "were correlated. The narrative engine was unavailable for this report, so only "
            "the deterministic correlation facts are presented."
        )
    out.append(summary)
    out.append("")

    severity = analysis.get("severity") or "Unrated"
    confidence = analysis.get("confidence") or "n/a"
    out.append("| Field | Value |")
    out.append("|---|---|")
    out.append(f"| Incident ID | `{incident_id}` |")
    out.append(f"| Severity | **{severity}** |")
    out.append(f"| Analyst confidence | {confidence} |")
    out.append(f"| Affected host | {trigger.get('agent_name') or 'n/a'} "
               f"(agent `{trigger.get('agent_id') or 'n/a'}`, ip {trigger.get('agent_ip') or 'n/a'}) |")
    out.append(f"| Source address | `{trigger.get('src_ip') or 'n/a'}` |")
    out.append(f"| Target account | `{trigger.get('dst_user') or 'n/a'}` |")
    out.append(f"| Detection rule | `{trigger.get('rule_id')}` (level {trigger.get('level')}) |")
    out.append(f"| Correlated events | {correlation.get('event_count', 0)} |")
    out.append(f"| Observation window | {_fmt_ts(correlation.get('first_seen'))} → "
               f"{_fmt_ts(correlation.get('last_seen'))} |")
    out.append(f"| **Attack duration** (trigger burst) | "
               f"**{_human_duration(correlation.get('trigger_burst_duration_seconds') or 0)}** |")
    out.append(f"| Attack burst | {_fmt_ts(correlation.get('trigger_burst_start'))} → "
               f"{_fmt_ts(correlation.get('trigger_burst_end'))} "
               f"({correlation.get('trigger_burst_event_count', 0)} event(s)) |")
    if (correlation.get("burst_count") or 0) > 1:
        out.append(f"| Separate bursts inside the window | "
                   f"{correlation.get('burst_count')} |")
    out.append("")
    if analysis.get("severity_rationale"):
        out.append(f"**Severity rationale:** {analysis['severity_rationale']}")
        out.append("")

    # --- 2. detection facts ----------------------------------------------
    out.append("## 2. Detection Facts")
    out.append("")
    out.append("| Fact | Value |")
    out.append("|---|---|")
    out.append(f"| Wazuh alert id | `{trigger.get('id') or 'n/a'}` |")
    out.append(f"| Wazuh timestamp | {_fmt_ts(trigger.get('ts'))} |")
    out.append(f"| Rule | `{trigger.get('rule_id')}` — {trigger.get('title')} |")
    out.append(f"| Rule groups | {', '.join(trigger.get('groups') or []) or 'none'} |")
    out.append(f"| Rule MITRE tags | {', '.join(trigger.get('mitre') or []) or 'none'} |")
    out.append(f"| Agent | {trigger.get('agent_name')} (`{trigger.get('agent_id')}`) |")
    out.append(f"| Agent IP | {trigger.get('agent_ip') or 'n/a'} |")
    out.append(f"| Source IP | {trigger.get('src_ip') or 'n/a'} |")
    out.append(f"| Target user | {trigger.get('dst_user') or 'n/a'} |")
    out.append(f"| Fired times | {trigger.get('firedtimes') or 0} |")
    out.append("")
    if trigger.get("full_log"):
        out.append("Raw log of the trigger event:")
        out.append("")
        out.append("```")
        out.append(trigger["full_log"][:1500])
        out.append("```")
        out.append("")

    # --- 3. key findings -------------------------------------------------
    out.append("## 3. Key Findings")
    out.append("")
    findings = analysis.get("key_findings") or []
    if findings:
        for finding in findings:
            out.append(f"- {finding}")
    else:
        out.append(
            "_The narrative engine was unavailable for this run, so no free-text "
            "findings were produced. The deterministic findings are in sections 4 and 5._"
        )
    out.append("")

    # --- 4. correlation ---------------------------------------------------
    out.append("## 4. Log Correlation")
    out.append("")
    out.append(
        "The agent queried the Wazuh indexer and linked every event that shares the "
        "affected endpoint, the source address, the target account, or the rule family "
        "with the trigger, inside the investigation window."
    )
    out.append("")
    out.append("**Relation breakdown**")
    out.append("")
    out.append("| Relation | Events |")
    out.append("|---|---|")
    relation_labels = {
        "TRIGGER": "Trigger event",
        "SAME_AGENT": "Same monitored endpoint",
        "SAME_SOURCE_IP": "Same source address",
        "SAME_USER": "Same target account",
        "SAME_RULE_GROUP": "Same rule family",
        "PRIOR": "Occurred before the trigger",
        "POST": "Occurred after the trigger",
    }
    for relation, count in (correlation.get("relation_counts") or {}).items():
        out.append(f"| {relation_labels.get(relation, relation)} (`{relation}`) | {count} |")
    out.append("")

    out.append("**Events by phase**")
    out.append("")
    out.append("| Phase | Meaning | Events |")
    out.append("|---|---|---|")
    for phase, count in (correlation.get("phase_counts") or {}).items():
        out.append(f"| `{phase}` | {PHASE_LABELS.get(phase, '')} | {count} |")
    out.append("")

    out.append("**Events by rule**")
    out.append("")
    out.append("| Rule | Level | Description | Events |")
    out.append("|---|---|---|---|")
    for row in (correlation.get("rule_counts") or [])[:25]:
        out.append(
            f"| `{row['rule_id']}` | {row.get('level', '—')} | {row['title']} | {row['count']} |"
        )
    out.append("")

    if correlation.get("source_counts"):
        out.append("**Source addresses**")
        out.append("")
        for ip, count in correlation["source_counts"].items():
            out.append(f"- `{ip}` — {count} event(s)")
        out.append("")

    out.append("**Deterministic outcome flags**")
    out.append("")
    out.append("| Flag | Value |")
    out.append("|---|---|")
    for key, value in flags.items():
        out.append(f"| `{key}` | {value} |")
    out.append("")
    out.append(
        "> **Counting note.** `failed_attempt_count` is the highest `rule.firedtimes` "
        "counter among the failure rules, because Wazuh's `firedtimes` is a cumulative "
        "per-rule counter and must not be summed across rules. "
        "`indexed_failure_events` counts the alert documents, and "
        "`distinct_failure_moments` counts unique (second, source, user) tuples — Wazuh "
        "decodes the same failed login through sshd, PAM and syslog-auth, so those three "
        "numbers legitimately differ."
    )
    out.append("")
    if flags.get("source_equals_agent_ip"):
        out.append(
            "> **Self-originated traffic.** The source address of these events is identical "
            "to the monitored host's own IP address, so the authentication attempts were "
            "generated on the monitored endpoint itself (lab tooling or a local process), "
            "not by a separate remote host."
        )
        out.append("")

    # --- 5. timeline ------------------------------------------------------
    out.append("## 5. Incident Timeline")
    out.append("")
    out.append("| # | Timestamp (UTC) | Phase | Rule | Lvl | Event | Host | Source | User | Burst |")
    out.append("|---|---|---|---|---|---|---|---|---|---|")
    for idx, entry in enumerate(correlation.get("timeline") or [], start=1):
        title = str(entry.get("title") or "").replace("|", "\\|")
        burst = "attack" if entry.get("in_trigger_burst") else "context"
        out.append(
            f"| {idx} | {entry['timestamp']} | `{entry['phase']}` | `{entry['rule_id']}` | "
            f"{entry['level']} | {title} | {entry.get('agent') or '-'} | "
            f"{entry.get('src_ip') or '-'} | {entry.get('dst_user') or '-'} | {burst} |"
        )
    out.append("")
    out.append("> `attack` marks the burst the trigger belongs to; `context` marks "
               "related activity in the same window from an earlier or separate burst.")
    out.append("")

    # --- 6. narrative -----------------------------------------------------
    out.append("## 6. Attack Narrative")
    out.append("")
    narrative = (analysis.get("attack_narrative") or "").strip()
    if narrative:
        out.append(narrative)
    else:
        out.append(
            "_Narrative engine unavailable — see the deterministic sections above._"
        )
    out.append("")

    # --- 7. MITRE ---------------------------------------------------------
    out.append("## 7. MITRE ATT&CK Mapping")
    out.append("")
    observed = correlation.get("mitre_ids") or []
    if observed:
        out.append(
            "Techniques tagged on the correlated Wazuh rules: "
            + ", ".join(f"`{t}`" for t in observed)
        )
        out.append("")
    mapping = analysis.get("mitre_mapping") or []
    if mapping:
        out.append("| Technique | Name | Tactic | Supporting evidence |")
        out.append("|---|---|---|---|")
        for row in mapping:
            out.append(
                f"| `{row.get('technique_id', '')}` | {row.get('technique_name', '')} | "
                f"{row.get('tactic', '')} | {row.get('evidence', '')} |"
            )
        out.append("")
    else:
        out.append("_No ATT&CK mapping produced by the narrative engine._")
        out.append("")

    # --- 8. risk ----------------------------------------------------------
    out.append("## 8. Risk Assessment")
    out.append("")
    out.append(
        f"- **Severity:** {severity}"
        + (f" — {analysis['severity_rationale']}" if analysis.get("severity_rationale") else "")
    )
    out.append(f"- **Analyst confidence:** {confidence}")
    fp = (analysis.get("false_positive_assessment") or "").strip()
    if fp:
        out.append(f"- **False-positive assessment:** {fp}")
    out.append("")

    # --- 9. recommendations ------------------------------------------------
    out.append("## 9. Recommended Actions")
    out.append("")
    out.append(
        "> These are **recommendations only**. The agent never executes containment, "
        "and a human analyst must approve any response action."
    )
    out.append("")
    actions = analysis.get("recommended_actions") or []
    if actions:
        out.append("| Priority | Action | Rationale |")
        out.append("|---|---|---|")
        for row in actions:
            out.append(
                f"| {row.get('priority', 'Medium')} | {row.get('action', '')} | "
                f"{row.get('rationale', '')} |"
            )
        out.append("")
    containment = analysis.get("containment_recommendations") or []
    if containment:
        out.append("**Containment options (pending analyst approval)**")
        out.append("")
        for item in containment:
            out.append(f"- {item}")
        out.append("")

    # --- 10. gaps ---------------------------------------------------------
    gaps = analysis.get("data_gaps") or []
    out.append("## 10. Evidence Gaps and Caveats")
    out.append("")
    if gaps:
        for gap in gaps:
            out.append(f"- {gap}")
    else:
        out.append("- No gaps were reported by the narrative engine.")
    if evidence_pillars:
        for pillar, status in evidence_pillars.items():
            out.append(f"- {pillar}: {status}")
    out.append("")

    # --- 11. metrics -------------------------------------------------------
    out.append("## 11. Detection and Triage Metrics")
    out.append("")
    out.append("| Metric | Value |")
    out.append("|---|---|")
    out.append(f"| MTTD (Wazuh alert → agent detection) | **{_human_duration(metrics.get('mttd_seconds') or 0)}** |")
    if metrics.get("burst_mttd_seconds") is not None:
        out.append(f"| End-to-end latency (first alert of the burst → report) | "
                   f"**{_human_duration(metrics.get('burst_mttd_seconds') or 0)}** |")
        out.append(f"| Settle window used before triage | "
                   f"{_human_duration(metrics.get('settle_seconds_configured') or 0)} |")
    out.append(f"| Agent triage time (detection → report) | **{_human_duration(metrics.get('triage_seconds') or 0)}** |")
    out.append(f"| Total time to incident report | **{_human_duration(metrics.get('total_seconds') or 0)}** |")
    out.append(f"| Manual baseline for the same work | {_human_duration(metrics.get('manual_baseline_seconds') or 0)} |")
    saved = metrics.get("time_saved_seconds") or 0.0
    if saved > 0:
        out.append(f"| **Estimated time saved** | **{_human_duration(saved)}** |")
    out.append(f"| Events correlated | {correlation.get('event_count', 0)} |")
    out.append(f"| Poll interval | {metrics.get('poll_interval_seconds')}s |")
    out.append("")

    # --- 12. provenance ----------------------------------------------------
    out.append("## 12. Provenance and Audit Trail")
    out.append("")
    out.append(f"- Agent run id: `{metrics.get('run_id', 'n/a')}`")
    out.append(f"- Reasoning model: `{model}`")
    out.append(f"- Evidence pack sha256: `{metrics.get('evidence_sha256', 'n/a')}`")
    out.append(f"- LLM prompt sha256: `{metrics.get('prompt_sha256', 'n/a')}`")
    out.append(f"- Prompt tokens: {metrics.get('prompt_tokens', 0)} | "
               f"completion tokens: {metrics.get('completion_tokens', 0)}")
    out.append(f"- Indexer queries: {metrics.get('indexer_queries', metrics.get('query_count', 0))}")
    out.append(f"- Wazuh index: `{metrics.get('index_pattern', 'wazuh-alerts-*')}`")
    out.append(f"- Investigation window (UTC): {_fmt_ts(correlation.get('window_start'))} → "
               f"{_fmt_ts(correlation.get('window_end'))}")
    if agents:
        out.append("")
        out.append("**Monitored agents at triage time**")
        out.append("")
        out.append("| ID | Name | IP | Version | Status |")
        out.append("|---|---|---|---|---|")
        for agent in agents[:15]:
            out.append(
                f"| {agent.get('id')} | {agent.get('name')} | {agent.get('ip')} | "
                f"{agent.get('version')} | {agent.get('status')} |"
            )
    out.append("")
    out.append("---")
    out.append("")
    out.append(
        "*This report was generated automatically by the AI-Agentic SOC Triage Engine. "
        "All counts, timestamps and identifiers above are reproducible from the Wazuh "
        "indexer; the narrative sections are LLM interpretation and require human review.*"
    )
    out.append("")
    return "\n".join(out)


def write_report(content: str, reports_dir: Path, incident_id: str) -> Path:
    reports_dir.mkdir(parents=True, exist_ok=True)
    path = reports_dir / f"{incident_id}.md"
    path.write_text(content, encoding="utf-8")
    latest = reports_dir / "LATEST.md"
    try:
        latest.write_text(content, encoding="utf-8")
    except OSError:
        pass
    return path

def evidence_hash(payload: dict[str, Any]) -> str:
    blob = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()[:32]


def prompt_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:32]


# ==========================================================================
# HTML rendering
# ==========================================================================

SEVERITY_COLORS = {
    "Informational": "#5b7083",
    "Low": "#2e7d32",
    "Medium": "#e65100",
    "High": "#c62828",
    "Critical": "#7b1fa2",
    "Unrated": "#5b7083",
}


def _html_escape(value: Any) -> str:
    text = "" if value is None else str(value)
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _severity_color(severity: str) -> str:
    return SEVERITY_COLORS.get((severity or "").strip().title(), "#5b7083")


def _html_table(headers: list[str], rows: list[list[Any]]) -> str:
    if not rows:
        return ""
    out = ["<table>", "<thead><tr>"]
    for header in headers:
        out.append(f"<th>{_html_escape(header)}</th>")
    out.append("</tr></thead><tbody>")
    for row in rows:
        out.append("<tr>")
        for cell in row:
            out.append(f"<td>{_html_escape(cell)}</td>")
        out.append("</tr>")
    out.append("</tbody></table>")
    return "\n".join(out)


def render_report_html(
    incident_id: str,
    trigger: dict[str, Any],
    correlation: dict[str, Any],
    analysis: Optional[dict[str, Any]],
    metrics: dict[str, Any],
    model: str,
    generated_at: Optional[datetime] = None,
    agents: Optional[list[dict[str, Any]]] = None,
    evidence_pillars: Optional[dict[str, Any]] = None,
) -> str:
    """Render a self-contained, human-readable HTML incident report.

    Same facts as :func:`render_report` (Markdown), but styled so it can be
    opened in a browser during a demo. No external assets, no JavaScript.
    """
    generated_at = generated_at or datetime.now(timezone.utc)
    analysis = analysis or {}
    flags = correlation.get("flags") or {}

    severity = analysis.get("severity") or "Unrated"
    confidence = analysis.get("confidence") or "n/a"
    sev_color = _severity_color(severity)

    summary = (analysis.get("executive_summary") or "").strip()
    if not summary:
        summary = (
            f"Automated triage detected Wazuh rule {trigger.get('rule_id')} "
            f"(level {trigger.get('level')}) on agent {trigger.get('agent_name')} at "
            f"{_fmt_ts(trigger.get('ts'))}. {correlation.get('event_count', 0)} related "
            "events were correlated. The narrative engine was unavailable for this "
            "report, so only the deterministic correlation facts are presented."
        )

    p: list[str] = []
    p.append("<!DOCTYPE html>")
    p.append('<html lang="en"><head><meta charset="utf-8">')
    p.append(f"<title>{_html_escape(incident_id)} — AI-Agentic SOC</title>")
    p.append("<style>")
    p.append(
        """
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body { margin: 0; padding: 2.5rem 1.5rem 5rem; background: #0f1419; color: #e6edf3;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  line-height: 1.55; }
.wrap { max-width: 1040px; margin: 0 auto; }
h1 { font-size: 1.9rem; margin: 0 0 .35rem; letter-spacing: -.02em; }
h2 { font-size: 1.2rem; margin: 2.6rem 0 .9rem; padding-bottom: .45rem;
  border-bottom: 1px solid #2a3441; color: #a9b8c9; text-transform: uppercase;
  letter-spacing: .06em; font-weight: 600; }
h3 { font-size: 1.02rem; margin: 1.6rem 0 .6rem; color: #c9d6e3; }
p { margin: .7rem 0; }
code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: .87em;
  background: #1b232d; padding: .12em .42em; border-radius: 4px; color: #9fd3ff; }
.banner { background: #1b232d; border: 1px solid #2a3441; border-left: 4px solid #f0b429;
  border-radius: 8px; padding: 1rem 1.25rem; margin: 1.4rem 0; font-size: .92rem; color: #d7e2ee; }
.meta { color: #8b9bad; font-size: .92rem; }
.meta strong { color: #d7e2ee; }
.sev { display: inline-block; padding: .32rem 1rem; border-radius: 999px; font-weight: 700;
  color: #fff; background: %sev%; font-size: .95rem; letter-spacing: .02em; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: .8rem; margin: 1.4rem 0; }
.card { background: #161d26; border: 1px solid #232d38; border-radius: 10px; padding: .85rem 1rem; }
.card .k { font-size: .72rem; text-transform: uppercase; letter-spacing: .07em; color: #7f8fa3; }
.card .v { font-size: 1.28rem; font-weight: 650; margin-top: .25rem; }
table { border-collapse: collapse; width: 100%; margin: 1rem 0; font-size: .9rem; }
th, td { text-align: left; padding: .55rem .7rem; border-bottom: 1px solid #232d38;
  vertical-align: top; }
th { background: #161d26; color: #a9b8c9; font-weight: 600; font-size: .78rem;
  text-transform: uppercase; letter-spacing: .05em; }
tbody tr:hover { background: #141a22; }
ul { margin: .6rem 0; padding-left: 1.3rem; }
li { margin: .35rem 0; }
pre { background: #11181f; border: 1px solid #232d38; border-radius: 8px; padding: .9rem 1rem;
  overflow-x: auto; font-size: .83rem; color: #c6d4e1; }
.tag { display: inline-block; background: #22303f; color: #9fd3ff; border-radius: 4px;
  padding: .08rem .45rem; font-size: .78rem; font-family: ui-monospace, Menlo, monospace; }
.pill { display: inline-block; padding: .1rem .55rem; border-radius: 999px; font-size: .75rem;
  font-weight: 600; }
.pill.attack { background: #4a1f1f; color: #ff9d9d; }
.pill.context { background: #1f2f4a; color: #9dc0ff; }
footer { margin-top: 3.5rem; padding-top: 1.2rem; border-top: 1px solid #232d38;
  color: #7f8fa3; font-size: .84rem; }
"""
        .replace("%sev%", sev_color)
    )
    p.append('</style></head><body><div class="wrap">')

    p.append(f"<h1>Incident Report {_html_escape(incident_id)}</h1>")
    p.append(
        f'<div class="meta">Generated by the <strong>AI-Agentic SOC Triage Engine</strong> '
        f"(automated triage, human-in-the-loop) &middot; {_fmt_ts(generated_at)} &middot; "
        f'model <code>{_html_escape(model)}</code></div>'
    )
    p.append(
        '<div class="banner"><strong>Report status:</strong> DRAFT &mdash; requires analyst '
        "review before any response action.</div>"
    )

    # --- 1. executive summary -------------------------------------------
    p.append("<h2>1. Executive Summary</h2>")
    p.append(f"<p>{_html_escape(summary)}</p>")
    p.append(f'<p><span class="sev">{_html_escape(severity)}</span> '
             f'&nbsp;<span class="meta">Analyst confidence: {_html_escape(confidence)}</span></p>')

    cards = [
        ("Affected host", trigger.get("agent_name") or "n/a"),
        ("Detection rule", f"{trigger.get('rule_id')} (L{trigger.get('level')})"),
        ("Correlated events", correlation.get("event_count", 0)),
        ("Attack duration", _human_duration(correlation.get("trigger_burst_duration_seconds") or 0)),
        ("Source address", trigger.get("src_ip") or "n/a"),
        ("Target account", trigger.get("dst_user") or "n/a"),
    ]
    p.append('<div class="cards">')
    for key, value in cards:
        p.append(f'<div class="card"><div class="k">{_html_escape(key)}</div>'
                 f'<div class="v">{_html_escape(value)}</div></div>')
    p.append("</div>")
    if analysis.get("severity_rationale"):
        p.append(f"<p><strong>Severity rationale:</strong> "
                 f"{_html_escape(analysis['severity_rationale'])}</p>")

    # --- 2. detection facts ---------------------------------------------
    p.append("<h2>2. Detection Facts</h2>")
    p.append(_html_table(
        ["Fact", "Value"],
        [
            ["Wazuh alert id", trigger.get("id") or "n/a"],
            ["Wazuh timestamp", _fmt_ts(trigger.get("ts"))],
            ["Rule", f"{trigger.get('rule_id')} — {trigger.get('title')}"],
            ["Rule groups", ", ".join(trigger.get("groups") or []) or "none"],
            ["Rule MITRE tags", ", ".join(trigger.get("mitre") or []) or "none"],
            ["Agent", f"{trigger.get('agent_name')} ({trigger.get('agent_id')})"],
            ["Agent IP", trigger.get("agent_ip") or "n/a"],
            ["Source IP", trigger.get("src_ip") or "n/a"],
            ["Target user", trigger.get("dst_user") or "n/a"],
            ["Fired times", trigger.get("firedtimes") or 0],
        ],
    ))
    if trigger.get("full_log"):
        p.append("<h3>Raw trigger log</h3>")
        p.append(f"<pre>{_html_escape(trigger['full_log'][:1500])}</pre>")

    # --- 3. key findings -------------------------------------------------
    p.append("<h2>3. Key Findings</h2>")
    findings = analysis.get("key_findings") or []
    if findings:
        p.append("<ul>" + "".join(f"<li>{_html_escape(f)}</li>" for f in findings) + "</ul>")
    else:
        p.append('<p class="meta">The narrative engine was unavailable for this run; '
                 "deterministic findings are in sections 4 and 5.</p>")

    # --- 4. correlation ---------------------------------------------------
    p.append("<h2>4. Log Correlation</h2>")
    p.append('<p class="meta">Every event sharing the endpoint, source address, target '
             "account or rule family with the trigger, inside the investigation window.</p>")
    relation_labels = {
        "TRIGGER": "Trigger event",
        "SAME_AGENT": "Same monitored endpoint",
        "SAME_SOURCE_IP": "Same source address",
        "SAME_USER": "Same target account",
        "SAME_RULE_GROUP": "Same rule family",
        "PRIOR": "Occurred before the trigger",
        "POST": "Occurred after the trigger",
    }
    p.append("<h3>Relation breakdown</h3>")
    p.append(_html_table(
        ["Relation", "Events"],
        [[f"{relation_labels.get(r, r)} ({r})", c]
         for r, c in (correlation.get("relation_counts") or {}).items()],
    ))
    p.append("<h3>Events by rule</h3>")
    p.append(_html_table(
        ["Rule", "Level", "Description", "Events"],
        [[row["rule_id"], row.get("level", "—"), row["title"], row["count"]]
         for row in (correlation.get("rule_counts") or [])[:25]],
    ))
    p.append("<h3>Deterministic outcome flags</h3>")
    p.append(_html_table(["Flag", "Value"], [[k, v] for k, v in flags.items()]))
    if flags.get("source_equals_agent_ip"):
        p.append('<div class="banner"><strong>Self-originated traffic.</strong> The source '
                 "address equals the monitored host's own IP, so these attempts were "
                 "generated on the endpoint itself, not by a separate remote host.</div>")

    # --- 5. timeline ------------------------------------------------------
    p.append("<h2>5. Incident Timeline</h2>")
    rows = []
    for idx, entry in enumerate(correlation.get("timeline") or [], start=1):
        burst = "attack" if entry.get("in_trigger_burst") else "context"
        rows.append([
            idx, entry["timestamp"], entry["phase"], entry["rule_id"], entry["level"],
            f'<span class="pill {burst}">{burst}</span>', entry.get("title") or "",
            entry.get("agent") or "-", entry.get("src_ip") or "-", entry.get("dst_user") or "-",
        ])
    if rows:
        out = ["<table>", "<thead><tr>"]
        for header in ["#", "Timestamp (UTC)", "Phase", "Rule", "Lvl", "Burst", "Event",
                       "Host", "Source", "User"]:
            out.append(f"<th>{_html_escape(header)}</th>")
        out.append("</tr></thead><tbody>")
        for row in rows:
            out.append("<tr>")
            for i, cell in enumerate(row):
                out.append(f"<td>{cell}</td>" if i == 5 else f"<td>{_html_escape(cell)}</td>")
            out.append("</tr>")
        out.append("</tbody></table>")
        p.append("\n".join(out))
    p.append('<p class="meta"><span class="pill attack">attack</span> marks the burst the '
             'trigger belongs to; <span class="pill context">context</span> marks related '
             "activity in the same window from an earlier or separate burst.</p>")

    # --- 6. narrative -----------------------------------------------------
    p.append("<h2>6. Attack Narrative</h2>")
    narrative = (analysis.get("attack_narrative") or "").strip()
    if narrative:
        for para in narrative.split("\n"):
            if para.strip():
                p.append(f"<p>{_html_escape(para.strip())}</p>")
    else:
        p.append('<p class="meta">Narrative engine unavailable — see the deterministic '
                 "sections above.</p>")

    # --- 7. MITRE ---------------------------------------------------------
    p.append("<h2>7. MITRE ATT&amp;CK Mapping</h2>")
    observed = correlation.get("mitre_ids") or []
    if observed:
        p.append("<p>Techniques tagged on the correlated Wazuh rules: "
                 + " ".join(f'<span class="tag">{_html_escape(t)}</span>' for t in observed)
                 + "</p>")
    mapping = analysis.get("mitre_mapping") or []
    if mapping:
        p.append(_html_table(
            ["Technique", "Name", "Tactic", "Supporting evidence"],
            [[row.get("technique_id", ""), row.get("technique_name", ""),
              row.get("tactic", ""), row.get("evidence", "")] for row in mapping],
        ))
    else:
        p.append('<p class="meta">No ATT&amp;CK mapping produced by the narrative engine.</p>')

    # --- 8. risk ----------------------------------------------------------
    p.append("<h2>8. Risk Assessment</h2>")
    p.append(f"<p><strong>Severity:</strong> {_html_escape(severity)}"
             + (f" — {_html_escape(analysis['severity_rationale'])}"
                if analysis.get("severity_rationale") else "") + "</p>")
    p.append(f"<p><strong>Analyst confidence:</strong> {_html_escape(confidence)}</p>")
    if analysis.get("false_positive_assessment"):
        p.append(f"<p><strong>False-positive assessment:</strong> "
                 f"{_html_escape(analysis['false_positive_assessment'])}</p>")

    # --- 9. recommendations ------------------------------------------------
    p.append("<h2>9. Recommended Actions</h2>")
    p.append('<div class="banner"><strong>Recommendations only.</strong> The agent never '
             "executes containment; a human analyst must approve any response action.</div>")
    actions = analysis.get("recommended_actions") or []
    if actions:
        p.append(_html_table(
            ["Priority", "Action", "Rationale"],
            [[row.get("priority", "Medium"), row.get("action", ""), row.get("rationale", "")]
             for row in actions],
        ))
    containment = analysis.get("containment_recommendations") or []
    if containment:
        p.append("<h3>Containment options (pending analyst approval)</h3>")
        p.append("<ul>" + "".join(f"<li>{_html_escape(c)}</li>" for c in containment) + "</ul>")

    # --- 10. gaps ---------------------------------------------------------
    p.append("<h2>10. Evidence Gaps and Caveats</h2>")
    gaps = analysis.get("data_gaps") or []
    items = list(gaps) if gaps else ["No gaps were reported by the narrative engine."]
    if evidence_pillars:
        items += [f"{k}: {v}" for k, v in evidence_pillars.items()]
    p.append("<ul>" + "".join(f"<li>{_html_escape(g)}</li>" for g in items) + "</ul>")

    # --- 11. metrics -------------------------------------------------------
    p.append("<h2>11. Detection and Triage Metrics</h2>")
    metric_rows = [
        ["MTTD (Wazuh alert → agent detection)", _human_duration(metrics.get("mttd_seconds") or 0)],
    ]
    if metrics.get("burst_mttd_seconds") is not None:
        metric_rows.append(["End-to-end latency (first alert of burst → report)",
                            _human_duration(metrics.get("burst_mttd_seconds") or 0)])
        metric_rows.append(["Settle window used before triage",
                            _human_duration(metrics.get("settle_seconds_configured") or 0)])
    metric_rows += [
        ["Agent triage time (detection → report)", _human_duration(metrics.get("triage_seconds") or 0)],
        ["Total time to incident report", _human_duration(metrics.get("total_seconds") or 0)],
        ["Manual baseline for the same work", _human_duration(metrics.get("manual_baseline_seconds") or 0)],
    ]
    saved = metrics.get("time_saved_seconds") or 0.0
    if saved > 0:
        metric_rows.append(["Estimated time saved", _human_duration(saved)])
    metric_rows.append(["Events correlated", correlation.get("event_count", 0)])
    p.append(_html_table(["Metric", "Value"], metric_rows))

    # --- 12. provenance ----------------------------------------------------
    p.append("<h2>12. Provenance and Audit Trail</h2>")
    p.append(_html_table(
        ["Field", "Value"],
        [
            ["Agent run id", metrics.get("run_id", "n/a")],
            ["Reasoning model", model],
            ["Evidence pack sha256", metrics.get("evidence_sha256", "n/a")],
            ["LLM prompt sha256", metrics.get("prompt_sha256", "n/a")],
            ["Tokens", f"prompt {metrics.get('prompt_tokens', 0)} / "
                       f"completion {metrics.get('completion_tokens', 0)}"],
            ["Indexer queries", metrics.get("indexer_queries", metrics.get("query_count", 0))],
            ["Wazuh index", metrics.get("index_pattern", "wazuh-alerts-*")],
            ["Investigation window", f"{_fmt_ts(correlation.get('window_start'))} → "
                                     f"{_fmt_ts(correlation.get('window_end'))}"],
        ],
    ))
    if agents:
        p.append("<h3>Monitored agents at triage time</h3>")
        p.append(_html_table(
            ["ID", "Name", "IP", "Version", "Status"],
            [[a.get("id"), a.get("name"), a.get("ip"), a.get("version"), a.get("status")]
             for a in agents[:15]],
        ))

    p.append(
        "<footer>Generated automatically by the AI-Agentic SOC Triage Engine. All counts, "
        "timestamps and identifiers are reproducible from the Wazuh indexer; the narrative "
        "sections are LLM interpretation and require human review.</footer>"
    )
    p.append("</div></body></html>")
    return "\n".join(p)


def write_report_html(content: str, reports_dir: Path, incident_id: str) -> Path:
    reports_dir.mkdir(parents=True, exist_ok=True)
    path = reports_dir / f"{incident_id}.html"
    path.write_text(content, encoding="utf-8")
    latest = reports_dir / "LATEST.html"
    try:
        latest.write_text(content, encoding="utf-8")
    except OSError:
        pass
    return path
