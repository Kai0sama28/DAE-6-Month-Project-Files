"""Streamlit views for StreamSOC.

The dashboard is deliberately read-only against the investigation engine: it
renders the generated reports, exposes the deterministic timeline/MITRE data,
and records the analyst's approve/reject decision. It never executes a
containment action.
"""

from __future__ import annotations

import html
import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

from frontend.backends import BackendError

SEVERITY_COLORS = {
    "critical": "#b91c1c",
    "high": "#dc2626",
    "medium": "#d97706",
    "low": "#2563eb",
    "informational": "#0f766e",
    "unrated": "#64748b",
}

DECISION_COLORS = {
    "approved": "#15803d",
    "rejected": "#b91c1c",
    "pending": "#a16207",
}


def inject_css() -> None:
    st.markdown(
        """
        <style>
        .block-container { padding-top: 1.4rem; padding-bottom: 3rem; }
        .soc-kicker { color: #7dd3fc; font-size: .78rem; font-weight: 700;
          letter-spacing: .14em; text-transform: uppercase; }
        .soc-title { font-size: 2rem; font-weight: 750; margin: .1rem 0 .2rem;
          letter-spacing: -.02em; }
        .soc-sub { color: #94a3b8; font-size: .95rem; margin-bottom: 1rem; }
        .badge { display: inline-block; padding: .16rem .62rem; border-radius: 999px;
          font-weight: 700; font-size: .76rem; letter-spacing: .02em; color: #fff; }
        .badge-outline { background: transparent; border: 1px solid #334155; color: #cbd5e1; }
        .panel { border: 1px solid #243041; border-radius: 10px; padding: .9rem 1rem;
          background: #0f1720; margin: .5rem 0; }
        .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
          font-size: .85rem; }
        .muted { color: #94a3b8; }
        .tiny { font-size: .78rem; color: #94a3b8; }
        .pipeline { display: flex; gap: .4rem; align-items: center; flex-wrap: wrap;
          margin: .4rem 0 .8rem; }
        .pipeline .step { padding: .3rem .7rem; border-radius: 7px; background: #111c28;
          border: 1px solid #243041; color: #cbd5e1; font-size: .82rem; }
        .pipeline .active { border-color: #38bdf8; color: #e0f2fe; background: #0b2536; }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _badge(text: str, color: str) -> str:
    return '<span class="badge" style="background:%s">%s</span>' % (
        color,
        html.escape(text or "Unrated"),
    )


def severity_badge(severity: Optional[str]) -> str:
    key = (severity or "unrated").strip().lower()
    return _badge(severity or "Unrated", SEVERITY_COLORS.get(key, "#64748b"))


def decision_badge(decision: Optional[Dict[str, Any]]) -> str:
    value = (decision or {}).get("decision", "pending")
    return _badge(value.title(), DECISION_COLORS.get(value, "#64748b"))


def _fmt(value: Any, fallback: str = "n/a") -> str:
    text = str(value).strip() if value is not None else ""
    return text if text and text.lower() not in ("none", "nan") else fallback


def _decision(case: Dict[str, Any]) -> Dict[str, Any]:
    return case.get("decision") or {}


def _decision_value(case: Dict[str, Any]) -> str:
    return _decision(case).get("decision", "pending")


def _case_frame(cases: List[Dict[str, Any]]) -> pd.DataFrame:
    rows = []
    for case in cases:
        rows.append(
            {
                "Incident": case.get("incident_id"),
                "Title": case.get("title"),
                "Severity": case.get("severity") or "Unrated",
                "Confidence": case.get("confidence") or "",
                "Host": case.get("affected_host") or "",
                "Rule": case.get("detection_rule") or "",
                "Events": case.get("correlated_events") or case.get("timeline_count") or 0,
                "Decision": _decision_value(case),
                "Generated (UTC)": case.get("generated_at") or "",
            }
        )
    return pd.DataFrame(rows)


def _bar(data: Dict[str, Any], x_label: str, y_label: str = "Cases") -> None:
    if not data:
        st.caption("No data.")
        return
    frame = (
        pd.DataFrame({x_label: list(data.keys()), y_label: list(data.values())})
        .sort_values(y_label, ascending=False)
        .reset_index(drop=True)
    )
    st.bar_chart(frame, x=x_label, y=y_label, height=260)


def render_page_header(kicker: str, title: str, subtitle: str = "") -> None:
    st.markdown(
        '<div class="soc-kicker">%s</div><div class="soc-title">%s</div>'
        '<div class="soc-sub">%s</div>'
        % (html.escape(kicker), html.escape(title), html.escape(subtitle)),
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Overview
# ---------------------------------------------------------------------------
def page_overview(backend: Any, cases: List[Dict[str, Any]]) -> None:
    render_page_header(
        "Security operations",
        "SOC overview",
        "Automated triage output, analyst decisions and ATT&CK coverage at a glance.",
    )

    if not cases:
        st.warning(
            "No incident reports were found. Run the triage agent or copy SOC-*.md "
            "reports into ai-agentic-soc/reports/."
        )
        return

    summary = _aggregate_cases(cases)
    columns = st.columns(5)
    columns[0].metric("Total cases", summary["total"])
    columns[1].metric("High / Critical", summary["high_risk"])
    columns[2].metric("Pending review", summary["pending"])
    columns[3].metric("Correlated events", summary["correlated_events"])
    columns[4].metric(
        "ATT&CK techniques",
        len(summary["by_technique"]),
        help="Distinct techniques observed across all reports.",
    )

    left, right = st.columns(2)
    with left:
        st.subheader("Cases by severity")
        _bar(summary["by_severity"], "Severity")
    with right:
        st.subheader("Analyst decision state")
        _bar(
            {
                key.title(): value
                for key, value in summary["by_decision"].items()
            },
            "Decision",
        )

    volume = _case_volume(cases)
    if not volume.empty:
        st.subheader("Case volume by day")
        st.bar_chart(volume, x="Date", y="Cases", height=230)

    left, right = st.columns(2)
    with left:
        st.subheader("Top MITRE tactics")
        _bar(
            dict(
                sorted(
                    summary["by_tactic"].items(),
                    key=lambda item: item[1],
                    reverse=True,
                )[:10]
            ),
            "Tactic",
            "Events",
        )
    with right:
        st.subheader("Top detection rules")
        _bar(
            dict(
                sorted(
                    summary["by_rule"].items(),
                    key=lambda item: item[1],
                    reverse=True,
                )[:10]
            ),
            "Rule",
        )

    st.subheader("Recent incidents")
    st.dataframe(
        _case_frame(cases[:12]),
        width="stretch",
        hide_index=True,
        height=360,
    )


def _aggregate_cases(cases: List[Dict[str, Any]]) -> Dict[str, Any]:
    severities = Counter(case.get("severity") or "Unrated" for case in cases)
    decisions = Counter(_decision_value(case) for case in cases)
    tactics = Counter()
    techniques = Counter()
    rules = Counter()
    for case in cases:
        tactics.update(case.get("mitre_tactics") or {})
        techniques.update(case.get("mitre_techniques") or [])
        rules[case.get("detection_rule") or "Unknown"] += 1
    return {
        "total": len(cases),
        "by_severity": dict(severities),
        "by_decision": dict(decisions),
        "by_tactic": dict(tactics),
        "by_technique": dict(techniques),
        "by_rule": dict(rules),
        "high_risk": sum(1 for case in cases if (case.get("severity_rank") or 0) >= 3),
        "pending": decisions.get("pending", 0),
        "correlated_events": sum(
            int(case.get("correlated_events_int") or 0) for case in cases
        ),
    }


def _case_volume(cases: List[Dict[str, Any]]) -> pd.DataFrame:
    dates = []
    for case in cases:
        raw = case.get("generated_at")
        if not raw:
            continue
        parsed = pd.to_datetime(raw, errors="coerce", utc=True)
        if pd.notna(parsed):
            dates.append(parsed.date().isoformat())
    if not dates:
        return pd.DataFrame()
    counts = Counter(dates)
    frame = pd.DataFrame(
        {"Date": list(counts.keys()), "Cases": list(counts.values())}
    ).sort_values("Date")
    return frame.reset_index(drop=True)


# ---------------------------------------------------------------------------
# Cases + detail
# ---------------------------------------------------------------------------
def page_cases(backend: Any, cases: List[Dict[str, Any]]) -> None:
    render_page_header(
        "Alert queue",
        "Cases",
        "Filter the report queue, open an incident and record the human decision.",
    )

    if not cases:
        st.warning("No cases available.")
        return

    severities = sorted({case.get("severity") or "Unrated" for case in cases})
    hosts = sorted({case.get("affected_host") or "Unknown" for case in cases})

    row1 = st.columns([2, 1, 1, 1])
    search = row1[0].text_input(
        "Search",
        placeholder="Incident id, title, host, rule or summary text",
        key="case_search",
    )
    severity_filter = row1[1].multiselect(
        "Severity", severities, key="case_severity_filter"
    )
    decision_filter = row1[2].selectbox(
        "Decision",
        ["All", "pending", "approved", "rejected"],
        key="case_decision_filter",
    )
    host_filter = row1[3].selectbox(
        "Host", ["All"] + hosts, key="case_host_filter"
    )

    filtered = _filter_cases(cases, search, severity_filter, decision_filter, host_filter)

    st.caption("%d of %d cases" % (len(filtered), len(cases)))
    st.dataframe(
        _case_frame(filtered),
        width="stretch",
        hide_index=True,
        height=320,
    )

    if not filtered:
        st.info("No cases match the current filters.")
        return

    labels = {
        "%s | %s | %s"
        % (
            case.get("incident_id"),
            case.get("severity") or "Unrated",
            case.get("title"),
        ): case.get("incident_id")
        for case in filtered
    }
    selected_label = st.selectbox(
        "Open incident", list(labels.keys()), key="case_selected"
    )
    selected_id = labels[selected_label]
    try:
        case = backend.get_case(selected_id)
    except BackendError as exc:
        st.error("Could not load case: %s" % exc)
        case = None
    if not case:
        case = next(
            (item for item in filtered if item.get("incident_id") == selected_id), None
        )
    if case:
        render_case_detail(backend, case)


def _filter_cases(
    cases: List[Dict[str, Any]],
    search: str,
    severities: List[str],
    decision: str,
    host: str,
) -> List[Dict[str, Any]]:
    text = (search or "").strip().lower()
    result = []
    for case in cases:
        if severities and (case.get("severity") or "Unrated") not in severities:
            continue
        if decision != "All" and _decision_value(case) != decision:
            continue
        if host != "All" and (case.get("affected_host") or "Unknown") != host:
            continue
        if text:
            haystack = " ".join(
                str(case.get(key) or "")
                for key in (
                    "incident_id",
                    "title",
                    "summary",
                    "affected_host",
                    "source_address",
                    "target_account",
                    "detection_rule",
                )
            ).lower()
            if text not in haystack:
                continue
        result.append(case)
    return result


def render_case_detail(backend: Any, case: Dict[str, Any]) -> None:
    st.divider()
    title_col, badge_col = st.columns([5, 1])
    with title_col:
        st.subheader("%s — %s" % (case.get("incident_id"), case.get("title")))
        st.caption(
            "Generated %s | Model %s | %s"
            % (
                _fmt(case.get("generated_at")),
                _fmt(case.get("model")),
                _fmt(case.get("report_status")),
            )
        )
    with badge_col:
        st.markdown(
            severity_badge(case.get("severity"))
            + "&nbsp;"
            + decision_badge(case.get("decision")),
            unsafe_allow_html=True,
        )

    metrics = st.columns(6)
    metrics[0].metric("Severity", _fmt(case.get("severity"), "Unrated"))
    metrics[1].metric("Confidence", _fmt(case.get("confidence")))
    metrics[2].metric("Events", _fmt(case.get("correlated_events")))
    metrics[3].metric("Attack duration", _fmt(case.get("attack_duration")))
    metrics[4].metric("Max rule level", _fmt(case.get("max_level")))
    metrics[5].metric("Techniques", len(case.get("mitre_techniques") or []))

    tabs = st.tabs(
        ["Summary", "Timeline", "MITRE ATT&CK", "Evidence", "Full report", "Decision"]
    )
    with tabs[0]:
        _summary_tab(case)
    with tabs[1]:
        _timeline_tab(case)
    with tabs[2]:
        _mitre_tab(case)
    with tabs[3]:
        _evidence_tab(case)
    with tabs[4]:
        _report_tab(case)
    with tabs[5]:
        _decision_tab(backend, case)


def _summary_tab(case: Dict[str, Any]) -> None:
    if case.get("summary"):
        st.markdown(case["summary"])
    if case.get("severity_rationale"):
        st.info(case["severity_rationale"])
    left, right = st.columns(2)
    with left:
        st.subheader("Key findings")
        findings = case.get("key_findings") or []
        if findings:
            for item in findings:
                st.markdown("- %s" % item)
        else:
            st.caption("No key findings were recorded.")
    with right:
        st.subheader("Risk assessment")
        risk = case.get("risk") or []
        if risk:
            for item in risk:
                st.markdown("- %s" % item)
        else:
            st.caption("No risk assessment was recorded.")

    st.subheader("Detection facts")
    facts = case.get("detection_facts") or {}
    if facts:
        st.dataframe(
            pd.DataFrame(
                {"Fact": list(facts.keys()), "Value": list(facts.values())}
            ),
            width="stretch",
            hide_index=True,
        )
    else:
        st.caption("No detection facts table found.")


def _timeline_tab(case: Dict[str, Any]) -> None:
    timeline = case.get("timeline") or []
    if not timeline:
        st.info("This report does not contain a timeline table.")
        return

    frame = pd.DataFrame(timeline)
    display_columns = [
        column
        for column in (
            "#",
            "Timestamp (UTC)",
            "Phase",
            "Rule",
            "Lvl",
            "Event",
            "Host",
            "Source",
            "User",
            "Burst",
        )
        if column in frame.columns
    ]
    st.dataframe(
        frame[display_columns],
        width="stretch",
        hide_index=True,
        height=320,
    )

    chart = frame.copy()
    if "Timestamp (UTC)" in chart.columns:
        chart["Time"] = pd.to_datetime(
            chart["Timestamp (UTC)"], errors="coerce", utc=True
        ).dt.tz_localize(None)
    if "Lvl" in chart.columns:
        chart["Level"] = pd.to_numeric(chart["Lvl"], errors="coerce").fillna(0)
    if "Time" in chart.columns and "Level" in chart.columns:
        st.subheader("Event level over time")
        st.scatter_chart(
            chart.dropna(subset=["Time"]),
            x="Time",
            y="Level",
            color="Phase" if "Phase" in chart.columns else None,
            height=300,
        )

    left, right = st.columns(2)
    with left:
        st.subheader("Events by phase")
        _bar(case.get("phase_counts") or {}, "Phase", "Events")
    with right:
        st.subheader("Burst split")
        burst = Counter(
            (row.get("Burst") or "unknown").lower() for row in timeline
        )
        _bar({key.title(): value for key, value in burst.items()}, "Burst", "Events")

    st.download_button(
        "Download timeline CSV",
        frame.to_csv(index=False).encode("utf-8"),
        file_name="%s-timeline.csv" % case.get("incident_id"),
        mime="text/csv",
        key="timeline-csv-%s" % case.get("incident_id"),
    )


def _mitre_tab(case: Dict[str, Any]) -> None:
    rows = case.get("mitre") or []
    if not rows:
        st.info("No MITRE ATT&CK mapping table found in this report.")
        return
    frame = pd.DataFrame(rows)
    st.dataframe(frame, width="stretch", hide_index=True, height=260)
    st.subheader("Techniques by tactic")
    _bar(case.get("mitre_tactics") or {}, "Tactic", "Techniques")
    techniques = case.get("mitre_techniques") or []
    if techniques:
        st.caption("Techniques: " + ", ".join(sorted(set(techniques))))


def _evidence_tab(case: Dict[str, Any]) -> None:
    left, right = st.columns(2)
    with left:
        st.subheader("Correlation relations")
        relations = case.get("relations") or {}
        if relations:
            st.dataframe(
                pd.DataFrame(
                    {"Relation": list(relations.keys()), "Events": list(relations.values())}
                ),
                width="stretch",
                hide_index=True,
            )
        else:
            st.caption("No relation table found.")
    with right:
        st.subheader("Deterministic flags")
        flags = case.get("flags") or {}
        if flags:
            st.dataframe(
                pd.DataFrame(
                    {"Flag": list(flags.keys()), "Value": list(flags.values())}
                ),
                width="stretch",
                hide_index=True,
                height=300,
            )
        else:
            st.caption("No outcome flags found.")

    st.subheader("Events by rule")
    rules = case.get("rule_rows") or []
    if rules:
        st.dataframe(
            pd.DataFrame(rules), width="stretch", hide_index=True
        )
    else:
        st.caption("No rule breakdown found.")

    st.subheader("Recommended actions")
    recommendations = case.get("recommendations") or []
    if recommendations:
        st.dataframe(
            pd.DataFrame(recommendations),
            width="stretch",
            hide_index=True,
        )
    else:
        st.caption("No recommended actions table found.")

    containment = case.get("containment") or []
    if containment:
        st.warning(
            "Containment is advisory only. The agent never executes a response "
            "action; a human must approve it."
        )
        for item in containment:
            st.markdown("- %s" % item)

    gaps = case.get("evidence_gaps") or []
    if gaps:
        st.subheader("Evidence gaps and caveats")
        for item in gaps:
            st.markdown("- %s" % item)

    provenance = case.get("provenance") or []
    if provenance:
        with st.expander("Provenance and audit trail"):
            for item in provenance:
                st.markdown("- %s" % item)


def _report_tab(case: Dict[str, Any]) -> None:
    markdown = case.get("markdown") or ""
    st.download_button(
        "Download Markdown report",
        markdown.encode("utf-8"),
        file_name="%s.md" % case.get("incident_id"),
        mime="text/markdown",
        key="md-download-%s" % case.get("incident_id"),
    )
    html_path = case.get("report_html_path")
    if html_path and Path(html_path).is_file():
        try:
            html_text = Path(html_path).read_text(encoding="utf-8", errors="replace")
            st.download_button(
                "Download HTML report",
                html_text.encode("utf-8"),
                file_name="%s.html" % case.get("incident_id"),
                mime="text/html",
                key="html-download-%s" % case.get("incident_id"),
            )
            with st.expander("Rendered HTML report"):
                components.html(html_text, height=900, scrolling=True)
        except OSError:
            pass
    st.markdown(markdown)


def _decision_tab(backend: Any, case: Dict[str, Any]) -> None:
    incident_id = case.get("incident_id")
    decision = _decision(case)
    state = decision.get("decision", "pending")

    steps = [
        ("Pending", state == "pending"),
        ("Approved", state == "approved"),
        ("Rejected", state == "rejected"),
        ("Closed", state in ("approved", "rejected")),
    ]
    st.markdown(
        '<div class="pipeline">%s</div>'
        % "".join(
            '<span class="step%s">%s</span>'
            % (" active" if active else "", html.escape(label))
            for label, active in steps
        ),
        unsafe_allow_html=True,
    )

    if decision:
        st.success(
            "%s by %s at %s"
            % (
                decision.get("decision", "").title(),
                _fmt(decision.get("analyst")),
                _fmt(decision.get("decided_at")),
            )
        )
        if decision.get("note"):
            st.caption("Note: " + decision["note"])
    else:
        st.warning("No analyst decision has been recorded for this case.")

    st.caption(
        "Approval records the human decision only. It does not execute containment."
    )

    with st.form("decision-%s" % incident_id):
        choice = st.radio(
            "Decision",
            ["approved", "rejected"],
            horizontal=True,
            key="decision-choice-%s" % incident_id,
        )
        analyst = st.text_input(
            "Analyst",
            value=st.session_state.get("analyst_name", ""),
            key="decision-analyst-%s" % incident_id,
        )
        note = st.text_area(
            "Note",
            value="",
            key="decision-note-%s" % incident_id,
            placeholder="Why is this being approved or rejected?",
        )
        submitted = st.form_submit_button("Record decision")

    if submitted:
        try:
            record = backend.record_decision(
                incident_id, choice, analyst or "analyst", note
            )
        except BackendError as exc:
            st.error("Could not record decision: %s" % exc)
        else:
            st.success(
                "Decision recorded: %s by %s."
                % (record.get("decision", choice), record.get("analyst", analyst))
            )
            st.rerun()


# ---------------------------------------------------------------------------
# Investigate
# ---------------------------------------------------------------------------
def page_investigate(backend: Any) -> None:
    render_page_header(
        "Control plane",
        "Investigate",
        "Queue an existing Wazuh alert for the LangGraph agent and follow the job.",
    )

    try:
        health = backend.health()
    except BackendError as exc:
        st.error("Backend unavailable: %s" % exc)
        return

    columns = st.columns(4)
    columns[0].metric("Mode", health.get("mode", backend.mode))
    columns[1].metric("API status", health.get("status", "unknown"))
    columns[2].metric("Queued jobs", health.get("queued_jobs", 0))
    columns[3].metric("Running jobs", health.get("running_jobs", 0))

    if backend.mode != "api":
        st.info(
            "The dashboard is running in local report mode. Investigating a new "
            "alert needs the triage API, the Wazuh indexer and the agent runtime."
        )
        st.markdown(
            """
Start the live stack from the copied project:

```bash
cd ai-agentic-soc
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
cp .env.example .env             # fill in Wazuh + OpenRouter values

python -m services.triage_api    # http://127.0.0.1:8080
```

Then switch the sidebar data source to **Auto** or **Triage API**. The agent
itself can also be run as a daemon:

```bash
python -m agent.runner
python -m agent.runner --once
python -m agent.runner --no-llm
```
"""
        )
        return

    with st.form("investigate-form"):
        alert_id = st.text_input(
            "Wazuh alert id", placeholder="1792695015.328031"
        )
        force = st.checkbox("Force a new run if one is already queued or running")
        submitted = st.form_submit_button("Queue investigation")
    if submitted:
        if not alert_id.strip():
            st.warning("Enter an alert id first.")
        else:
            try:
                job = backend.submit_investigation(alert_id.strip(), force)
            except BackendError as exc:
                st.error("Could not queue investigation: %s" % exc)
            else:
                st.session_state["triage_job_id"] = job.get("job_id")
                st.success("Queued job %s." % job.get("job_id"))

    job_id = st.session_state.get("triage_job_id")
    if job_id:
        try:
            job = _find_job(backend.list_jobs(limit=100), job_id)
        except BackendError as exc:
            st.error("Could not read job status: %s" % exc)
            job = None
        if job:
            columns = st.columns(3)
            columns[0].metric("Job status", job.get("status", "unknown"))
            columns[1].metric("Alert", job.get("alert_id", "n/a"))
            columns[2].metric("Created", job.get("created_at", "n/a"))
            if st.button("Refresh job status"):
                st.rerun()
            if job.get("status") == "succeeded":
                st.success("Report ready: %s" % (job.get("result") or {}))
                st.json(job.get("result") or {})
            elif job.get("status") == "failed":
                st.error(job.get("error") or "investigation failed")
            else:
                st.info("Investigation is still running. Refresh in a moment.")

    st.subheader("Recent jobs")
    try:
        jobs = backend.list_jobs(limit=25)
    except BackendError as exc:
        st.error("Could not read jobs: %s" % exc)
        jobs = []
    if jobs:
        st.dataframe(
            pd.DataFrame(jobs), width="stretch", hide_index=True
        )
    else:
        st.caption("No jobs yet.")


def _find_job(jobs: List[Dict[str, Any]], job_id: str) -> Optional[Dict[str, Any]]:
    for job in jobs:
        if job.get("job_id") == job_id:
            return job
    return None


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------
def page_evaluation(evals_dir: Path) -> None:
    render_page_header(
        "Measured accuracy",
        "Evaluation",
        "The labeled 50-case dataset and the agent's measured ATT&CK and recommendation accuracy.",
    )

    results_dir = Path(evals_dir) / "results"
    dataset_path = Path(evals_dir) / "dataset" / "soc-eval-2026-11.jsonl"

    if dataset_path.is_file():
        cases = _load_jsonl(dataset_path)
        if cases:
            labels = Counter(case.get("label") or "unknown" for case in cases)
            verdicts = Counter(
                "malicious" if case.get("is_malicious") else "benign" for case in cases
            )
            columns = st.columns(4)
            columns[0].metric("Dataset cases", len(cases))
            columns[1].metric("Labels", len(labels))
            columns[2].metric("Malicious", verdicts.get("malicious", 0))
            columns[3].metric("Benign", verdicts.get("benign", 0))
            left, right = st.columns(2)
            with left:
                st.subheader("Cases by label")
                _bar(dict(labels), "Label")
            with right:
                st.subheader("Alert bundles")
                bundle = Counter(
                    case.get("label") or "unknown" for case in cases
                )
                avg = {
                    label: round(
                        sum(
                            len(case.get("alerts") or [])
                            for case in cases
                            if (case.get("label") or "unknown") == label
                        )
                        / max(1, count),
                        1,
                    )
                    for label, count in bundle.items()
                }
                _bar(avg, "Label", "Avg alerts")

    evaluation_reports = sorted(results_dir.glob("*EVALUATION.md"))
    processing_reports = sorted(results_dir.glob("*PROCESSING_TIMES.md"))

    if not evaluation_reports and not processing_reports:
        st.info(
            "No evaluation results found yet. Run `python -m evals.run_eval` "
            "inside ai-agentic-soc to generate them."
        )
        return

    st.subheader("Evaluation report")
    report_names = [path.name for path in evaluation_reports + processing_reports]
    selected = st.selectbox("Report", report_names, key="eval-report")
    selected_path = next(
        path for path in evaluation_reports + processing_reports if path.name == selected
    )
    st.caption(str(selected_path))
    st.markdown(selected_path.read_text(encoding="utf-8", errors="replace"))

    raw = results_dir / "soc-eval-2026-11-cases-llm-evaluation.jsonl"
    if raw.is_file():
        with st.expander("Raw evaluation records"):
            records = _load_jsonl(raw)
            st.caption("%d records" % len(records))
            if records:
                st.dataframe(
                    pd.DataFrame(records),
                    width="stretch",
                    hide_index=True,
                    height=360,
                )


def _load_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows = []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    continue
    except OSError:
        return []
    return rows


# ---------------------------------------------------------------------------
# About
# ---------------------------------------------------------------------------
def page_about(assessment_path: Path, architecture_path: Path) -> None:
    render_page_header(
        "Project notes",
        "About StreamSOC",
        "What was already sufficient, what was improved, and how the pieces fit.",
    )

    st.markdown(
        """
### What this is

StreamSOC is the analyst-facing Streamlit layer over the existing
**AI-Agentic SOC Triage & Investigation Engine**. The engine watches Wazuh,
correlates identity, SIEM and EDR evidence, maps the result to MITRE ATT&CK,
writes Markdown + HTML reports, and leaves every containment action to a human.

### Operating modes

| Mode | Data source | New investigations | Decisions |
|---|---|---|---|
| Local reports | `ai-agentic-soc/reports/*.md` | No | `data/triage_decisions.json` |
| Triage API | FastAPI on `127.0.0.1:8080` | Yes, if Wazuh + agent are running | API decision store |
| Auto | API if healthy, otherwise local | Depends on API | Depends on backend |

Local mode is deliberate: the dashboard remains demonstrable without Wazuh,
OpenRouter, Docker or the agent daemon.

### Safety model

- The agent never executes containment. Recommendations are advisory.
- Every report is stamped `DRAFT — requires analyst review`.
- The dashboard records approve/reject decisions only; it has no action executor.
- The API and dashboard have no authentication, so keep them on loopback.
"""
    )

    if assessment_path.is_file():
        with st.expander("Full sufficiency assessment", expanded=False):
            st.markdown(assessment_path.read_text(encoding="utf-8", errors="replace"))

    if architecture_path.is_file():
        with st.expander("Architecture notes", expanded=False):
            st.markdown(architecture_path.read_text(encoding="utf-8", errors="replace"))
