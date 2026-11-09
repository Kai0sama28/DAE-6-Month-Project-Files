"""Minimal Streamlit dashboard for the triage API.

Run from ``ai-agentic-soc/``::

    venv/bin/streamlit run frontend/app.py --server.address 127.0.0.1

Start the API first::

    venv/bin/python -m services.triage_api
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

import httpx
import streamlit as st
import streamlit.components.v1 as components

DEFAULT_API = os.environ.get("TRIAGE_API_URL", "http://127.0.0.1:8080")


def api_get(base: str, path: str, params: Optional[Dict[str, Any]] = None) -> Optional[Any]:
    try:
        with httpx.Client(timeout=15.0) as client:
            response = client.get(base + path, params=params)
            response.raise_for_status()
            return response.json()
    except (httpx.HTTPError, ValueError) as exc:
        st.error("API request failed: %s" % exc)
        return None


def api_text(base: str, path: str, params: Optional[Dict[str, Any]] = None) -> Optional[str]:
    try:
        with httpx.Client(timeout=15.0) as client:
            response = client.get(base + path, params=params)
            response.raise_for_status()
            return response.text
    except httpx.HTTPError as exc:
        st.error("API request failed: %s" % exc)
        return None


def api_post(base: str, path: str, payload: Dict[str, Any]) -> Optional[Any]:
    try:
        with httpx.Client(timeout=30.0) as client:
            response = client.post(base + path, json=payload)
            response.raise_for_status()
            return response.json()
    except (httpx.HTTPError, ValueError) as exc:
        st.error("API request failed: %s" % exc)
        return None


def render_cases(base: str) -> None:
    cases: List[Dict[str, Any]] = api_get(base, "/api/v1/cases", {"limit": 200}) or []
    if not cases:
        st.info("No reports yet. Queue an investigation or start the agent daemon.")
        return

    labels = {}
    for case in cases:
        label = "%s | %s | %s" % (
            case.get("incident_id"),
            case.get("severity") or "Unrated",
            case.get("affected_host") or "unknown host",
        )
        labels[label] = case.get("incident_id")
    selected = st.selectbox("Incident", list(labels.keys()))
    incident_id = labels[selected]
    detail = api_get(base, "/api/v1/cases/%s" % incident_id)
    if not detail:
        return

    columns = st.columns(4)
    columns[0].metric("Severity", detail.get("severity") or "Unrated")
    columns[1].metric("Confidence", detail.get("confidence") or "Unknown")
    columns[2].metric("Correlated events", detail.get("correlated_events") or "n/a")
    columns[3].metric("Attack duration", detail.get("attack_duration") or "n/a")

    decision = detail.get("decision")
    if decision:
        st.success(
            "Analyst decision: %s by %s at %s"
            % (decision.get("decision"), decision.get("analyst"), decision.get("decided_at"))
        )
    else:
        st.warning("No analyst decision recorded yet.")

    st.markdown(detail.get("markdown") or "")

    with st.expander("HTML report"):
        html = api_text(base, "/api/v1/cases/%s/report" % incident_id, {"format": "html"})
        if html:
            components.html(html, height=900, scrolling=True)

    with st.form("decision-%s" % incident_id):
        st.subheader("Record analyst decision")
        choice = st.radio("Decision", ["approved", "rejected"], horizontal=True)
        analyst = st.text_input("Analyst", value="")
        note = st.text_area("Note", value="")
        submitted = st.form_submit_button("Record decision")
    if submitted:
        record = api_post(
            base,
            "/api/v1/cases/%s/decision" % incident_id,
            {"decision": choice, "analyst": analyst or "analyst", "note": note},
        )
        if record:
            st.success("Decision recorded for %s." % incident_id)
            st.rerun()


def render_investigation(base: str) -> None:
    st.write(
        "Queue an existing Wazuh alert for the LangGraph agent. "
        "The request returns immediately; poll the job for the report."
    )
    with st.form("investigate-form"):
        alert_id = st.text_input("Wazuh alert id", placeholder="1792695015.328031")
        force = st.checkbox("Force a new run if one is already queued or running")
        submitted = st.form_submit_button("Queue investigation")
    if submitted:
        if not alert_id.strip():
            st.warning("Enter an alert id first.")
        else:
            job = api_post(
                base,
                "/api/v1/investigations",
                {"alert_id": alert_id.strip(), "force": force},
            )
            if job:
                st.session_state["triage_job_id"] = job["job_id"]
                st.success("Queued job %s." % job["job_id"])

    job_id = st.session_state.get("triage_job_id")
    if not job_id:
        return
    job = api_get(base, "/api/v1/jobs/%s" % job_id)
    if not job:
        return

    columns = st.columns(3)
    columns[0].metric("Job status", job.get("status") or "unknown")
    columns[1].metric("Alert", job.get("alert_id") or "n/a")
    columns[2].metric("Created", job.get("created_at") or "n/a")
    if st.button("Refresh job status"):
        st.rerun()

    if job.get("status") == "succeeded":
        result = job.get("result") or {}
        st.success(
            "Report ready: %s" % (result.get("incident_id") or result.get("report_path") or "unknown")
        )
        st.json(result)
    elif job.get("status") == "failed":
        st.error(job.get("error") or "investigation failed")
    else:
        st.info("Investigation is still running. Refresh in a moment.")


def main() -> None:
    st.set_page_config(page_title="AI-Agentic SOC", layout="wide")

    st.sidebar.header("Connection")
    base = st.sidebar.text_input("API base URL", value=DEFAULT_API).rstrip("/")
    if st.sidebar.button("Refresh"):
        st.rerun()

    health = api_get(base, "/api/v1/health")
    if health:
        st.sidebar.success("API %s" % health.get("status"))
        st.sidebar.caption(
            "Queued %s | Running %s"
            % (health.get("queued_jobs"), health.get("running_jobs"))
        )
    else:
        st.sidebar.error("API unavailable")

    st.sidebar.divider()
    st.sidebar.caption("Recent jobs")
    jobs: List[Dict[str, Any]] = api_get(base, "/api/v1/jobs", {"limit": 10}) or []
    if not jobs:
        st.sidebar.write("No jobs yet.")
    for job in jobs:
        st.sidebar.write(
            "%s  %s  %s" % (job.get("status"), job.get("alert_id"), job.get("job_id", "")[:8])
        )

    st.title("AI-Agentic SOC Triage")
    st.caption("Human-in-the-loop review of automated incident reports.")

    cases_tab, investigate_tab = st.tabs(["Cases", "Investigate"])
    with cases_tab:
        render_cases(base)
    with investigate_tab:
        render_investigation(base)


main()
