"""Adapter between the API worker and the existing investigation graph.

This is the only place the service touches the agent runtime. It builds the
same clients the daemon uses, resolves one Wazuh alert, and calls
:func:`agent.runner.investigate_now` unchanged.
"""

from __future__ import annotations

from typing import Any, Dict

from agent.config import AgentConfig
from agent.events import event_from_wazuh
from agent.runner import build_clients, investigate_now
from agent.state import AgentState


class AlertNotFound(LookupError):
    pass


def investigate_alert(alert_id: str) -> Dict[str, Any]:
    config = AgentConfig.from_env()
    config.notify = False
    indexer, llm = build_clients(config, use_llm=config.llm_enabled)
    state_store = AgentState(config.state_file)
    try:
        alert = indexer.get_alert(alert_id)
        if alert is None:
            raise AlertNotFound("alert %s not found in the Wazuh indexer" % alert_id)
        trigger = event_from_wazuh(alert)
        result = investigate_now(config, indexer, llm, state_store, trigger)
        analysis = result.get("analysis") or {}
        metrics = result.get("metrics") or {}
        return {
            "alert_id": alert_id,
            "incident_id": result.get("incident_id"),
            "status": result.get("status"),
            "report_path": result.get("report_path"),
            "report_html_path": result.get("report_html_path"),
            "severity": analysis.get("severity"),
            "confidence": analysis.get("confidence"),
            "metrics": metrics,
            "errors": result.get("errors") or [],
        }
    finally:
        try:
            indexer.close()
        except Exception:
            pass
        if llm is not None:
            try:
                llm.close()
            except Exception:
                pass
