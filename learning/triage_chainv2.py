"""
AI-Agentic SOC Triage Engine - Pydantic Tools & LangGraph Chain (v2)
Designed for the ai-agentic-soc workspace.

Changes from v1:
  - Conditional routing (ISOLATE / MONITOR / FALSE_POSITIVE / ESCALATE all reachable)
  - Evidence-based risk scoring (threat intel + MITRE + log volume + FP history)
  - Parallel enrichment; every SIEM tool is now used
  - PID comes from the alert or inspect_process_tree (no hardcoded PID), with a protected-process guard
  - Human-approval gate before automated isolation
  - Missing alert fields are flagged instead of silently invented
  - Status updates are consistent (no overwrite of CLOSED_FALSE_POSITIVE)
  - Linux-consistent mock data
  - Correct invoke() handling for compiled LangGraph graphs
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, TypedDict

from pydantic import BaseModel, Field

# =====================================================================
# CONFIG
# =====================================================================

REQUIRED_FIELDS = ("agent_id", "hostname")
ISOLATE_THRESHOLD = 75.0
ESCALATE_THRESHOLD = 50.0
MONITOR_THRESHOLD = 25.0
REQUIRE_APPROVAL = True  # human gate before automated isolation
PROTECTED_PROCESSES = {"systemd", "init", "sshd", "wazuh-agentd", "wazuh-modulesd"}

# Alert decision -> SIEM ticket status (only values from the documented list)
STATUS_MAP = {
    "ISOLATE": "CONTAINED",
    "MONITOR": "IN_PROGRESS",
    "ESCALATE": "ESCALATED",
    "FALSE_POSITIVE": "CLOSED_FALSE_POSITIVE",
}


# =====================================================================
# 1. PYDANTIC TOOL DEFINITIONS: SIEM AGENT SKILLS
# =====================================================================

class QueryRelatedLogsInput(BaseModel):
    query_string: str = Field(description="Search filter string (e.g. 'src_ip:192.168.1.50 OR user:admin')")
    time_window_minutes: int = Field(default=60, description="Time window in minutes to search backwards from alert timestamp")
    max_results: int = Field(default=100, description="Maximum log entries to return")

class CorrelateMitreTacticsInput(BaseModel):
    event_ids: List[str] = Field(description="List of SIEM event IDs or rule names to map")
    process_hashes: Optional[List[str]] = Field(default_factory=list, description="Process SHA256 hashes associated with the alert")

class CheckFalsePositiveHistoryInput(BaseModel):
    rule_id: str = Field(description="SIEM rule ID or signature name")
    host_id: str = Field(description="Target host ID or hostname")
    lookback_days: int = Field(default=30, description="Days to look back in historic ticket resolution DB")

class EnrichIndicatorsInput(BaseModel):
    iocs: List[str] = Field(description="IOCs (IPs, domains, SHA256 hashes) to look up in threat intelligence feeds")

class SynthesizeIncidentTimelineInput(BaseModel):
    alert_id: str = Field(description="Unique alert identifier")
    events: List[Dict[str, Any]] = Field(description="Unsorted log events collected across SIEM indices")

class UpdateAlertStatusInput(BaseModel):
    alert_id: str = Field(description="Unique alert identifier")
    status: str = Field(description="'IN_PROGRESS', 'CLOSED_FALSE_POSITIVE', 'ESCALATED', or 'CONTAINED'")
    notes: str = Field(description="Summary narrative explaining the status update")


# Dummy handlers (replace with real Wazuh/OpenSearch calls)
def query_related_logs(params: QueryRelatedLogsInput) -> Dict[str, Any]:
    return {
        "status": "success",
        "logs_found": 12,
        "events": [
            {"ts": "14:00:15", "msg": "Outbound connection to 203.0.113.50:4444"},
            {"ts": "14:00:02", "msg": "curl downloaded /tmp/payload.sh"},
            {"ts": "14:00:10", "msg": "bash launched with base64-decoded command"},
        ],
    }

def correlate_mitre_tactics(params: CorrelateMitreTacticsInput) -> Dict[str, Any]:
    return {
        "tactics": ["Execution (TA0002)", "Defense Evasion (TA0005)"],
        "techniques": ["T1059.004 - Unix Shell", "T1070.004 - File Deletion"],
    }

def check_false_positive_history(params: CheckFalsePositiveHistoryInput) -> Dict[str, Any]:
    return {"is_known_fp": False, "historical_fp_rate": 0.05, "past_matches": 0}

def enrich_indicators(params: EnrichIndicatorsInput) -> Dict[str, Any]:
    return {"reputation": "MALICIOUS", "threat_actor": "UNKNOWN_RAT", "risk_score": 88}

def synthesize_incident_timeline(params: SynthesizeIncidentTimelineInput) -> Dict[str, Any]:
    ordered = sorted(params.events, key=lambda e: e.get("ts", ""))
    return {"timeline_events": [f"{e.get('ts')} - {e.get('msg')}" for e in ordered]}

def update_alert_status(params: UpdateAlertStatusInput) -> Dict[str, Any]:
    return {"alert_id": params.alert_id, "updated_status": params.status, "notes": params.notes}


# =====================================================================
# 2. PYDANTIC TOOL DEFINITIONS: HOST & ENDPOINT AGENT SKILLS
# =====================================================================

class IsolateHostNetworkInput(BaseModel):
    agent_id: str = Field(description="Wazuh or EDR agent ID assigned to host")
    hostname: str = Field(description="Target host hostname or IP address")
    isolation_mode: str = Field(default="FULL", description="'FULL' (blocks all non-management traffic) or 'PARTIAL'")

class UnisolateHostNetworkInput(BaseModel):
    agent_id: str = Field(description="Wazuh or EDR agent ID")
    reason: str = Field(description="Justification for releasing host network isolation")

class InspectProcessTreeInput(BaseModel):
    agent_id: str = Field(description="Wazuh or EDR agent ID")
    pid: Optional[int] = Field(default=None, description="Specific PID to inspect, or None for top suspicious processes")

class TerminateProcessInput(BaseModel):
    agent_id: str = Field(description="Wazuh or EDR agent ID")
    pid: int = Field(description="Process ID to terminate")
    force: bool = Field(default=True, description="Force termination flag")

class QuarantineFileInput(BaseModel):
    agent_id: str = Field(description="Wazuh or EDR agent ID")
    file_path: str = Field(description="Absolute path to the suspicious file on the target host")

class CollectVolatileArtifactsInput(BaseModel):
    agent_id: str = Field(description="Wazuh or EDR agent ID")
    artifact_types: List[str] = Field(default=["network_connections", "memory_dump", "running_processes"], description="Artifacts to harvest")

class DisableUserAccountInput(BaseModel):
    username: str = Field(description="Target local or Active Directory username")
    domain: Optional[str] = Field(default=None, description="Domain name if AD account")


def isolate_host_network(params: IsolateHostNetworkInput) -> Dict[str, Any]:
    return {
        "status": "ISOLATED",
        "agent_id": params.agent_id,
        "isolation_rule_applied": "iptables/nftables baseline applied blocking external egress",
    }

def unisolate_host_network(params: UnisolateHostNetworkInput) -> Dict[str, Any]:
    return {"status": "UNISOLATED", "agent_id": params.agent_id, "reason": params.reason}

def inspect_process_tree(params: InspectProcessTreeInput) -> Dict[str, Any]:
    return {
        "pid": params.pid or 4120,
        "name": "bash",
        "parent_pid": 1024,
        "parent_name": "sshd",
        "command_line": "bash -c 'echo aWV4... | base64 -d | sh'",
        "children": [4128],
    }

def terminate_process(params: TerminateProcessInput) -> Dict[str, Any]:
    return {"status": "TERMINATED", "pid": params.pid, "agent_id": params.agent_id}

def quarantine_file(params: QuarantineFileInput) -> Dict[str, Any]:
    return {"status": "QUARANTINED", "path": params.file_path, "agent_id": params.agent_id}

def collect_volatile_artifacts(params: CollectVolatileArtifactsInput) -> Dict[str, Any]:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return {"status": "COLLECTED", "artifacts": params.artifact_types, "evidence_package": f"evidence_{stamp}.zip"}

def disable_user_account(params: DisableUserAccountInput) -> Dict[str, Any]:
    return {"status": "DISABLED", "username": params.username}


# =====================================================================
# 3. STATE & NODES
# =====================================================================

class TriageState(TypedDict, total=False):
    alert_id: str
    agent_id: Optional[str]
    hostname: Optional[str]
    src_ip: Optional[str]
    user_sid: Optional[str]
    rule_name: Optional[str]
    pid: Optional[int]
    file_path: Optional[str]
    file_hash: Optional[str]
    missing_fields: List[str]
    raw_alert: Dict[str, Any]
    enriched_context: Dict[str, Any]
    mitre_tactics: List[str]
    timeline: List[str]
    risk_score: float
    decision: str  # "ISOLATE", "MONITOR", "FALSE_POSITIVE", "ESCALATE"
    analyst_approved: bool
    actions_taken: List[str]
    summary: str


def ingestion_node(state: TriageState) -> Dict[str, Any]:
    """Node 1: Normalize the alert. Missing fields are flagged, never invented."""
    alert = state.get("raw_alert", {})
    data = alert.get("data", {})
    fields = {
        "alert_id": alert.get("id"),
        "agent_id": alert.get("agent", {}).get("id"),
        "hostname": alert.get("agent", {}).get("name"),
        "src_ip": data.get("srcip"),
        "user_sid": data.get("user"),
        "rule_name": alert.get("rule", {}).get("description"),
        "pid": int(data["pid"]) if str(data.get("pid", "")).isdigit() else None,
        "file_path": data.get("file_path"),
        "file_hash": data.get("sha256"),
    }
    missing = [k for k in REQUIRED_FIELDS if not fields[k]]
    fields["alert_id"] = fields["alert_id"] or "UNKNOWN-ALERT"
    note = "Alert ingested and fields normalized."
    if missing:
        note += f" WARNING: missing required fields {missing}."
    return {
        **fields,
        "missing_fields": missing,
        "actions_taken": list(state.get("actions_taken", [])) + [note],
    }


def enrichment_node(state: TriageState) -> Dict[str, Any]:
    """Node 2: Run independent enrichment lookups in parallel."""
    hashes = [state["file_hash"]] if state.get("file_hash") else []
    iocs = [i for i in [state.get("src_ip"), *hashes] if i]
    query = " OR ".join(
        q for q in (
            f"src_ip:{state['src_ip']}" if state.get("src_ip") else "",
            f"agent_id:{state['agent_id']}" if state.get("agent_id") else "",
        ) if q
    ) or f"rule:{state.get('rule_name', '')}"

    with ThreadPoolExecutor(max_workers=4) as pool:
        f_logs = pool.submit(query_related_logs, QueryRelatedLogsInput(query_string=query))
        f_mitre = pool.submit(correlate_mitre_tactics, CorrelateMitreTacticsInput(
            event_ids=[state.get("rule_name") or ""], process_hashes=hashes))
        f_fp = pool.submit(check_false_positive_history, CheckFalsePositiveHistoryInput(
            rule_id=state.get("rule_name") or "", host_id=state.get("hostname") or ""))
        f_intel = pool.submit(enrich_indicators, EnrichIndicatorsInput(iocs=iocs)) if iocs else None
        logs, mitre, fp = f_logs.result(), f_mitre.result(), f_fp.result()
        intel = f_intel.result() if f_intel else {"reputation": "UNKNOWN", "risk_score": 0}

    timeline = synthesize_incident_timeline(SynthesizeIncidentTimelineInput(
        alert_id=state["alert_id"], events=logs.get("events", [])))

    return {
        "enriched_context": {"logs": logs, "fp_check": fp, "threat_intel": intel,
                             "techniques": mitre.get("techniques", [])},
        "mitre_tactics": mitre["tactics"],
        "timeline": timeline["timeline_events"],
        "actions_taken": list(state.get("actions_taken", [])) + [
            "Enriched with SIEM logs, threat intel, MITRE mapping, FP history and timeline."],
    }


def threat_classification_node(state: TriageState) -> Dict[str, Any]:
    """Node 3: Evidence-based scoring using all enrichment signals."""
    ctx = state.get("enriched_context", {})
    fp = ctx.get("fp_check", {})
    intel = ctx.get("threat_intel", {})

    score = intel.get("risk_score", 0) * 0.5                       # up to 50
    score += min(len(state.get("mitre_tactics", [])) * 12, 30)      # up to 30
    score += min(ctx.get("logs", {}).get("logs_found", 0), 20)      # up to 20
    if intel.get("reputation") == "MALICIOUS":
        score += 5
    if fp.get("is_known_fp"):
        score -= 50
    score *= (1 - min(fp.get("historical_fp_rate", 0.0), 0.5))
    score = round(max(0.0, min(score, 100.0)), 1)

    if state.get("missing_fields"):
        decision = "ESCALATE"  # cannot act safely without agent/host
    elif score >= ISOLATE_THRESHOLD:
        decision = "ISOLATE"
    elif score >= ESCALATE_THRESHOLD:
        decision = "ESCALATE"
    elif score >= MONITOR_THRESHOLD:
        decision = "MONITOR"
    else:
        decision = "FALSE_POSITIVE"

    # Human-approval gate: no automated containment without sign-off
    note = ""
    if decision == "ISOLATE" and REQUIRE_APPROVAL and not state.get("analyst_approved"):
        decision = "ESCALATE"
        note = " Isolation recommended; awaiting analyst approval."

    return {
        "risk_score": score,
        "decision": decision,
        "actions_taken": list(state.get("actions_taken", [])) + [
            f"Classified as {decision} (Risk Score: {score}).{note}"],
    }


def route_decision(state: TriageState) -> str:
    return state.get("decision", "ESCALATE")


def isolate_node(state: TriageState) -> Dict[str, Any]:
    """Containment: isolate -> inspect -> collect evidence -> terminate -> quarantine."""
    agent_id, actions = state["agent_id"], list(state.get("actions_taken", []))

    iso = isolate_host_network(IsolateHostNetworkInput(
        agent_id=agent_id, hostname=state["hostname"], isolation_mode="FULL"))
    actions.append(f"Host Isolation Executed: {iso['isolation_rule_applied']}")

    proc = inspect_process_tree(InspectProcessTreeInput(agent_id=agent_id, pid=state.get("pid")))
    actions.append(f"Inspected PID {proc['pid']} ({proc['name']}, parent {proc['parent_name']}): {proc['command_line']}")

    # Collect volatile evidence BEFORE killing anything
    col = collect_volatile_artifacts(CollectVolatileArtifactsInput(agent_id=agent_id))
    actions.append(f"Artifacts Collected: Package {col['evidence_package']}.")

    if proc["name"] in PROTECTED_PROCESSES:
        actions.append(f"Skipped terminating protected process {proc['name']} (PID {proc['pid']}); escalate to analyst.")
    else:
        term = terminate_process(TerminateProcessInput(agent_id=agent_id, pid=proc["pid"]))
        actions.append(f"Process Terminated PID {term['pid']} on agent {agent_id}.")

    if state.get("file_path"):
        q = quarantine_file(QuarantineFileInput(agent_id=agent_id, file_path=state["file_path"]))
        actions.append(f"File quarantined: {q['path']}")

    return {"actions_taken": actions}


def monitor_node(state: TriageState) -> Dict[str, Any]:
    return {"actions_taken": list(state.get("actions_taken", [])) + [
        "No containment. Alert kept open for monitoring."]}


def false_positive_node(state: TriageState) -> Dict[str, Any]:
    return {"actions_taken": list(state.get("actions_taken", [])) + [
        "Closed as false positive (benign pattern / low risk)."]}


def escalate_node(state: TriageState) -> Dict[str, Any]:
    reason = (f"missing fields {state['missing_fields']}" if state.get("missing_fields")
              else "needs analyst review/approval")
    return {"actions_taken": list(state.get("actions_taken", [])) + [
        f"Escalated to analyst: {reason}."]}


def reporting_node(state: TriageState) -> Dict[str, Any]:
    """Node 5: Build report and sync the ticket exactly once, with a status matching the decision."""
    decision = state.get("decision", "ESCALATE")
    summary = (
        f"Incident Triage Report - {state.get('alert_id')}\n"
        f"Host: {state.get('hostname')} (IP: {state.get('src_ip')}, Agent ID: {state.get('agent_id')})\n"
        f"Risk Score: {state.get('risk_score')}/100 | Decision: {decision}\n"
        f"MITRE Tactics: {', '.join(state.get('mitre_tactics', [])) or 'n/a'}\n"
        f"Timeline:\n" + "\n".join(f"  {t}" for t in state.get("timeline", [])) + "\n"
        f"Actions Performed:\n" + "\n".join(f"- {a}" for a in state.get("actions_taken", []))
    )
    update_alert_status(UpdateAlertStatusInput(
        alert_id=state.get("alert_id", "UNKNOWN-ALERT"),
        status=STATUS_MAP[decision],
        notes=summary,
    ))
    return {"summary": summary}


# =====================================================================
# 4. WORKFLOW COMPOSITION
# =====================================================================

BRANCHES = {
    "ISOLATE": isolate_node,
    "MONITOR": monitor_node,
    "FALSE_POSITIVE": false_positive_node,
    "ESCALATE": escalate_node,
}


def build_triage_graph():
    """Compiled LangGraph if available, else a plain-Python runner with identical routing."""
    try:
        from langgraph.graph import END, START, StateGraph
    except ImportError:
        def run_chain_simulation(initial_state: TriageState) -> TriageState:
            s = dict(initial_state)
            for node in (ingestion_node, enrichment_node, threat_classification_node):
                s.update(node(s))
            s.update(BRANCHES[route_decision(s)](s))
            s.update(reporting_node(s))
            return s  # type: ignore[return-value]
        run_chain_simulation.invoke = run_chain_simulation  # same interface as LangGraph
        return run_chain_simulation

    builder = StateGraph(TriageState)
    builder.add_node("ingestion", ingestion_node)
    builder.add_node("enrichment", enrichment_node)
    builder.add_node("classification", threat_classification_node)
    for name, fn in BRANCHES.items():
        builder.add_node(name.lower(), fn)
    builder.add_node("reporting", reporting_node)

    builder.add_edge(START, "ingestion")
    builder.add_edge("ingestion", "enrichment")
    builder.add_edge("enrichment", "classification")
    builder.add_conditional_edges(
        "classification", route_decision, {name: name.lower() for name in BRANCHES})
    for name in BRANCHES:
        builder.add_edge(name.lower(), "reporting")
    builder.add_edge("reporting", END)
    return builder.compile()


if __name__ == "__main__":
    sample_alert = {
        "id": "SOC-20261030-007",
        "agent": {"id": "007", "name": "ubuntu-lab-host"},
        "rule": {"description": "Wazuh Alert: Suspicious shell execution & file modification"},
        "data": {"srcip": "10.0.2.15", "user": "root", "pid": "4120",
                 "file_path": "/tmp/payload.sh"},
    }
    initial_state: TriageState = {
        "raw_alert": sample_alert,
        "actions_taken": [],
        "analyst_approved": True,  # set False to see the approval gate escalate instead
    }
    runner = build_triage_graph()
    final_state = runner.invoke(initial_state)
    print("=== FINAL STATE SUMMARY ===")
    print(final_state["summary"])
