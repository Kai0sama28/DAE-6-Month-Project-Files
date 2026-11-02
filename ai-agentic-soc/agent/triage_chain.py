"""
AI-Agentic SOC Triage Engine - Pydantic Tools & LangGraph Chain
Designed for the ai-agentic-soc workspace.
"""

from typing import Dict, List, Optional, Any, TypedDict
from pydantic import BaseModel, Field


# =====================================================================
# 1. PYDANTIC TOOL DEFINITIONS: SIEM AGENT SKILLS
# =====================================================================

class QueryRelatedLogsInput(BaseModel):
    query_string: str = Field(description="Search filter string (e.g. 'src_ip:192.168.1.50 OR user:admin')")
    time_window_minutes: int = Field(default=60, description="Time window in minutes to search backwards from alert timestamp")
    max_results: int = Field(default=100, description="Maximum log entries to return")

class CorrelateMitreTacticsInput(BaseModel):
    event_ids: List[str] = Field(description="List of SIEM event IDs or rule names to map")
    process_hashes: Optional[List[str]] = Field(default=[], description="List of process SHA256 hashes associated with the alert")

class CheckFalsePositiveHistoryInput(BaseModel):
    rule_id: str = Field(description="SIEM rule ID or signature name")
    host_id: str = Field(description="Target host ID or hostname")
    lookback_days: int = Field(default=30, description="Days to look back in historic ticket resolution DB")

class EnrichIndicatorsInput(BaseModel):
    iocs: List[str] = Field(description="List of IOCs (IPs, domains, SHA256 hashes) to look up in threat intelligence feeds")

class SynthesizeIncidentTimelineInput(BaseModel):
    alert_id: str = Field(description="Unique alert identifier")
    events: List[Dict[str, Any]] = Field(description="Unsorted log events collected across SIEM indices")

class UpdateAlertStatusInput(BaseModel):
    alert_id: str = Field(description="Unique alert identifier")
    status: str = Field(description="New alert status: 'IN_PROGRESS', 'CLOSED_FALSE_POSITIVE', 'ESCALATED', or 'CONTAINED'")
    notes: str = Field(description="Summary narrative explaining the status update")


# Dummy tool execution handlers for SIEM Agent
def query_related_logs(params: QueryRelatedLogsInput) -> Dict[str, Any]:
    """Execute SIEM query across indexed logs."""
    return {
        "status": "success",
        "logs_found": 12,
        "sample": f"Found 12 related logs for query '{params.query_string}' in past {params.time_window_minutes} mins."
    }

def correlate_mitre_tactics(params: CorrelateMitreTacticsInput) -> Dict[str, Any]:
    """Map events to MITRE ATT&CK tactics."""
    return {
        "tactics": ["Execution (TA0002)", "Defense Evasion (TA0005)"],
        "techniques": ["T1059.001 - PowerShell", "T1070.004 - File Deletion"]
    }

def check_false_positive_history(params: CheckFalsePositiveHistoryInput) -> Dict[str, Any]:
    """Check historical triage decisions."""
    return {
        "is_known_fp": False,
        "historical_fp_rate": 0.05,
        "past_matches": 0
    }

def enrich_indicators(params: EnrichIndicatorsInput) -> Dict[str, Any]:
    """Query threat intelligence feeds for IOC context."""
    return {
        "reputation": "MALICIOUS",
        "threat_actor": "UNKNOWN_RAT",
        "risk_score": 88
    }

def synthesize_incident_timeline(params: SynthesizeIncidentTimelineInput) -> Dict[str, Any]:
    """Assemble chronological timeline."""
    return {
        "timeline_events": [
            "14:00:02 - Suspicious file downloaded (payload.ps1)",
            "14:00:10 - PowerShell launched with encoded command",
            "14:00:15 - Outbound C2 connection attempted"
        ]
    }

def update_alert_status(params: UpdateAlertStatusInput) -> Dict[str, Any]:
    """Modify SIEM alert ticket state."""
    return {"alert_id": params.alert_id, "updated_status": params.status, "notes": params.notes}


# =====================================================================
# 2. PYDANTIC TOOL DEFINITIONS: HOST & ENDPOINT AGENT SKILLS
# =====================================================================

class IsolateHostNetworkInput(BaseModel):
    agent_id: str = Field(description="Wazuh or EDR agent ID assigned to host")
    hostname: str = Field(description="Target host hostname or IP address")
    isolation_mode: str = Field(default="FULL", description="Isolation level: 'FULL' (blocks all non-management traffic) or 'PARTIAL'")

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


# Dummy tool execution handlers for Endpoint Agent
def isolate_host_network(params: IsolateHostNetworkInput) -> Dict[str, Any]:
    """Execute host isolation via firewall / Active Response script."""
    return {
        "status": "ISOLATED",
        "agent_id": params.agent_id,
        "isolation_rule_applied": "iptables/nftables baseline applied blocking external egress"
    }

def unisolate_host_network(params: UnisolateHostNetworkInput) -> Dict[str, Any]:
    """Remove network isolation rules."""
    return {"status": "UNISOLATED", "agent_id": params.agent_id, "reason": params.reason}

def inspect_process_tree(params: InspectProcessTreeInput) -> Dict[str, Any]:
    """Fetch process hierarchy from target host."""
    return {
        "pid": params.pid or 4120,
        "name": "powershell.exe",
        "parent_pid": 1024,
        "parent_name": "explorer.exe",
        "command_line": "powershell.exe -e aQBlAHgA...",
        "children": [4128]
    }

def terminate_process(params: TerminateProcessInput) -> Dict[str, Any]:
    """Kill process by PID on host."""
    return {"status": "TERMINATED", "pid": params.pid, "agent_id": params.agent_id}

def quarantine_file(params: QuarantineFileInput) -> Dict[str, Any]:
    """Quarantine malware file to secure directory."""
    return {"status": "QUARANTINED", "path": params.file_path, "agent_id": params.agent_id}

def collect_volatile_artifacts(params: CollectVolatileArtifactsInput) -> Dict[str, Any]:
    """Gather volatile memory/netstat evidence."""
    return {
        "status": "COLLECTED",
        "artifacts": params.artifact_types,
        "evidence_package": "evidence_20261030.zip"
    }

def disable_user_account(params: DisableUserAccountInput) -> Dict[str, Any]:
    """Disable compromised user account."""
    return {"status": "DISABLED", "username": params.username}


# =====================================================================
# 3. LANGRAPH STATE DEFINITION & CHAIN NODES
# =====================================================================

class TriageState(TypedDict):
    alert_id: str
    agent_id: str
    hostname: str
    src_ip: str
    user_sid: str
    rule_name: str
    raw_alert: Dict[str, Any]
    enriched_context: Dict[str, Any]
    mitre_tactics: List[str]
    risk_score: float
    decision: str  # "ISOLATE", "MONITOR", "FALSE_POSITIVE", "ESCALATE"
    actions_taken: List[str]
    summary: str


def ingestion_node(state: TriageState) -> Dict[str, Any]:
    """Node 1: Parse alert payload and extract baseline metadata."""
    alert = state.get("raw_alert", {})
    return {
        "alert_id": alert.get("id", "SOC-20261030-001"),
        "agent_id": alert.get("agent", {}).get("id", "007"),
        "hostname": alert.get("agent", {}).get("name", "ubuntu-workstation"),
        "src_ip": alert.get("data", {}).get("srcip", "192.168.1.105"),
        "user_sid": alert.get("data", {}).get("user", "jdoe"),
        "rule_name": alert.get("rule", {}).get("description", "Malware execution detected"),
        "actions_taken": state.get("actions_taken", []) + ["Alert ingested and fields normalized."]
    }


def enrichment_node(state: TriageState) -> Dict[str, Any]:
    """Node 2: Enrich alert with SIEM logs, threat intel, and false positive history."""
    log_results = query_related_logs(QueryRelatedLogsInput(
        query_string=f"src_ip:{state['src_ip']} OR agent_id:{state['agent_id']}"
    ))
    mitre_info = correlate_mitre_tactics(CorrelateMitreTacticsInput(
        event_ids=[state['rule_name']]
    ))
    fp_check = check_false_positive_history(CheckFalsePositiveHistoryInput(
        rule_id=state['rule_name'],
        host_id=state['hostname']
    ))
    
    enriched = {
        "logs": log_results,
        "fp_check": fp_check
    }
    
    return {
        "enriched_context": enriched,
        "mitre_tactics": mitre_info["tactics"],
        "actions_taken": state.get("actions_taken", []) + ["Enriched with SIEM logs & MITRE ATT&CK mapping."]
    }


def threat_classification_node(state: TriageState) -> Dict[str, Any]:
    """Node 3: Calculate risk score and determine response decision."""
    enriched = state.get("enriched_context", {})
    fp_check = enriched.get("fp_check", {})
    
    if fp_check.get("is_known_fp"):
        decision = "FALSE_POSITIVE"
        risk_score = 15.0
    else:
        # High confidence malicious activity detected
        decision = "ISOLATE"
        risk_score = 85.0
        
    return {
        "risk_score": risk_score,
        "decision": decision,
        "actions_taken": state.get("actions_taken", []) + [f"Threat classified as {decision} (Risk Score: {risk_score})."]
    }


def tool_dispatcher_node(state: TriageState) -> Dict[str, Any]:
    """Node 4: Execute endpoint actions based on triage decision."""
    decision = state.get("decision")
    agent_id = state.get("agent_id", "007")
    actions = list(state.get("actions_taken", []))
    
    if decision == "ISOLATE":
        # 1. Isolate target host network
        iso_res = isolate_host_network(IsolateHostNetworkInput(
            agent_id=agent_id,
            hostname=state.get("hostname", "unknown"),
            isolation_mode="FULL"
        ))
        actions.append(f"Host Isolation Executed: {iso_res['isolation_rule_applied']}")
        
        # 2. Terminate malicious process
        term_res = terminate_process(TerminateProcessInput(
            agent_id=agent_id,
            pid=4120
        ))
        actions.append(f"Process Terminated PID {term_res['pid']} on agent {agent_id}.")
        
        # 3. Collect volatile artifacts
        col_res = collect_volatile_artifacts(CollectVolatileArtifactsInput(
            agent_id=agent_id
        ))
        actions.append(f"Artifacts Collected: Package {col_res['evidence_package']}.")
        
    elif decision == "FALSE_POSITIVE":
        up_res = update_alert_status(UpdateAlertStatusInput(
            alert_id=state["alert_id"],
            status="CLOSED_FALSE_POSITIVE",
            notes="Automated triage identified benign historical pattern."
        ))
        actions.append(f"Alert status updated: {up_res['updated_status']}")
        
    return {"actions_taken": actions}


def reporting_node(state: TriageState) -> Dict[str, Any]:
    """Node 5: Generate final incident summary and update SIEM ticket."""
    summary = (
        f"Incident Triage Report - {state.get('alert_id')}\n"
        f"Host: {state.get('hostname')} (IP: {state.get('src_ip')}, Agent ID: {state.get('agent_id')})\n"
        f"Risk Score: {state.get('risk_score')}/100 | Decision: {state.get('decision')}\n"
        f"MITRE Tactics: {', '.join(state.get('mitre_tactics', []))}\n"
        f"Actions Performed:\n" + "\n".join(f"- {a}" for a in state.get("actions_taken", []))
    )
    
    # Sync with SIEM ticket
    update_alert_status(UpdateAlertStatusInput(
        alert_id=state.get("alert_id", "SOC-001"),
        status="CONTAINED" if state.get("decision") == "ISOLATE" else "TRIAGED",
        notes=summary
    ))
    
    return {"summary": summary}


# =====================================================================
# 4. LANGRAPH WORKFLOW COMPOSITION
# =====================================================================

def build_triage_graph():
    """Assemble the state graph if langgraph is available, otherwise return node map."""
    try:
        from langgraph.graph import StateGraph, START, END
        
        builder = StateGraph(TriageState)
        
        # Add chain nodes
        builder.add_node("ingestion", ingestion_node)
        builder.add_node("enrichment", enrichment_node)
        builder.add_node("classification", threat_classification_node)
        builder.add_node("tool_dispatcher", tool_dispatcher_node)
        builder.add_node("reporting", reporting_node)
        
        # Define execution flow
        builder.add_edge(START, "ingestion")
        builder.add_edge("ingestion", "enrichment")
        builder.add_edge("enrichment", "classification")
        builder.add_edge("classification", "tool_dispatcher")
        builder.add_edge("tool_dispatcher", "reporting")
        builder.add_edge("reporting", END)
        
        return builder.compile()
    except ImportError:
        # Fallback runner for standalone script testing
        def run_chain_simulation(initial_state: TriageState) -> TriageState:
            s1 = {**initial_state, **ingestion_node(initial_state)}
            s2 = {**s1, **enrichment_node(s1)}
            s3 = {**s2, **threat_classification_node(s2)}
            s4 = {**s3, **tool_dispatcher_node(s3)}
            s5 = {**s4, **reporting_node(s4)}
            return s5
        return run_chain_simulation


if __name__ == "__main__":
    sample_alert = {
        "id": "SOC-20261030-007",
        "agent": {"id": "007", "name": "ubuntu-lab-host"},
        "rule": {"description": "Wazuh Alert: Suspicious PowerShell execution & file modification"},
        "data": {"srcip": "10.0.2.15", "user": "root"}
    }
    
    initial_state: TriageState = {
        "alert_id": "",
        "agent_id": "",
        "hostname": "",
        "src_ip": "",
        "user_sid": "",
        "rule_name": "",
        "raw_alert": sample_alert,
        "enriched_context": {},
        "mitre_tactics": [],
        "risk_score": 0.0,
        "decision": "",
        "actions_taken": [],
        "summary": ""
    }
    
    runner = build_triage_graph()
    if callable(runner):
        final_state = runner(initial_state)
        print("=== FINAL STATE SUMMARY ===")
        print(final_state["summary"])
