"""Ground-truth taxonomy for the evaluation dataset.

The label is assigned by the generator from the scenario that built the case.
It is never inferred from text and never produced by the LLM.
"""

from __future__ import annotations

from typing import Dict, Tuple

LABELS: Tuple[str, ...] = (
    "credential_stuffing",
    "brute_force",
    "phishing",
    "ransomware_precursor",
    "benign",
)

LABEL_PREFIX: Dict[str, str] = {
    "credential_stuffing": "CS",
    "brute_force": "BF",
    "phishing": "PH",
    "ransomware_precursor": "RP",
    "benign": "BN",
}

LABEL_DISPLAY: Dict[str, str] = {
    "credential_stuffing": "Credential stuffing",
    "brute_force": "Brute force",
    "phishing": "Phishing",
    "ransomware_precursor": "Ransomware precursor",
    "benign": "Benign",
}

SEVERITIES: Tuple[str, ...] = ("low", "medium", "high", "critical")
VERDICTS: Tuple[str, ...] = ("true_positive", "benign", "false_positive")
ACTIONS: Tuple[str, ...] = ("monitor", "investigate", "escalate", "contain")
DIFFICULTIES: Tuple[str, ...] = ("easy", "medium", "hard")

MITRE_BY_LABEL: Dict[str, Tuple[str, ...]] = {
    "credential_stuffing": ("T1110.004",),
    "brute_force": ("T1110.001",),
    "phishing": ("T1566", "T1204.002", "T1059.001"),
    "ransomware_precursor": ("T1490", "T1486", "T1053.005"),
    "benign": (),
}

MITRE_NAMES: Dict[str, str] = {
    "T1110.004": "Credential Stuffing",
    "T1110.001": "Password Guessing",
    "T1110.003": "Password Spraying",
    "T1078": "Valid Accounts",
    "T1566": "Phishing",
    "T1204.002": "Malicious File",
    "T1059.001": "PowerShell",
    "T1490": "Inhibit System Recovery",
    "T1486": "Data Encrypted for Impact",
    "T1053.005": "Scheduled Task",
    "T1070.004": "File Deletion",
}

MITRE_TACTICS: Dict[str, str] = {
    "T1110.004": "Credential Access",
    "T1110.001": "Credential Access",
    "T1110.003": "Credential Access",
    "T1078": "Defense Evasion",
    "T1566": "Initial Access",
    "T1204.002": "Execution",
    "T1059.001": "Execution",
    "T1490": "Impact",
    "T1486": "Impact",
    "T1053.005": "Persistence",
    "T1070.004": "Defense Evasion",
}

# If any of these strings appear in model-visible prose, the case has leaked
# its answer and would make the evaluation invalid.
FORBIDDEN_PROSE_TERMS: Tuple[str, ...] = (
    "credential stuffing",
    "credential-stuffing",
    "brute force",
    "brute-force",
    "phishing",
    "ransomware",
    "benign",
    "malicious",
    "ground truth",
    "false positive",
    "true positive",
)

BENIGN_SCENARIOS: Tuple[str, ...] = (
    "authorized_password_change",
    "windows_update_service",
    "routine_admin_ssh",
    "sca_failure_summary",
    "vulnerability_scan",
    "dcom_timeout_noise",
    "updater_service_install",
    "backup_job",
    "new_city_mfa_login",
    "typo_failures_then_success",
)
