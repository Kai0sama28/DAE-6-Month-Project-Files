# Demonstrate SOC Fundamentals

**Workspace:** `DAE-6-Month-Project-Files` (DAE 6-month cybersecurity program, capstone `ai-agentic-soc`)
**Prepared:** 2026-11-22
**Purpose:** Show how the project demonstrates SOC fundamentals — three or more SOC roles, a monitoring tool covering two or more network activity types, two alerts generated/investigated/resolved, and threat detection analysis — using the SOC1 deliverables (SOC Operations, SIEM Implementation, Threat Detection Principles, Incident Response Methodology) plus the live Wazuh lab and the AI-agentic triage engine. Paths and line numbers are given so every claim can be checked.

---

## Rubric coverage at a glance

| Rubric requirement | Status | Primary evidence |
|---|---|---|
| ≥3 SOC roles | **Met** — Tier 1 / Tier 2 / Tier 3 / management + advisory owners, with named analyst in worked cases | `security_operations_center_1/SOC_Operations.md`; `Incident_Response_Methodology.md` |
| 1 monitoring tool with ≥2 network activity types | **Met** — Wazuh 4.14.7 monitors authentication, FIM, Windows event logs, vulnerability/SCA, network-sensor and volume-anomaly activity | `Security_Monitoring_1/Monitoring Implementation.md`; `Threat_Detection_Principles.md` |
| 2 alerts generated, investigated and resolved | **Met** — live case `SOC-CASE-2026-0142` (40112) and worked exercise `SOC-CASE-2026-0143`; multiple additional generated reports | `security_operations_center_1/Incident Response Documentation_ Case Management, Escalation, and Ransomware Report.md`; `Threat_Detection_Principles.md`; `ai-agentic-soc/reports/` |
| ≥1 threat detection analysis | **Met** — seven-phase methodology, rule-mechanism analysis, three scenarios, worked investigation with findings/gaps | `security_operations_center_1/Threat_Detection_Principles.md`; `incident_response_1/Incident Detection and Analysis.md` |

---

## 1. SOC roles and responsibilities (≥3)

`security_operations_center_1/SOC_Operations.md:118–140` defines the escalation tiers that double as SOC roles:
- **Tier 1 — Triage**: "Acknowledge, validate, block source IP" — every new alert.
- **Tier 2 — Investigation**: "Deep analysis, endpoint isolation, credential rotation, forensics initiation" — triggered by D3 = login succeeded, High severity, or host access needed.
- **Tier 3 — Advanced IR**: "Full forensics, eradication, rebuild from known-good" — triggered by D5 = post-compromise indicators or Critical severity.
- **Management / on-call lead**: "Client & external notification, resourcing" — triggered by Critical, personal data, or notification duties.

`security_operations_center_1/Incident_Response_Methodology.md:375–401` repeats the four-tier table (Tier 1 Triage, Tier 2 Investigation, Tier 3 Advanced/IR, Management/shift lead) plus **Advisory non-SOC** owners (system owners, IT, comms, legal) for actions outside SOC authority, and gives triggers: "D3=YES → Tier 2 within 15 min", "D5=YES → Tier 3 + Management within 30 min", "SLA over-run → automatic escalation one tier".

Roles are **named in the worked case** — `Incident Response Documentation_ Case Management, Escalation, and Ransomware Report.md:138`: Kyrell Green, Tier 1 case owner; Tier 2 responder engaged (mandatory on confirmed success); Management/shift lead notified at High; Tier 3/forensics "Not engaged — no trigger"; system owner/lab admin for hardening; legal/privacy "Assessed, not notified"; external regulator "Not applicable" (see also `Incident_Response_Methodology.md:717–728`, a communications log with named recipients, channels, messages and acknowledgements).

Supporting SOC operations evidence in `SOC_Operations.md`:
- Toolchain purpose (lines 25–31): "the **SIEM detects**, the **ticketing platform tracks**, and **monitoring watches** continuously"; tool summary at lines 77–85 (Wazuh, TheHive, Wazuh FIM, Suricata, mock EDR).
- Alert-handling workflow as a Mermaid diagram (lines 89–110) and objective escalation triggers D1–D7 in `Incident_Response_Methodology.md:258–272`.
- Shift handover (lines 159–241): "verbal-only handovers are not permitted in this SOC. The communication rule: if it isn't written in TheHive, it isn't handed over" (191–194), plus a full handover template (227–241).
- Ten-step incident handling procedure (lines 260–273): detect → acknowledge → verify → scope → triage → escalate → contain → eradicate/recover → document → review/close, applied to `SOC-CASE-2026-0142`.

## 2. Monitoring tool with ≥2 network activity types

The monitored platform is real, not a mock: `Security_Monitoring_1/Monitoring Implementation.md:29–36` — "A working, live monitoring platform was implemented on the lab host — not a mock or a design on paper… Wazuh 4.14.7 SIEM (manager + indexer + dashboard + REST API) running in Docker; three enrolled endpoint agents… Suricata 8.0… downstream triage engine."

`Monitoring Implementation.md:166–176` documents **four data-source classes** integrated into Wazuh (requirement ≥3): DS-1 Windows event logs (agent 007), DS-2 Linux auth/system logs (agents 002/008), DS-3 FIM (agents 002/007/008), DS-4 vulnerability detection and SCA (agent 007). Ports/components at lines 150–162 include agent channel 1514/1515, dashboard 443, indexer 9200, API 55000, Suricata/EveBox 5636.

Activity types actually monitored (`Threat_Detection_Principles.md:165–177`, `network_security_1/Monitor_and_Respond_Network_Security_Events.md:80–88`):
1. **Authentication events** — `sshd`/PAM failures and successes, valid-account vs invalid-user brute force, session open/close timing, sudo/admin commands. Real chain: `5716 → 5760 → 5763` (frequency 8/120 s, level 10), `5503 → 5551`, `40111`, `40112` (level 12, MITRE `T1078` + `T1110`).
2. **File integrity changes** — Wazuh FIM/syscheck rules `550`, `510`; `/etc/shadow` changes, Windows ADS/service/account/time changes (`61104`, `60110`, `60132`).
3. **Network-sensor events** — Suricata `ET SCAN Potential SSH Scan`, `gid 1`, `sid 2001219`, severity 2, from `203.0.113.77:51422 → 192.168.64.3:22/TCP` (`Threat_Detection_Principles.md:300–325`). The document is candid: "The detection logic is real and the signature match is genuine; the packet timestamps are an artefact of the capture" (offline pcap replay).
4. **Vulnerability/SCA and volume anomalies** — rule `23504` (7 GIMP CVEs) and internal rule `11` (a level-4 volume anomaly, "average 561, reached 1812", 10 minutes before the successful brute-force wave).
5. **Endpoint behaviour** — process/network/file telemetry via the mock EDR pillar (labelled as mock, not a live EDR product).

The capstone adds a genuinely integrated ingestion path: `ai-agentic-soc/docs/ARCHITECTURE.md:12–23` — "The SIEM pillar is no longer a locally simulated Splunk/FastAPI mock. It is replaced by the real Wazuh 4.14.7 single-node deployment… live pulls from the Wazuh API." Code confirms `ai-agentic-soc/siem/indexer_client.py:10–32`: `DEFAULT_URL = "https://localhost:9200"`, `DEFAULT_INDEX_PATTERN = "wazuh-alerts-*"`, with the note "Wazuh 4.x removed the 3.x `/security-events` API route, so alerts are only reachable through the indexer."

Dashboards (`Security_Monitoring_1/Security Reporting.md:313–327`) include Security Events, Agents Status, Top Alerts, MITRE ATT&CK, Event Distribution, Integrity Monitoring, and Vulnerability Detection, with metrics such as MTTD `< 5 s` and MTTI `12–18 s` (lines 169–181).

## 3. Two alerts generated, investigated and resolved

### Case 1 — live investigation `SOC-CASE-2026-0142` (the actual OpenCTI/TheHive case #142)

- **Generated:** Wazuh rule `40112`, level 12, at `2026-10-01T17:50:09.931Z`: "Accepted password for labtester from 192.168.64.3 port 49024 ssh2", MITRE `T1110` + `T1078` (`Threat_Detection_Principles.md:688–697`; `Incident Response Documentation…:133–144`).
- **Investigated:** `Incident_Response_Methodology.md:658–674` records the decisive evidence — the alert `_id` `4VOW-KABMZhxAQGakjXR` in index `wazuh-alerts-4.x-2026.10.01`, the log line, and the `5501`/`5502` session pair bounding the session to **71 ms**. `Threat_Detection_Principles.md:771–797` reconstructs three batches of four parallel SSH connections, with the credential succeeding on the fourth attempt of one connection. `Incident Detection and Analysis.md:66–83` documents pivots before and after the event, ATT&CK (`T1110`, `T1078`) and Diamond Model analysis.
- **Resolved:** `Incident Response Documentation…:187–202` — source blocked at T+20, credential rotated, password SSH disabled and key-only enforced; "no malware, persistence, backdoor account, or added SSH key found"; no restoration required; elevated 30-day monitoring; FIM baseline deliberately not reset. Closure (`…:251–264`): closed by Kyrell Green (Tier 1) with Tier 2 review, `2026-10-01 18:15 UTC`, final severity High, time to declare ≈2 min, time to contain ≈20 min. `Incident_Response_Methodology.md:754–770` corroborates.

### Case 2 — worked exercise `SOC-CASE-2026-0143` (distinct case, dedicated detection-principles exercise)

- **Generated:** starting alert `40112`, level 12, `2026-10-01T17:50:09.931+0000`, agent `002` / Kali / `192.168.64.3`, `dstuser labtester` (`Threat_Detection_Principles.md:641–658`, `:688–697`).
- **Investigated:** hypotheses H1 "credential attack against a real account", H2 "achieved a successful authentication", H3 "post-access activity followed" (lines 641–658); negative findings at lines 809–818 (no post-login command execution, no `sudo` by `labtester`, no SSH persistence, no file changes at attack time, no lateral movement, no C2); findings F1–F9 at lines 917–931.
- **Resolved:** decisions at lines 878–895 — open case with credential-attack template, register observables, escalate Tier 2, rotate `labtester`, enforce key-only SSH, harden `sshd` limits (`MaxStartups`), **do not block** `192.168.64.3` because it is the monitored host's own address, open 30-day elevated monitoring, and add password-spraying detection coverage. The human gate is explicit (892–895): "an automated or AI-assisted triage layer may recommend actions 4–6 but never performs them."

### Additional generated/triaged alerts (supporting evidence)

The AI-agentic engine produces its own investigated reports: `ai-agentic-soc/reports/SOC-20261022-001.md:8–27` (SSH brute force from `192.168.64.1`, rule `100002` level 12, no successful authentication, severity Medium, DRAFT pending review); `SOC-20261105-013.md:10–24` (Responder-style LLMNR/NBT-NS poisoning, ARP spoofing, WPAD/NTLM capture, rule `100057`, 250 correlated events, analyst-approved); `LATEST.md:1–27` (OOM kill of Wireshark, rule `5108`, no compromise found). These are engine outputs, not the live lab case — label them accordingly.

## 4. Threat detection analysis

`security_operations_center_1/Threat_Detection_Principles.md` is the dedicated analysis document and sets a high evidence standard at lines 18–33: "Every rule fragment, rule ID, level, threshold, timestamp and alert count … was read from the live lab, not from memory", with labels "**Real evidence** — output produced by the running lab, quoted verbatim" and "**Designed / not deployed** — logic that is correct and specified … but is not currently loaded on the manager."

- **Rule anatomy and mechanisms** (lines 137–177): explains `id`, `level`, `if_matched_sid`, `if_matched_group`, `if_group`, `frequency`, `timeframe`, `ignore`, `same_source_ip`/`same_user`/`same_host`, `mitre`, `group`, `description`; classifies detections into signature/single-event (`5716`, `5758`, `550`), correlation/frequency (`5763`, `5712`, `5551`, `40111`, `2502`), composite/state sequence (`40112`) and statistical/anomaly (internal rule `11`). Line 179: "A signature match tells you what happened. A frequency match tells you how much is happening… A composite match tells you the outcome…"
- **Three distinct scenarios** (lines 272–345): A — credential attack against a valid account (`sshd`/PAM, `T1110`, `T1110.001`, `T1078`, `T1021.004`); B — network reconnaissance (Suricata `sid 2001219`); C — unauthorised host/account state change (FIM/syscheck, syscollector, "Was the change authorised?").
- **Indicator categories** (lines 59–66, 713–728): five families — network (source/destination address and port), host (target account, authorisation event), behavioural (failure volume, failure→success, session duration, volume anomaly), network-sensor (Suricata scan signature), contextual (asset, vulnerability).
- **Seven-phase methodology** (lines 64 and `incident_response_1/Incident Detection and Analysis.md:48–83`): mapped to NIST SP 800-61, MITRE ATT&CK and the Diamond Model, with evidence discipline — "Hypothesis-driven", "Disprove-first", "Observation ≠ inference".
- **Findings and gaps** (`Threat_Detection_Principles.md:917–944`): findings F1–F9 and gaps G1–G8 — no notification path, custom rule `100010` not deployed, `40112` silently depends on `5715`'s `authentication_success` tag, duplicate high-severity rules, unactioned rule-11 flood, password spraying undetectable (`same_source_ip` only), no live Suricata→Wazuh integration, journald-only endpoint visibility.
- **Capstone correlation engine** supports the analysis: `ai-agentic-soc/agent/correlation.py:1–30` defines relations `SAME_AGENT`, `SAME_SOURCE_IP`, `SAME_USER`, `SAME_RULE_GROUP`, `PRIOR`, `POST`, with `SUCCESS_RULE_IDS` and `FAILURE_RULE_IDS`; `ai-agentic-soc/docs/TECHNICAL_DOCUMENTATION.md:188–200` explains query windows and deterministic narrative flags. Evaluation (`ai-agentic-soc/evals/results/soc-eval-2026-11-cases-llm-EVALUATION.md:10–16`): 45/50 investigations completed, 43/50 correct ATT&CK any-technique.

## 5. Honest qualifications

1. **Stale claims in older documents.** Custom rule `100010`, email notification, Active Response, the Wazuh 3.x `/security-events` route, and an automatic Wazuh→TheHive connector appear in older SOC/SIEM/network documents but are contradicted by live verification: `Threat_Detection_Principles.md:35–50` ("Custom rule `100010` is not deployed", "Email notification is not enabled"), `Incident_Response_Methodology.md:338–350` ("G1 — No alert connector. Wazuh → TheHive is not wired"; Active Response commented out). Present live detections as **stock Wazuh rules**.
2. **Suricata status is time-dependent.** Authentic signature match, but offline pcap replay with synthetic 2002 timestamps; not live Wazuh ingestion (`Monitoring Implementation.md:345–347`, `Threat_Detection_Principles.md:300–325`).
3. **Screenshot caveat.** Several captions ask for live-console verification (`SOC_Operations.md:285–290`); `ai-agentic-soc/screenshots/UTM_Docker_Wazuh_Deployment.png` is 0 bytes and is a placeholder, not evidence. Valid screenshots exist (`agent deployment.png`, `agent deployed.png`, `Ping.png`, `SOC Test Server.jpg`).
4. **Later remediation is separate.** `incident_response_1/Incident Detection and Analysis.md:71` records custom rules `100030`–`100032` deployed 2026-10-13; this does not retroactively validate `100010`.
5. **Engine vs. lab.** Capstone-generated reports are triage-engine outputs with a human approval gate, not autonomous SOC actions; the case-study explicitly lists authentication and RBAC as future work before exposing the API/dashboard beyond loopback (`docs/ai-agentic-soc-case-study.md:277–283`).

## 6. Conclusion

SOC fundamentals are demonstrated across all four areas: a defined four-tier role model with named analysts and handover discipline; a live Wazuh SIEM monitoring five-plus activity types; two fully investigated cases (`0142` live, `0143` exercise) with containment/hardening outcomes; and a rigorous threat-detection analysis built on real rule chains, three scenarios, a seven-phase method and explicit gap tracking. The main risk to a reviewer is internal inconsistency between older design documents and later live-verified corrections; citing the dated, verification-first documents avoids overclaiming.

### Related rubric write-ups

- `implement and explain advanced cybersecurity defense strategies.md`
- `implement incident response and handling.md`
- `develop and implement security policies and governance.md`
- `produce effective security documentation.md`
