# Kyrell Green — Cybersecurity Program & AI-Agentic SOC Capstone

---

## Slide 1: AI-Agentic SOC triage engine: build, tools and evidence

CAPSTONE PROJECT UPDATE · DAE CYBERSECURITY PROGRAM

Kyrell Green · SOC Analyst track · Graduation December 2026


> Notes: Overview of the six-month journey, how each rubric deliverable feeds the capstone, and where the capstone stands today.

---

## Slide 2: The triage engine and its detection stack

Wazuh, Suricata, TheHive and Wireshark surround an agent that triages alerts first.

### Identity

Mock, Okta-shaped API: users and login history

### SIEM

Real Wazuh 4.14.7 in Docker: alerts and history

### EDR

Mock, CrowdStrike-shaped API: process, network, file telemetry

Pipeline: LangGraph supervisor → MITRE timeline and risk summary → human approval gate


> Notes: Wazuh replaced the original mock SIEM, so the agent is exercised against real detections. Alerts are read from the Wazuh indexer because Wazuh 4.x has no alerts API route.

---

## Slide 3: Wazuh dashboard: the analyst's single view

![Wazuh MITRE ATT&CK dashboard for the Kali agent](images/wazuh-mitre-attack-kali.jpg)

### What the dashboard does

- Security events and rule levels in one console
- MITRE ATT&CK view: password guessing, SSH, brute force
- Top tactics: Credential Access, Lateral Movement
- Same indexer data feeds the triage agent

> Notes: MITRE ATT&CK dashboard filtered to the Kali agent, from the lab. Alerts live in the Wazuh indexer, which both the dashboard and the agent read.

---

## Slide 4: Wazuh agents: eyes on every endpoint

![Wazuh Endpoints view with an active agent](images/wazuh-agents-endpoints.jpg)

### What agents do

- Collect logs, file changes and inventory
- Stream events to the manager over TCP 1514
- Enrol over TCP 1515
- Live fleet: Kali 002, Windows 007, Ubuntu 008

> Notes: Endpoints view from the first enrolment capture, showing one active agent on v4.14.7. The live lab now has three agents.

---

## Slide 5: Kali Linux VM: attack and detection

![Hydra brute-force run against the Kali endpoint](images/kali-hydra-brute-force.jpg)

![Rule 40112 level 12 alert, failures followed by a success](images/kali-rule-40112-access.jpg)

Hydra brute-force run against the Kali endpoint

Rule 40112, level 12: failures followed by a success

Kali runs in UTM with Wazuh agent 002, and acts as both target and attack source.


> Notes: Same-process correlation showed three failures then a success on one connection. The session lasted 71 ms.

---

## Slide 6: Endpoint detection on the Windows agent

![Host anomaly scan for Windows agent 007](images/windows-endpoint-anomaly-scan.jpg)

### Endpoint detection

- Rootcheck found NTFS alternate data streams
- File integrity monitoring watches file changes
- Vulnerability detection: 7 CVEs on agent 007
- Anomaly, not confirmed malware, until verified

> Notes: Host anomaly scan for agent 007. 18 rootcheck events across three paths. Wording stays cautious because the report does not confirm malware.

---

## Slide 7: A second line of defense around the setup

### Suricata

Network IDS watches traffic. Rule ET SCAN Potential SSH Scan fired on replayed traffic.

Status: offline replay, not yet in Wazuh

### TheHive

Case management. Each alert becomes a tracked case with tasks, observables and a timeline.

Status: running, connector not wired yet

### Wireshark

Packet tracing. Capture filters at capture time, display filters at analysis time.

Status: verified on macOS, Kali analysis done

Wazuh sees hosts. Suricata and Wireshark see the wire. TheHive tracks the response.


> Notes: Layered detection: host agents, network IDS and packet capture agree or disagree. TheHive holds the human-approved response record.

---

## Slide 8: One real case ties it together

SOC-CASE-2026-0142: SSH brute force that succeeded against the Kali endpoint (T1110, T1078)

4th

password attempt accepted

71 ms

session length, no activity logged

~2 min

detection to declaration

High

severity, scored with the matrix

Wazuh rule 40112 fired, the case was scored, the source blocked, and isolation was declined with a written reason. The source address was the lab host itself, a self-generated test.


> Notes: This case uses the policy, the IR template, the escalation matrix and Wazuh monitoring in one flow. The template and methodology documents hold the full timeline.

---

## Slide 9: How the rubric feeds the capstone

| Rubric deliverable | Evidence in the repo | Role in the capstone |
|---|---|---|
| Security policy, incident response plan | Comprehensive Security Policy, IR Plan | Human approval gate; containment never auto-executed |
| Encryption and hashing | AES-256 and SHA-256 demo | Secrets stay in .env; FIM integrity checks |
| Vulnerability and threat intel | Nmap scan, Vidar analysis, OpenCTI plan | Enrichment and MITRE ATT&CK mapping |
| Topology, protocols, subnetting | Topology and Protocols reports | The 10.11.0.0/22 LAN hosting Wazuh |
| Firewall, IDS, IPS, monitoring | Firewall report, Monitor and Respond | Real alert source: Wazuh rule 100010, T1110 |
| SOC operations, case management | IR Template, Methodology | Evidence bundle, timeline, analyst report |


> Notes: Every rubric item is a building block. None of it is stand-alone coursework: the policy defines the approval gate, the network work defines the lab, the SOC work defines the investigation flow.

---

## Slide 10: Next steps

### Build

LangGraph supervisor agent with tool calls to the three evidence pillars

### Close gaps

Wire Wazuh into TheHive, feed Suricata into Wazuh, and turn on alert notifications

### Publish

Replace the portfolio project placeholders with the capstone and best rubric work

Goal: a SOC Analyst role, with the capstone as proof.


> Notes: Close on the three actions. The portfolio site config still holds placeholder project entries.

