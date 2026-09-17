# Incident Response Plan — SOC Lab

**Author:** Kyrell Green
**Date:** 2026-09-14
**Module:** Cyber Threats & Vulnerabilities / SOC Security Analyst track
**Scope:** Incident Response Plan for the Agentic SOC lab environment — detecting security
incidents, containing them, eradicating the root cause, and recovering, with a worked example
tied to the live SOC lab (Wazuh manager, Kali Linux endpoint, firewall/IDS/IPS pipeline).

---

## 1. Purpose

This plan defines how security incidents are **detected, contained, eradicated, and recovered
from** in the SOC lab, using the NIST SP 800-61 incident-response lifecycle
(Preparation → Detection & Analysis → Containment → Eradication → Recovery → Post-Incident).
It is designed so that the human analyst keeps final authority over every response action —
the same hard rule the AI-Agentic SOC project enforces with its human-in-the-loop approval gate.

Every technical control referenced below already exists in the lab environment:

| Control | Location | Role in response |
|---|---|---|
| Wazuh manager + agents (SSH brute-force detection live) | `single-node-wazuh` Docker on the lab Mac | Detection & evidence (SIEM) |
| Kali Linux (Wazuh agent enrolled) | UTM VM, `10.11.0.0/22` | Monitored endpoint (the host under test) |
| Firewall / IDS / IPS pipeline (rule-based detect → decide → respond) | SOC lab network | Containment enforcement |
| Wazuh FIM (file integrity monitoring) | Wazuh agent on endpoints | Detection of file changes / malware writes |
| Threat intelligence IoC checks | OpenCTI / Threat-Intel module | Detection enrichment, eradication verification |

---

## 2. Incident Detection (Method #1 — signature/log-correlation via SIEM & IDS)

The primary detection method is **signature- and rule-based detection through the SIEM
(Wazuh) plus the network IDS**, correlating log and network evidence against known-bad
patterns.

How it works in the lab:

1. The Wazuh agent on the Kali endpoint ships authentication, process, and file events to
   the manager.
2. Wazuh rules fire on known-bad behavior. **Worked example already demonstrated in the lab:**
   Wazuh rule `100010` (SSH brute-force attempt) detects repeated failed logins and maps to
   MITRE technique **T1110 — Brute Force** (level-tagged alerts visible via
   `GET /security-events` on the Wazuh API).
3. The network-side Suricata IDS rules (firewall/IDS/IPS pipeline) flag the same behavior at
   the wire level (e.g., many SSH auth attempts from one source), confirming the host-based
   alert — detection by two independent sensors reduces false positives.
4. **Secondary detection methods (defense in depth):**
   - **Host-based FIM (Wazuh syscheck):** detects when files in monitored paths change on
     Kali — this is how a ransomware encoder or dropper write would first be caught.
   - **Behavioural/anomaly:** process + network telemetry (EDR layer) flags mass file
     renames, rapid process spawns, or outbound beaconing to suspicious IPs — a
     *post-compromise* indicator.

Trigger for this plan: any alert rated **level 10+**, any confirmed **T1110 / T1566 / T1486
(MITRE-mapped) hit, or any IoC match** (hash/IP/domain from threat intel).

---

## 3. Containment Strategy (Strategy #1 — network + host isolation)

The containment strategy is **isolate and deny** — cut off the incident's ability to spread
*before* eradication, using layered network and host actions. Containment is a
**human-approved** decision in this lab; it is never executed automatically.

Immediate actions (short-term containment — stops lateral movement):

1. **Block at the network edge:** add a deny rule on the firewall/IPS for the attacker
   source IP and any confirmed C2/beacon destination so the affected host cannot reach the
   attacker and the attacker cannot reach the lab.
2. **Isolate the affected endpoint:** disconnect the Kali VM from the network
   (disable its interface at the hypervisor) to stop lateral movement and further
   exfiltration/encryption.
3. **Disable affected credentials/accounts:** suspend the compromised user session and
   rotate credentials of any account seen in the alerts — this stops reuse of stolen
   SSH keys or passwords.

Longer-term containment options kept ready: VLAN segmentation (moving the compromised host
to a quarantined segment with deny-all default), and host-level firewall drop rules if
network isolation at the edge is not sufficient.

---

## 4. Eradication Steps

Eradication removes the root cause and the attacker's foothold so the incident cannot resume.

1. **Scope the compromise:** collect and review the MITRE-tagged alert timeline and run an
   IoC sweep on the endpoint (running processes, listening services, autoruns, recently
   modified files) to identify every artifact.
2. **Kill and remove:** terminate the malicious process(es), delete the malicious files and
   any persistence mechanisms (services, cron jobs, startup entries, scheduled tasks)
   identified in the sweep.
3. **Remove attacker access:** delete any backdoor accounts, SSH keys, or credentials the
   attacker added.
4. **Patch the root cause:** fix the vector that allowed the incident — in the brute-force
   example, disable password-based SSH and move to key-only authentication, then update the
   system to the latest patched state.
5. **Re-image if confirmed:** if the host is confirmed substantially compromised (ransomware
   encryption, credential theft), the NIST-preferred approach is a full reinstall from a
   known-good image rather than in-place cleanup — this is the backup containment strategy.
6. **Verify eradication:** rescan with the IDS and Wazuh (no new alerts), re-check the IoCs
   (hash no longer present), and only then reset the FIM baseline so future detections are
   against a clean state.

---

## 5. Recovery Steps

Recovery returns the environment to normal operation, monitored enough that any recurrence
is caught early.

1. **Restore from verified backups:** reinstate the affected host from the most recent
   known-good backup (restore tested — backups that cannot be restored are not backups).
2. **Verify integrity:** confirm restored files match the FIM baseline and confirm no IoCs
   are present before reconnect.
3. **Reconnect incrementally:** bring the host back onto the network, confirm normal
   operation, and re-enable the affected services (SSH key-only) one at a time.
4. **Elevated monitoring (30 days):** keep the endpoint under heightened Wazuh/FIM and IDS
   scrutiny and re-check any future alert against the incident's IoCs — a recurrence is
   evidence eradication was incomplete.
5. **Post-incident review:** document the timeline, root cause, what worked/ failed on this
   plan, and update rules and the plan accordingly (this is also where the agentic SOC's
   investigation bundle and reasoning log feeds the write-up).

---

## 6. Cyber Attack Types (& worked explanation: Ransomware)

The plan is exercised against the four attack types covered by this module. **Ransomware is
explained in depth** because it demonstrates every phase of this plan and has a
ransomware-precursor scenario in the lab's EDR layer.

### 6.1 Ransomware (explained)

**What it is:** malware that encrypts the victim's files and demands payment for the
decryption key. Modern ransomware is usually *double extortion* — it also exfiltrates
sensitive data and threatens to publish it, so suppression of backups is a core part of the
attack (deleting volume shadow copies). It typically arrives via **phishing** or another
malware loader, then escalates privileges and spreads laterally before the final encryption
wave.

**Lifecycle in MITRE ATT&CK terms:**

| Phase | MITRE technique | How this plan catches it |
|---|---|---|
| Delivery (phishing attachment/link) | T1566 — Phishing | IDS + Wazuh log correlation; phishing module IoCs |
| Execution / privilege escalation | T1059 (command & script), T1078 — Valid Accounts | Process telemetry (EDR layer) |
| Lateral movement | T1021 — Remote Services | Network IDS / firewall rules |
| System recovery suppression | T1490 — Inhibit System Recovery | FIM detects deletion of backups/VSS |
| Encryption | T1486 — Data Encrypted for Impact | FIM mass-change events + EDR mass file-rename telemetry |

**How the plan responds to it:** **Detect** via FIM rule firing on mass file changes
(Section 2); **contain** by blocking C2 traffic and isolating the endpoint fast to stop the
encryption wave spreading (Section 3); **eradicate** by re-imaging from a known-good source
rather than trusting decryption tools, and removing the phishing/dropper mechanism
(Section 4); **recover** from verified, offline/immutable backups (never pay the ransom — it
funds the attacker and does not guarantee decryption) (Section 5).

### 6.2 The other three types (identified & summarized)

| Type | What it is | Where it fits in this plan |
|---|---|---|
| **Malware** | Any malicious software (infostealers, Trojans, botnets). Lab evidence: Vidar Stealer analysis | Detection via file-hash IoCs + FIM; eradication removes the binary; recovery restores a clean state |
| **Phishing** | Social-engineering attack delivering malware or harvesting credentials via deceptive messages/links. Lab evidence: MITRE Phishing analysis | Detection via email/link IoCs + user-reported alerts; containment = blocked sender/domain; eradication = remove delivered payload and disable stolen-credential reuse |
| **Denial of Service (DoS)** | Overwhelming a service/network so legitimate users are denied access (volumetric floods, resource exhaustion) | Detection via bandwidth/latency anomalies in the IDS pipeline; containment = rate-limit/filter attack traffic at the firewall (blackhole/ICMP rules); recovery = restore service health, then re-apply normal rules |

---

## 7. Integration with the Agentic SOC (how this plan maps to the capstone)

The plan is the human-run response playbook that the AI-Agentic SOC project automates *the
front half of* — while keeping the human decision rights the plan depends on:

- **Detect** ⇄ the Wazuh `siem/client.py` pulls `/security-events` and the normalizer tags
  alerts with MITRE techniques (Section 2 detection = the agent's input).
- **Contain** ⇄ the agent proposes a containment action, but it is **never auto-executed** —
  it routes to the analyst approval gate exactly as this plan makes containment a
  human-approved decision (Section 3).
- **Eradicate/Recover** ⇄ the investigation bundle's MITRE-mapped timeline feeds the
  post-incident write-up, and the approval gate's log becomes the audit trail for
  Post-Incident review (Sections 4–5).

---

## 8. Legal & Ethical Compliance

Incident response is not purely technical — it is bound by law and by professional ethics.
This section states the laws this plan is designed to comply with, the ethical principles its
operators are bound by, and the specific plan steps that uphold them.

### 8.1 Relevant laws & regulations

**1. Data protection law — GDPR (EU/UK, implemented as the UK Data Protection Act 2018).**
Incident data is inherently personal data: usernames, IP addresses, login events, and file
metadata belong to real individuals. The GDPR applies throughout the plan:

- **Article 5 (data minimisation, purpose limitation):** only the security-relevant events the
  validated alert requires may be collected, and only for the stated legitimate purpose of
  protecting the systems.
- **Article 32 (security of processing):** the technical measures this plan relies on
  (encryption of sensitive data in transit/at rest, access control, logging) are the
  required safeguards.
- **Articles 33–34 (breach notification):** if an incident involves personal data, the
  responsible authority is notified within the required window (e.g. 72 hours for the GDPR)
  and affected individuals are informed where the risk is high.

**2. Computer Misuse Act 1990 (UK) — or the equivalent (e.g. US CFAA) where the lab runs.**
This law criminalizes unauthorized access (s.1), access with intent to commit further
offences (s.2), and unauthorized modification of data (s.3). It is why this plan — and the
Comprehensive Security Policy's acceptable-use rule — insist that every detection,
containment, and eradication action applies **only to authorized, in-scope lab systems**
(managed endpoints, the Wazuh stack, and the test scenarios the program authorizes). Defensive
inline-quarantine of a lab host is authorized; probing anyone else's systems is not.

### 8.2 Ethical considerations

**Primary ethical consideration — proportionate investigation on private data.**
Investigating an incident is itself an intrusion: it reads sessions, file paths, credentials,
and communications of the people who use the system. The ethical duty is to investigate
**proportionately** — collect only what the validated alert justifies, review sensitive
evidence (e.g. likely-exfiltrated content, credentials) only on a need-to-know basis by the
assigned responder, and not speculate or attribute blame publicly until evidence confirms it.

Two further principles the plan is built on:

- **Human accountability for AI-assisted decisions.** The agentic SOC front-half can propose
  actions, but responsibility always rests with a human. The approval gate (§7) guarantees a
  person — not a model — authorizes every containment action and owns the outcome.
- **Never paying ransom, and honest reporting.** Restoring from backups (Section 5) keeps the
  plan from funding the attacker ecosystem, and post-incident reviews report what actually
  happened rather than a sanitized version.

### 8.3 How the plan upholds these requirements & principles

| Law / principle | Requirement | Where the plan upholds it |
|---|---|---|
| GDPR Art. 5 — minimisation & purpose | Collect only what is needed | Section 2 detection is scoped to security-relevant events already flowing to Wazuh; no broad data collection |
| GDPR Arts. 33–34 — breach notification | Notify authority/individuals on personal-data breach | New: Step 0 added below — a **notify** obligation triggered when a declared incident involves personal data |
| GDPR Art. 32 — security of processing | Safeguard the data you hold | Access controls (Section 2/3), evidence preserved for the investigation, secrets policy from the Comprehensive Security Policy |
| CMA 1990 — authorized access only | No unauthorized modification/access | Whole plan operates only on lab-managed endpoints and authorized test scenarios; acceptable-use rule in the policy |
| Proportionate investigation (ethics) | Minimize intrusion during IR | Sections 2–4: needs-based collection, need-to-know evidence handling, evidence preserved without alteration |
| Human accountability (ethics) | Human owns the decision | Section 7 approval gate — containment recommended, never auto-executed |

**Breach-notification step (Step 0 of the response runbook).** On declaring an incident:
1. Determine whether personal data is involved (usernames, IPs, login events, file content).
2. If yes, log the breach decision and notify the responsible authority within the required
   window (72 hours under GDPR, unless extended by the authority's guidance), including the
   nature, likely impact, and measures taken.
3. Notify affected individuals where the risk to them is high, per Article 34.
This obligation is recorded in the timeline at Section 4 step 1 so it cannot be missed.

---

## 9. Rubric Coverage

| Requirement | Addressed in |
|---|---|
| ≥1 method for detecting security incidents | Section 2 — Wazuh SIEM + IDS signature correlation (live: rule 100010 / T1110) + FIM + behavioural |
| ≥1 containment strategy | Section 3 — network edge block + endpoint isolation + credential actions |
| Steps for eradication and recovery | Sections 4 and 5 |
| Identifies + explains ≥1 cyber attack type | Section 6.1 — Ransomware (deep) + 6.2 Malware / Phishing / DoS |
| Compliance section in the IR plan | Section 8 — Legal & Ethical Compliance (8.1 laws, 8.2 ethics, 8.3 mapping + notification step) |