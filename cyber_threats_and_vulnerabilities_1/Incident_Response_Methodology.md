# Incident Response Methodology — Documented Process for the SOC Lab

**Author:** Kyrell Green
**Date:** 2026-09-15
**Module:** Cyber Threats & Vulnerabilities — SOC Security Analyst track
**Designated incident type:** SSH brute-force attack (MITRE ATT&CK **T1110 — Brute Force**)
**Case management system:** TheHive (alert/case management) integrated with the SOC lab
**Companion document:** `Incident_Response_Plan.md` (NIST SP 800-61 plan for the same lab)

---

## Rubric Coverage

| Rubric requirement | Addressed in |
|---|---|
| Thorough documentation of **initial response protocols** for a designated incident type | Section 1 — SSH brute force definition + 30/60-minute initial response runbook |
| Detailed descriptions of **case management system components** and their operational purpose | Section 2 — TheHive alerts, cases, tasks, observables, TTPs, logs/audit, dashboards, roles, integration with the lab |
| Comprehensive **escalation criteria and communication protocols** with clear decision points | Section 3 — severity/priority model, escalation tiers, notification matrix, decision-point flowchart |
| Completed **incident response documentation template** for the provided scenario | Section 4 — fully completed IR documentation template for the SSH brute-force scenario |
| Clear explanations of **incident response principles and response methodologies** | Section 5 — NIST SP 800-61 lifecycle, prioritization, evidence handling, and documentation principles |

---

## 1. Designated Incident Type & Initial Response Protocols

### 1.1 The incident type: SSH brute-force attack (T1110)

An **SSH brute-force attack** is a credential-attack type in which an adversary makes a large
number of authentication attempts against the Secure Shell (SSH) service, trying guessed or
previously breached passwords until one succeeds. In MITRE ATT&CK terms this maps to
**T1110 — Brute Force**, under the **Credential Access** tactic, because the goal is obtaining
valid credentials to the host (typically `root` or a privileged account).

**Why this incident type is significant for a SOC:**

| Characteristic | Impact on the analyst |
|---|---|
| Extremely common in internet-exposed hosts | High volume of *potential* alerts; a large part of the analyst's job is separating real attacks from noise (false positives) |
| Low-entry, highly automated | Tools like `hydra`, `medusa`, `ncrack`, or botnet campaigns make thousands of guesses/minute — a single host can generate a flood of auth-failure log lines |
| Escalates quickly if it succeeds | One successful login gives an attacker a foothold: a valid privileged session that can be used for lateral movement (T1021), backdoor installs, or data theft |
| Verbose, detectable signature | The "many failed auths from same source in a short window" pattern is easily detectable by SIEM correlation — but differentiating *brute force* from *accidental lockouts / scripted scans* is where triage skill shows |

**How it is detected in this lab (real evidence):** the Wazuh manager correlates SSH
authentication events from the monitored Kali endpoint. Wazuh **rule 100010** (SSH brute-force
attempt — repeated failed logins from one source within 2 minutes) fires alongside the per-event
authentication rule **5716**, with a severity of 10, and is tagged with MITRE **T1110**. The same
behavior is confirmed at the wire level by the Suricata IDS rules in the firewall/IDS/IPS
pipeline, giving host-based + network-based sensor confirmation. Both are pulled through the
Wazuh REST API (`GET /security-events`) by the SIEM connector used by the Agentic SOC engine.

### 1.2 Initial response protocol (runbook for the first 60 minutes)

The **initial response** is the set of immediate, structured actions taken from the moment an
analyst is notified of a potential incident until the situation is assessed and, if needed,
contained. It is deliberately *crawl, don't jump*: triage and containment first, forensics and
eradication afterward. The protocol below follows NIST SP 800-61's Detection & Analysis phase,
split into three timed blocks.

**RULE OF THE LAB AND THE CAPSTONE:** every containment action below is a **human decision**.
The AI-Agentic SOC engine may draft the investigation and *recommend* an action, but the analyst
— never the model — authorizes it at the approval gate. This is stated here because the initial
response protocol is the human procedure that gate formalizes.

#### Block 1 — Alert received (T+0 to T+10 min): assess and verify

| Step | Action | Why / decision point |
|---|---|---|
| 1.1 | Acknowledge the alert in TheHive (claim/assign it, open the case) | Ownership from minute one; prevents two analysts working the same alert; gives the clock a start (SLA) |
| 1.2 | Read the alert fields: source IP, target host, username, rule ID, severity, MITRE tag | Confirm the alert is what it says it is before acting (decision point D1) |
| 1.3 | Verify the detection is real, not a false positive | Cross-check host-based (Wazuh rule 100010) AND network-based (IDS) evidence. If both fire for the same source, confidence is high. If only one and it looks like a scanner/benign script, go to D2 |
| 1.4 | Preserve the evidence as-is | Case page in TheHive records the original alert JSON; do not modify log data. Early decisions affect chain of custody later |

#### Block 2 — Triage and scope (T+10 to T+30 min): decide real vs. noise

| Step | Action | Why / decision point |
|---|---|---|
| 2.1 | Pull the account-, host-, and IP-scoped evidence into the case: login history (identity pillar), process/network telemetry (EDR pillar), related SIEM events | The three-pillar evidence model this lab uses; answers "who, what host, what else happened" |
| 2.2 | Determine if the attack **succeeded** (any successful login?) | This is the single highest-leverage question. Decision point D3: *no* → monitor/block, *yes* → assume compromise and contain |
| 2.3 | Determine scope: how many hosts, how many accounts, how long running | Time window from first failed attempt to last evidence; count of affected accounts. Feeds severity/priority scoring (Section 3) |
| 2.4 | Make the initial severity/priority call and set the case fields in TheHive | Provokes the right escalation path (Section 3) and sets the SLA clock |

#### Block 3 — First containment response (T+30 to T+60 min)

| Step | Action | Why / decision point |
|---|---|---|
| 3.1 | **Block the attacker source** at the network edge (firewall/IPS deny rule for the source IP) | Cheap, reversible, stops the current wave of attempts; does not require host access |
| 3.2 | **Isolate the affected endpoint** if the attack succeeded (disconnect the Kali VM interface at the hypervisor) | Stops lateral movement and further credential use — decision point D4 (isolation yes/no) |
| 3.3 | **Disable/rotate the targeted credentials** (e.g., temporarily disable `root` SSH login, rotate any account that may have authenticated) | Invalidates any credential the attacker already harvested |
| 3.4 | Document every action in the case timeline with timestamps | Reversibility + audit trail are core IR principles; the case log is the source of truth for the post-incident review |

**Decision points in the initial response (summary):**
- **D1 — Is the alert claimable & in scope?** No → mark as duplicate/informational, close or merge in TheHive.
- **D2 — Real attack or false positive?** FP → document the rationale, tag, close case. Real → continue.
- **D3 — Did any login succeed?** No → block + monitor (low priority). Yes → escalate to Tier 2 and contain per 3.1–3.3.
- **D4 — Isolate the host now?** Yes if compromise is confirmed; otherwise blocking the source may be enough to avoid unnecessary downtime.

---

## 2. Case Management System: Components and Operational Purpose

The case management system for this lab is **TheHive**, the open-source SOC case-management and
alert-triage platform, fed live by Wazuh alerting (via the standard Wazuh → TheHive connector
path) and enriched by linked threat-intelligence lookups. TheHive's job is to turn raw alerts
into **titled, tracked, assigned, documented work packages** — a case — and to carry every
investigation from first sighting to documented closure so that nothing is lost and everything
is auditable.

The table below details the **components** of the case management system, what each one *is*,
and its **operational purpose** — both generally and in this lab's brute-force workflow.

| Component | What it is | Operational purpose | Used in the SSH brute-force workflow as |
|---|---|---|---|
| **Alerts** | Incoming detection records from detection tools (Wazuh) before they become cases; each alert carries its raw detection data | Central ingest point & deduplication — lets the SOC survey "what is hitting us right now" without opening cases for every event; multiple identical alerts can be merged | The Wazuh rule-100010 detection lands as a TheHive alert: source IP, destination account, timestamps, MITRE tag; the analyst reviews it here before deciding whether to promote it to a case |
| **Cases** | The core work package: a titled record (incident) with severity, status, assignee, tags, TLP, and timeline | Everything about one incident lives in one place; the case is what people, escalation, and reporting all refer to — it *is* the investigation record | `#142 — SSH brute force on kali-lab-02` is opened, tracked, and closed here; its status changes as it progresses (Section 4 template) |
| **Tasks** | Ordered subtasks inside a case, each with an assignee, status, and due date | Enforce the runbook/checklist discipline: the analysis steps actually get done in order and no step is silently skipped; provides SLA visibility | The initial-response blocks from Section 1 are created as tasks (verify alert → scope → block source → rotate creds) and ticked off with timestamps |
| **Observables** | Extracted artifacts tied to the case: IPs, domains, hashes, usernames, file paths (IoC data) | Gives every artifact a home in the case so it can be searched, enriched, and shared; enables correlation ("have we seen this IP before?") and later threat-intel matching | `203.0.113.77` (attacker IP) is recorded as an observable and checked against the OpenCTI threat-intel store for prior sightings |
| **TTPs (MITRE mapping)** | ATT&CK technique/tactic tags attached to a case | Standardizes *what kind of behavior* this was; makes severity consistent, reporting defensible, and stats comparable across cases | Case tagged `T1110 / Credential Access`; identical tags on every future brute-force case make trends measurable |
| **Logs / audit trail** | An append-only record of every comment, field change, status change, and logged note on a case | Accountability and **chain of custody**: reviewers can reconstruct exactly who did what and when; also the raw material for the post-incident "lessons learned" write-up | Every action from rule-100010 acknowledgment to the firewall deny is timestamped here, including who ran the approval gate |
| **Custom fields** | Case-defined structured fields beyond the defaults (e.g., affected accounts, business criticality, GDPR-personal-data flag) | Lets the SOC capture lab/specific data the generic schema lacks, keeping key facts queryable instead of buried in prose | A custom `affected_accounts` field (e.g., `root`) and `personal_data_involved` flag drive escalation in Section 3 |
| **Case templates** | Pre-packaged case definitions with pre-created tasks/fields for a known incident type | Standardize recurring runbooks so every analyst opens the *same* structure; reduces forgetting steps and produces consistent documentation | A "Credential Attack / SSH brute force" template preloads the Section 1 tasks, so the analyst doesn't write the checklist from scratch each time |
| **Dashboards / statistics** | Aggregated views over all cases: open counts, severity mix, SLA breaches, resolution times | Situational awareness for the SOC and management reporting; surfaces where the SOC is fast/slow and where the noise is | A "brute-force trend" dashboard showing source IPs and affected accounts over time |
| **Users, roles & permissions** | Analyst accounts with role-based access (Tier 1/2/3, admin, read-only) | Enforces the escalation model of Section 3: each tier can see and do what its scope requires, and every action is attributed to a named human | Tie-1 analysts triage; Tier 2 analysts deep-investigate; Tier 3 has forensics/admin rights for advanced containment |
| **Integration with Wazuh (+ intel)** | The connector that pushes alerting, and the enrichment path to the threat-intel layer (OpenCTI/MISP/IoC feeds) | Closes the loop between "detection" and "case" so no alert dies in the SIEM, and enriches observables so analysts answer "is this known-bad?" in one click | Alert 100010 auto-lands in the alert queue; the source IP observable is automatically enriched from threat intel before the analyst even opens it |

**Summed up:** alerts *detect*, cases *own*, tasks *execute*, observables *connect*, TTPs
*classify*, logs *account*, dashboards *report*, and roles *enforce* — together they turn raw
detections into documented, auditable, completed incident response.

---

## 3. Escalation Criteria & Communication Protocols

### 3.1 Severity and priority model

Every alert/case is scored on two axes, using a 1–4 priority that drives the escalation path
(4 = highest):

| Severity (impact) | Criterion (SSH brute-force context) |
|---|---|
| **4 — Critical** | Confirmed successful login to a privileged account (`root`) AND signs of post-compromise activity (new processes, outbound C2, lateral movement) |
| **3 — High** | Confirmed successful login to a normal account, or a large-scale attack on privileged accounts (unauthorized access confirmed) |
| **2 — Medium** | Confirmed ongoing brute force with **no** successful login yet (single host, single source) |
| **1 — Low** | Scans/false positives, single failed-auth noise, no successful logins, no persistence |

The priority also factors **scope**: multiple affected hosts or accounts raise the priority by one
step. This mirrors the lab's alert-severity scale (1–10) normalized: Wazuh rule 100010 is level
10 → maps to the "confirmed attack" band, while a single auth-failure (5716, level 5) maps to
Low until correlated.

### 3.2 Escalation tiers

| Tier | Who | Authority | When they get it |
|---|---|---|---|
| **Tier 1 (Triage)** | First-line analyst (the role this lab trains for) | Validate, scope, block source IP, document, open/close cases | All new alerts — owns the initial response (Section 1) |
| **Tier 2 (Investigation)** | Senior SOC analyst / responder | Deeper analysis, endpoint isolation, credential rotation, EDR actions, forensics initiates | Severity 3+; any case with a **confirmed successful login**; containment that needs host actions |
| **Tier 3 (Advanced / IR)** | Incident-response lead or forensic specialist | Host re-imaging, full forensic acquisition, eradication of persistent access, root-cause engineering fix | Severity 4; evidence of persistence, C2, lateral movement; eradication that requires rebuild |
| **Management / on-call lead** | SOC manager / shift lead | Resource decisions, client/external notification, legal/MFA involvement | Critical incidents (severity 4); any breach of the notification obligations (Section 3.4) |
| **Advisory (non-SOC)** | System owners, IT support, communications/legal | Authorize infrastructure changes outside SOC reach, public-communication | Only with a declared incident needing external notification (GDPR, client) |

### 3.3 Escalation criteria — clear decision points

```
                 Alert enters TheHive queue
                            |
                            v
              [D1] Is it claimable & in scope?
                  | no                         | yes
                  v                            v
           Mark duplicate / info      [D2] Real attack or false positive?
           and close/merge                 | FP             | real (rule 100010 confirmed)
                                           v                                    v
                                    Document, tag,                    [D3] Did any login SUCCEED?
                                    close case                            | no                  | yes
                                                                         v                        v
                                                              Block source, keep   Escalate to TIER 2,
                                                              monitor — SEVERITY 2  then [D4] isolate host,
                                                                                    rotate creds — SEVERITY 3+
                                                                                                |
                                                                               [D5] Post-compromise signs?
                                                                                     (persistence/C2/lateral?)
                                                                                          | no      | yes
                                                                                          v         v
                                                                                    SEVERITY 3   SEVERITY 4 →
                                                                                                 escalate to TIER 3
                                                                                                 + management, and
                                                                                                 trigger notification
```

Decision rules (each is an escalation *trigger*):

| Decision point | Escalation trigger | Response |
|---|---|---|
| **D1** — claimable, in scope? | Not in scope / duplicate | No escalation — close or merge with the owning case |
| **D2** — real attack vs. false positive? | Confirmed false positive | No escalation — document rationale in the case log, close |
| **D3** — did any authentication succeed? | **Yes** | **Mandatory Tier 2 escalation** — a successful login is a confirmed unauthorized access, not a nuisance |
| **D4** — is host isolation required? | Confirmed compromise | Tier 2/3 executes isolation; host is not reconnected until eradication verified (Section 5 principles) |
| **D5** — post-compromise indicators? | Any persistence, C2 contact, or lateral movement | **Mandatory Tier 3 + management** and, if personal data is involved, the notification protocol (3.4) |
| **SLA over-run** | Case open past its target (High/Critical: 4h to initial response; 24h to containment decision) | Automatic escalation one tier up — status is not an SLA that gets quietly blown |

### 3.4 Communication protocols

| Trigger / audience | Channel | Content | Timing target |
|---|---|---|---|
| Analyst ↔ Tier 2 on escalation (D3/D4) | Message to on-call Tier 2 + **case reference** in TheHive | Case #, severity, confirmed/attempted access, affected host/accounts, containment status | Within **15 min** of the decision point |
| Tier 2 → Tier 3 + SOC management (D5, severity 4) | Incident bridge call (dedicated channel) + TheHive case update | Evidence summary, current containment state, who is doing what, decision needed | Within **30 min** of severity-4 classification |
| SOC → system owner / IT for off-SOC changes (e.g., rotating a shared service account) | Escalated ticket + TheHive case reference | Exactly what change is requested, why, and the security rationale | As soon as containment needs it |
| **External notification** (personal data involved — GDPR Articles 33–34; client/contractual) | Designated management/legal channel, documented in case | Nature, likely impact, measures taken (template fields, Section 4) | GDPR Regulator: **72 hours** from becoming aware; affected individuals per Article 34 where risk is high |
| Everyone, continuously | **TheHive case timeline is the single source of truth** | All actions & decisions commented with timestamps | Every change, no exceptions |

**Communication principles:** state the **case number** in every channel; never discuss evidence
details on non-verified channels; keep the written record authoritative (phone calls are
followed up with a TheHive note); and preserve the **human approval gate** — the agent's
recommended action only becomes a real action after a named analyst approves it in the case
timeline.

---

## 4. Completed Incident Response Documentation Template (provided scenario)

The template below is the completed incident documentation for the designated scenario: an SSH
brute-force attack against the lab's monitored endpoint. All fields are filled to the level of
detail a SOC case file requires. (Case metadata, timestamps, and technical IPs mirror the lab
environment; attacker IP `203.0.113.77` uses a documentation/reserved range.)

### 4.1 Case record

| Field | Value |
|---|---|
| **Incident / case reference** | SOC-CASE-2026-0142 (TheHive case `#142`) |
| **Incident title** | SSH brute-force attack on `kali-lab-02` targeting `root` account (T1110) |
| **Reporter / source** | Automated — Wazuh SIEM (rule 100010 + 5716) via alert integration; IDS correlation |
| **Date & time detected** | 2026-09-15 02:14:07 UTC (Wazuh `/security-events` timestamp) |
| **Date & time declared (incident)** | 2026-09-15 02:18:30 UTC — after analyst verification (Tier 1) |
| **Classification** | Credential attack — Brute Force (MITRE **T1110**, tactic Credential Access; rule-level 10) |
| **Security posture at detection** | Attempted → **escalated to High/Critical on confirmed login** |
| **Severity / priority** | Severity 3 (High) at declaration; held at 3 — no post-compromise indicators found (D5 = no) |
| **Affected assets** | `kali-lab-02` (agent id `011`, 10.11.3.57), SSH service on TCP 22 |
| **Affected accounts** | `root` (target), attacker-controlled attempts only; no other accounts impacted |
| **Lead investigator** | Kyrell Green (Tier 1 — triage/initial response) |
| **Supporting staff** | Tier 2 analyst (escalation review D3), Tier 2 confirmed no host isolation required (D4) |
| **Case management tool** | TheHive (case `#142`); template "Credential Attack / SSH brute force" applied |
| **Status (final)** | **Resolved** (monitored) — escalated to Tier 2 review, contained, no compromise confirmed |

### 4.2 Incident timeline

| Time (UTC) | Event | Source / action taken |
|---|---|---|
| 01:58–02:13 | 412 SSH authentication failures from `203.0.113.77` to `root` on port 22 | Kali `/var/log/auth.log` → Wazuh agent → manager |
| 02:14:07 | Wazuh rule **100010** (SSH brute force — multiple failed logins in 2 min) fires, level 10, MITRE T1110; correlated with rule 5716 auth-failure events | Wazuh detection → alert created in TheHive queue |
| 02:14:20 | Suricata IDS confirms high-rate SSH auth attempts from same source at wire level | Network sensor — second, independent confirmation |
| 02:18:30 | Alert claimed by Tier 1; case `#142` opened; severity 3 assigned | TheHive case created; initial-response tasks auto-loaded from template |
| 02:21 | Scope identified: single host, single account, single source | Log review: `srcip=203.0.113.77`, `dstuser=root` |
| 02:24 | **Evidence gathered for the case** — identity login history, EDR process/network telemetry, related SIEM events pulled; `203.0.113.77` registered as case observable and enriched against threat intel (no prior sightings) | Three-pillar evidence model; OpenCTI lookup |
| 02:28 | **D3 decision:** log review confirms **no successful authentication** across the window — all failures. Escalated to Tier 2 per protocol for review | Authorized at the human approval gate |
| 02:33 | **Containment (approved):** firewall/IPS deny rule added for `203.0.113.77`; attacks stop hitting the endpoint | Tier 1 executes; rule logged in case timeline |
| 02:35 | `root` SSH login policy verified (password auth already disabled on `kali-lab-02`); no credential rotation required | Root-cause hardening check — policy was already the mitigation |
| 02:40 | Tier 2 review complete: confirms no compromise indicators; decision **D4 = no isolation needed** (blocking was sufficient); severity held at 3, endpoint left monitored | Escalation return-to-Tier 1 |
| 03:00 | Case updated to **In Progress → monitoring**; heightened Wazuh/FIM + IDS monitoring of `kali-lab-02` scheduled for 30 days; no recurrence expected | Elevated monitoring window opened |
| 03:20 | **Post-incident review logged:** detection-to-declaration 4 min; root cause = internet-facing SSH reachable; action = confirmed key-only auth + periodic review; rules 100010/5716 kept as-is (they performed correctly) | Lessons-learned record appended, dashboard updated |

### 4.3 Evidence collected

| Evidence type | Artifact | Where stored |
|---|---|---|
| Alert payloads | Wazuh `/security-events` records for rule 100010/5716 (original JSON preserved unmodified) | TheHive case log + SIEM archive |
| Authentication events | `auth.log` excerpts: 412 failed attempts from `203.0.113.77` | Case observables/logs |
| Network evidence | IDS alert confirming the same source at wire level; firewall deny rule record | IDS console + firewall log linked in case |
| Identity evidence | Login history & risk profile for `root` account — no successful or anomalous logins | Identity API (mock, Okta-shaped) pulled into evidence bundle |
| Endpoint evidence | EDR process/network telemetry for `kali-lab-02` during the window — no suspicious processes | EDR API (mock, Falcon-shaped) pulled into evidence bundle |
| Intelligence | Threat-intel lookup on `203.0.113.77` — no prior sightings; tagged for continued watch | OpenCTI / threat-intel layer |
| Audit trail | Every action and approval timestamped with the responsible analyst | TheHive case timeline (append-only) |

### 4.4 Containment, eradication & recovery applied

| Phase | Actions taken | Rationale |
|---|---|---|
| **Containment** | 1) Firewall/IPS deny for `203.0.113.77`; 2) endpoint isolation **evaluated and declined** (blocking sufficient — D4); 3) credential policy verified (password auth disabled) | Stopped the current attack; no successful login so no host compromise to isolate; hardening already in place |
| **Eradication** | None required — no successful access, no malware, no persistence; the attack never reached the system | Eradication applies to root cause/foot-holds; there was no foothold. Root-cause action: keep SSH key-only (verified) |
| **Recovery** | No restoration required; host remained operational throughout; heightened monitoring (30 days) instead | Nothing was lost/encrypted; the goal is catching any recurrence |

### 4.5 Lessons learned & follow-up actions

| Lesson | Follow-up action | Owner |
|---|---|---|
| Detection stack performed correctly (host + network correlation, 2-sensor confirmation) | Keep rule set; schedule quarterly review of brute-force rule tuning | Tier 2 |
| Strong existing mitigation (key-only SSH) turned a wouldn't-succeed attack into a non-event | Formalize "no successful login ⇒ verify existing hardening instead of assuming worst case" in the case template checklist | Tier 1 |
| Documentation discipline held under time pressure (all decisions timestamped) | Reinforce the approval-gate habit: log *who approved the firewall change and when* | All analysts |

---

## 5. Incident Response Principles & Response Methodology (explanation)

This section explains the *why* behind the process — the incident-response principles and the
response methodology that the runbook, case management, and documentation requirements are built
on. A documentation deliverable is judged not only on completeness but on whether the analyst can
explain the methodology behind it.

### 5.1 The response lifecycle (NIST SP 800-61)

The methodology follows four lifecycle phases, which the initial-response runbook (Section 1)
implements in practice:

1. **Preparation** — the sensors, rules, credentials, playbooks, and case templates that make a
   fast response possible. In this lab: the Wazuh rule set, the IDS pipeline, the TheHive
   "SSH brute force" template, and key-only SSH hardening *before* an attack (this is why the
   attack failed: preparation was already the mitigation).
2. **Detection & Analysis** — recognizing and confirming the incident, assessing its scope, and
   deciding severity. This is the entire content of Section 1 and the escalation decisions D1–D3.
   Its core skill is separating a real attack from noise using corroborating evidence
   (host + network + identity + endpoint).
3. **Containment, Eradication & Recovery** — stopping the spread, removing the root cause, and
   returning to normal operation (Sections 4.4). The methodology's timing principle: **contain
   while you analyze** — do not wait for a perfect forensic picture before cutting off an active
   attacker; containment actions are chosen to be reversible and proportionate to evidence.
4. **Post-Incident Activity** — the lessons-learned review, documentation completion, and
   process improvement (Section 4.5). The methodology treats the incident as *finished only when
   the write-up is done and the decision trail is complete.*

### 5.2 IR principles demonstrated by this document

| Principle | What it means in practice | Where shown |
|---|---|---|
| **Human decision rights** | AI/tools recommend, humans authorize; every action has a named accountable owner | Section 1 rule, approval gate, Section 4.4 approvals |
| **Documentation first** | If it isn't written down, it didn't happen — cases, timelines, and approvals are the product of incident response, not an afterthought | Sections 2 (logs/audit) and 4 (completed template) |
| **Evidence preservation & chain of custody** | Original alert data preserved unaltered, every access/action attributed and timestamped | Section 4.3; TheHive append-only logs |
| **Proportionate investigation** | Collect only what the confirmed alert justifies; no fishing expeditions into unrelated data | Section 1 Block 2; GDPR data-minimisation alignment |
| **Triage by priority, not by arrival order** | Severity × scope drives who gets worked first and who gets escalated | Section 3 scoring model |
| **Escalation is triggered by defined criteria** | Decisions are structured decision points (D1–D5), not gut feeling — so any analyst escalates consistently | Section 3.3 flowchart |
| **Clean restoration over in-place repair** | When a host is confirmed compromised, rebuild from known-good rather than trust spot-cleaning | Section 5.1 phase 3; plan §4 eradication |
| **Notification obligations** | External communication (GDPR 72h, affected individuals, clients) is part of the response, not separate from it | Section 3.4; legal mapping in the incident plan §8 |

### 5.3 Why documentation requirements exist (explanation for the rubric)

Incident documentation exists to answer, for every person who later touches the case — a
replacement analyst at 3 AM, a Tier 3 responder, a manager, an external auditor, or a court —
four questions without talking to anyone:

1. **What happened?** (timeline, artifacts, observables — Section 4.2/4.3)
2. **What did we do?** (actions, approvals, containment — Section 4.4)
3. **Why did we do it?** (decision points, severity, rationale — Section 3 and 4.4 rationale column)
4. **What will we do differently?** (lessons learned, follow-ups — Section 4.5)

A case management system (Section 2) is the infrastructure that makes this possible at scale:
without alerts, cases, tasks, observables, TTP tags, and the audit log, response depends on
individual memory. With them, response becomes a repeatable, measurable, auditable process —
which is the difference between "a good analyst" and "a functioning SOC."

---

## Document Map (how this document satisfies each rubric element)

| Requirement | Location |
|---|---|
| Initial response protocols for the designated incident type | §1.1 (incident definition/detection) + §1.2 (60-minute runbook with D1–D4) |
| Case management system components & operational purpose | §2 (TheHive component table + summary) |
| Escalation criteria & communication protocols with decision points | §3 (severity/priority, tiers, D1–D5 decision map, notification matrix) |
| Completed incident response documentation template | §4 (full case record, timeline, evidence, containment, lessons learned) |
| Understanding of IR principles & documentation requirements | §5 (NIST lifecycle, principles table, documentation rationale) |