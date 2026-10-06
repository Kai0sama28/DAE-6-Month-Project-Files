# Incident Response Documentation: Case Management, Escalation, and Ransomware Report

*Parts 1 and 2 document the generic industry model (Jira/Slack, SEV1–4) and map it to this lab's actual deployment (TheHive 5.2.16, Wazuh 4.14.7). Part 3 is the completed incident response report for the **real lab case `SOC-CASE-2026-0142`** — every rule ID, level, timestamp, count and log line was read from the live Wazuh indexer on 2026-10-05, not invented. §3.13 is a clearly-labelled illustrative ransomware annex: the lab produced a credential-compromise incident, not a ransomware one, and the annex shows how this same process applies to the ransomware scenario named in the assignment title.*

**Companion documents:** `Incident_Response_Methodology.md` (full methodology + Sections A–J of the completed template), `../cybersecurity_basics_1/Incident_Response_Template.md`, `../cybersecurity_basics_1/Incident_Response_Plan.md`, `SOC_Operations.md`, `Threat_Detection_Principles.md`.

---

## Part 1. Case Management System Components

A case management system is the **system of record** for an incident: it gives every incident one owner, one status, one timeline, and one audit trail. In a typical setup, Jira holds the record and Slack holds the live coordination.

### 1.1 Jira (system of record)

| Component | Description | Operational purpose |
| --- | --- | --- |
| **Project / issue type** | Dedicated "Security Incidents" project with an *Incident* issue type and *Task / Sub-task* types for response actions | Keeps IR work separate from general IT tickets and lets access be restricted |
| **Custom fields** | Severity (SEV1-4), incident category, detection source, affected assets/users, incident commander, data classification, regulatory impact (Y/N), IOC list | Makes incidents searchable, reportable, and consistent; drives automation and metrics |
| **Workflow** | New → Triage → Investigating → Contained → Eradicating → Recovering → Post-Incident Review → Closed | Mirrors the IR lifecycle; transitions can require fields (e.g., cannot close without a root cause) |
| **Sub-tasks** | One per action (isolate host, reset credentials, restore from backup), each with owner and due time | Assigns accountability and shows progress at a glance |
| **Comments and timeline** | Timestamped, attributed entries (UTC) | Builds the chronological record used for the post-incident report |
| **Attachments / links** | Evidence references (log extracts, screenshots, hashes), links to related tickets or problem records | Preserves evidence references; chain-of-custody details recorded, sensitive files stored in a controlled evidence store, not in the ticket |
| **Automation rules** | Auto-assign on-call, set SLA timers, notify Slack on SEV1/2, remind on stale tickets | Reduces manual overhead and missed hand-offs |
| **SLAs** | Time-to-acknowledge, time-to-contain, time-to-resolve per severity | Measures performance and triggers escalation when breached |
| **Permissions / security level** | Restricted issue security levels (need-to-know) | Prevents leakage of sensitive details such as legal or HR matters |
| **Dashboards / reports** | Open incidents by severity, MTTA/MTTR, recurring categories | Management oversight and trend analysis |
| **Audit history** | Immutable change log | Accountability and compliance evidence |

### 1.2 Slack (real-time coordination)

| Component | Description | Operational purpose |
| --- | --- | --- |
| **Dedicated incident channel** | Private channel per incident, named `#inc-YYYYMMDD-short-name` | Single place for live discussion; avoids scattered conversation |
| **Integration (Jira app / workflow bot)** | Creates the channel and posts ticket updates automatically; `/` commands to update status | Keeps Slack and Jira synchronized |
| **Role assignments** | Incident Commander (IC), Technical Lead, Communications Lead, Scribe | Clear authority and division of labor; the Scribe copies key decisions to Jira |
| **Pinned summary** | Current status, severity, next update time, bridge link | Lets late joiners get up to speed without interrupting |
| **Paging / on-call integration** | Alerts routed to the on-call responder | Ensures a human acknowledges high-severity events |
| **Huddles / bridge** | Voice/video call linked to the channel | Fast decisions during SEV1/2 |
| **Retention / legal hold** | Message retention configured per policy | Preserves communications as potential evidence |

**Key principle:** Slack is for *coordination*, Jira is for the *record*. Any decision or action taken in chat must be captured in the ticket. If the compromise may include collaboration or email platforms, move coordination to a pre-agreed **out-of-band channel**, because an attacker may be reading normal channels.

### 1.3 Mapping to this lab's deployment (TheHive 5.2.16 + Wazuh 4.14.7)

The generic model above is what a production SOC would run. This lab runs the same model on different tooling — the equivalence matters, because the assignment is answered against the lab:

| Generic component (Jira / Slack) | Lab equivalent | Verified status (2026-10-05) |
| --- | --- | --- |
| Jira = system of record | **TheHive 5.2.16 case** (`http://localhost:9000`), e.g. `SOC-CASE-2026-0142` / TheHive case `#142` | Live (Cassandra + Elasticsearch 7.17.13) |
| Issue types / workflow | Case status `New → In Progress → Contained → Recovered → Closed` | Live |
| Sub-tasks per response action | **Tasks** generated from the case template *"Credential Attack — SSH brute force"* — the runbook becomes ordered tasks, with the `D3` ("did a login succeed?") task mandatory so it cannot be skipped | Live |
| Custom fields | TheHive custom fields: `username_validity`, `authentication_success` (the `D3` answer), `session_duration_ms`, `attack_wave_index`, `password_changed_pre_attack` | Defined in `Incident_Response_Methodology.md` §3.2 |
| IOC / evidence attachments | **Observables** (IPs, hosts, usernames, ATT&CK techniques) — `192.168.64.3`, agent `002`/`Kali`, `labtester` uid 1001, T1110 + T1078 | Live |
| Automation rules / paging bot | **Gap:** Wazuh → TheHive alert connector is **not wired** (TheHive's alert queue is empty), and `<email_notification>no</email_notification>` in `ossec.conf` — a level-12 alert pushes a notification to nobody. Alert promotion into the case is **manual** | Gap `G1` / finding `I.2` |
| SLA timers | Documented as explicit targets (claim ≤ 10 min, `D3` ≤ 30 min, first containment ≤ 60 min) but **not system-enforced** — a breach is found at review, not at breach | Gap `G4` |
| Dashboards / reports | TheHive dashboards/statistics + Wazuh **indexer** aggregations (the analyst's real reporting surface) | Live |
| Audit history | TheHive append-only case timeline: every state change, decision and approval, timestamped and attributed — this is what proves the approval gate was respected | Live |
| Slack incident channel | **No chat bridge in the lab.** Coordination happens on the case timeline itself, which enforces the key principle above by construction: the record *is* the coordination surface | By design |

**Why the gaps are listed rather than hidden:** a methodology that claims a capability the lab does not have is worse than one that is smaller and true. `G1`, `G2` (no threat-intel enrichment), `G3` (Suricata offline replay only), `G4`, `G5` (rules are `same_source_ip` only — spraying undetectable) and `G6` (no custom rule deployed) are recorded in `Incident_Response_Methodology.md` §3.4 with their compensating practices.

---

## Part 2. Escalation Criteria and Communication Protocols

### 2.1 Severity classification

| Severity | Criteria (any one) | Acknowledge | Notify |
| --- | --- | --- | --- |
| **SEV1 Critical** | Confirmed ransomware/encryption or destructive attack; confirmed exfiltration of regulated or sensitive data; loss of a critical business system; active attacker with privileged access | 15 min | IC, CISO, executives, Legal, Communications, 24/7 bridge |
| **SEV2 High** | Confirmed malware or compromised account on a sensitive system; suspected data exposure; spreading activity contained to a limited scope | 30 min | Security manager, IT leadership, Legal (advisory) |
| **SEV3 Medium** | Single endpoint compromise, contained; policy violation with limited impact | 4 hrs | SOC lead, system owner |
| **SEV4 Low** | Blocked attack, false positive, informational | Next business day | Ticket only |

### 2.2 Escalation decision points

1. **Is this a true positive?** No → close with justification. Yes or uncertain → continue.
2. **Does it affect a critical system, sensitive data, or multiple hosts?** Yes → minimum SEV2.
3. **Is there evidence of encryption, destruction, exfiltration, or privileged compromise?** Yes → SEV1, convene the incident response team.
4. **Is personal, regulated, or contractual data potentially involved?** Yes → engage Legal and Privacy immediately (notification clocks may apply).
5. **Is the response beyond the team's capability or authority?** Yes → escalate to management and engage external IR retainer, cyber insurer, and law enforcement liaison as appropriate.
6. **Has an SLA been breached or the severity changed?** Re-evaluate and re-notify; **severity can only be lowered with IC approval and a documented reason**.

*When in doubt, escalate. Downgrading later costs less than a late escalation.*

### 2.3 Communication protocols

| Audience | Who communicates | Cadence | Content |
| --- | --- | --- | --- |
| Response team | IC | Continuous; status every 30-60 min on SEV1 | Tasks, findings, decisions |
| Executives | IC / CISO | At declaration, then every 2-4 hrs (SEV1) | Impact, business risk, decisions needed |
| Legal / Privacy | IC → Legal | Immediately for SEV1 or data exposure | Facts only; privileged channel |
| Employees | Communications Lead | As needed | What to do and not do; no speculation |
| Customers / partners | Communications + Legal | Only after approval | Verified facts, actions taken, guidance |
| Regulators / insurers / law enforcement | Legal | Per legal timelines | Required notifications only |
| Media | Designated spokesperson only | Reactive | Approved statement |

**Rules:** one source of truth; facts separated from assumptions; all times in UTC; need-to-know distribution; no discussion of the incident over compromised systems; Legal reviews all external messaging; every communication logged in the ticket.

### 2.4 Alignment with the lab's severity and escalation model

The generic SEV1–4 scheme above maps onto the lab's scored model (`Incident_Response_Template.md` §A.9: severity = **Impact × Scope × Urgency**, each 1–4, highest factor wins, then override and cap rules):

| This document | Lab model | Worked from `SOC-CASE-2026-0142` |
| --- | --- | --- |
| SEV1 Critical | **Critical** — only when `D5` = YES (persistence, C2, lateral movement, privilege escalation) | Not reached: `D5` = NO, so severity was **capped** |
| SEV2 High | **High** — base score plus override | **← the real case.** Impact 2 / Scope 1 / Urgency 2 → base Medium → **override +1 on `D3` = YES** (confirmed valid-account authentication) → **High**, mandatory Tier 2 |
| SEV3 Medium | **Medium** — base score before overrides | The case's pre-override score |
| SEV4 Low | **Low / informational** | Blocked-run alerts (2026-09-30 comparison) |

**Decision points:** the six questions in §2.2 are the generic form of the lab's seven objective decision points `D1`–`D7` (claimable/in-scope → real-vs-noise → **did any authentication succeed?** → isolation required? → post-compromise activity? → prior/parallel wave? → personal data / notification clock?). Each has an objective criterion, so two analysts branch the same way.

**Timing, as actually achieved in the real case:**

| Milestone | Target | `SOC-CASE-2026-0142` |
| --- | --- | --- |
| `D3` answered | ≤ 30 min | **< 1 minute** — the success event was the alert's own subject (`40112` level 12) |
| Declared / severity set | ≤ 30 min | **≈ 2 minutes** (declared ~17:52 UTC against 17:50:09 detection) |
| Tier 2 engaged (`D3` = YES) | ≤ 15 min after the decision | Same shift, case update + message both carrying the case reference |
| First containment action or decline-with-reason | ≤ 60 min | **T+20** — source blocked; endpoint isolation **declined with written reason** |
| Management engaged | On High/Critical | 18:10 UTC, case update with the severity arithmetic |

Standing rule carried into every message below: **the case reference (`SOC-CASE-2026-0142`) is stated in every communication** — a fact without a case ID cannot be traced back to evidence — and containment status is always reported *with its evidence*, never as an assertion.

---

## Part 3. Completed Incident Response Report — SOC-CASE-2026-0142 (real lab case)

### 3.1 Incident metadata

| Field | Entry |
| --- | --- |
| Incident ID | `SOC-CASE-2026-0142` (TheHive case `#142`, template *"Credential Attack — SSH brute force"*) |
| Environment | SOC lab — Wazuh 4.14.7 (manager/API/indexer/dashboard), TheHive 5.2.16, Kali Linux UTM endpoint |
| Category | Credential attack — SSH brute force escalating to **confirmed valid-account compromise** (MITRE **T1110** + **T1078**) |
| Severity | **High** (base Medium + override for confirmed authentication success; capped at High — no persistence/C2/lateral movement) |
| Status | Closed — operational response closed 2026-10-01 18:15 UTC; documentation completed 2026-10-05 |
| Roles | Kyrell Green — Tier 1 (triage, case owner); Tier 2 responder engaged (mandatory on confirmed success); no Tier 3 trigger; management/shift lead notified at High |
| Detected (machine) | **2026-10-01 17:50:09.931 UTC** — Wazuh rule `40112`, level 12 |
| Declared (human) | **≈ 17:52 UTC** — detection-to-declaration ≈ 2 minutes |
| Contained | **T+20** — source blocked; isolation considered and declined with reason |
| Recovered | No restoration required — no service interruption, no data loss (recovery is a documented no-op) |
| Reporter | Automated — Wazuh SIEM alert read from the indexer (`wazuh-alerts-4.x-2026.10.01`). **No push notification existed** (`<email_notification>no</email_notification>`) — the alert had to be looked for |
| Source-address caveat | `data.srcip = 192.168.64.3` **is the monitored agent's own address** (verified `agent.ip`) — a **self-generated lab test attack**, not a remote adversary. Must not be reported as an external attacker IP |

### 3.2 Executive summary

On 1 October 2026, Wazuh's correlation rule `40112` (level 12, *"Multiple authentication failures followed by a success"*) fired at 17:50:09 UTC on the lab's Kali endpoint (agent `002`, `192.168.64.3`). The brute force had run in three waves that day (16:23, 17:05, 17:48), preceded each time by an administrative `passwd labtester` command — the last one **2 minutes 15 seconds** before the successful login. On the winning connection, three failed password attempts and the success shared the same SSH PID (`2446058`) and source port (`49024`): the credential fell on the **fourth attempt**. The authenticated session lasted **71 milliseconds** and produced no observable activity — the credential was validated, not used. Severity was scored **High** (base Medium, +1 override for confirmed authentication success, capped because no post-compromise activity was found), Tier 2 was engaged, the source was blocked at T+20, the credential was rotated, and SSH key-only authentication was enforced to close the attack vector. A bounded four-day query of the host returned **no post-access activity of any kind**. No personal data was involved (purpose-created lab test account), so the case was assessed as not notifiable. The case was closed at 18:15 UTC the same day; findings `I.1`–`I.9` were assigned with owners and dates at the 2026-10-05 review.

### 3.3 Timeline (UTC)

| Time | Event | Source |
| --- | --- | --- |
| 10-01 16:22:17 | `sudo … COMMAND=/usr/bin/passwd labtester` (rule `5402` L3) — password change #1 | Wazuh indexer |
| 10-01 16:23:32 → 16:25:00 | **Wave 1**: `5763` / `5758` / `40111` / `5551` fire — brute force, **no success** | indexer |
| 10-01 17:03:06 | Password change #2 (`5402`) | indexer |
| 10-01 17:05:52 → 17:08:31 | **Wave 2**: correlation rules fire again — **no success** | indexer |
| 10-01 **17:38:44** | Internal rule `11`, level 4: log-volume anomaly *"average … 561. We reached 1812"* — **10 minutes before the successful wave, not actioned** | indexer |
| 10-01 **17:46:11** | Password change #3 (`5402`) — **2 min 15 s before the successful login. The enabling condition** | indexer |
| 10-01 17:48:26 → 17:50:07 | **Wave 3**: 61 indexed `5760` failures (`firedtimes` = **614** true volume), `5763` L10 ×93, `5758` L8 ×116, `40111` L10 ×31; 3 batches × 4 parallel connections (12 distinct source ports) | indexer |
| 10-01 17:50:02 / :05 / :07 | Three `Failed password for labtester` on PID `2446058`, port `49024` (`5760` firedtimes 605 → 610 → 612) | indexer |
| 10-01 **17:50:09.931** | **`40112` LEVEL 12** — *"Multiple authentication failures followed by a success."* `full_log`: `Accepted password for labtester from 192.168.64.3 port 49024 ssh2`. Same PID and port as the three failures — **attempt 4 accepted** | indexer |
| 10-01 17:50:09.931 → 17:50:10.002 | Session opened (uid **1001**, non-privileged) and closed — **71 ms**. Credential validated, not used | indexer (`5501`/`5502`) |
| 10-01 17:50:11 → 17:50:13 | Attack tool still running ~2 s after success (4 more `5760`) | indexer |
| 10-01 **~17:52** | **Case declared High; Tier 2 engaged** (mandatory on confirmed success); TheHive case record | TheHive |
| 10-01 ~17:52–18:10 | Containment: source blocked at the lab-segment edge (**T+20**); `labtester` privilege review; credential rotation; **endpoint isolation considered and declined** (session already closed, no post-access activity) — decisions recorded, not omitted | Case timeline |
| 10-01 18:00:45 | Last activity of any kind on the host that day — `lightdm` greeter events, not attacker-related | indexer |
| 10-01 18:10 | Management / shift lead notified with the severity arithmetic (High) | Case timeline |
| 10-01 ~18:15 | **SSH key-only authentication enforced** (hardening closes the vector); operational response closed | Case timeline |
| 10-01 18:15 | **Case closed** (operational); documentation completed 2026-10-05 | TheHive |
| 10-02 03:54 | FIM: `/etc/shadow` modified, *Mode: scheduled* — **attributable to the `passwd labtester` command, not tampering** | indexer + FIM |
| 10-01 → 10-05 | Bounded 4-day post-access query: **8 documents total, all benign** (4 × agent-disconnected lab VM shutdowns, 1 × the FIM event above, 3 × greeter sessions). **No `5402` by `labtester`, no new success, no persistence rule** | indexer |

*Pre-incident waves, the parallel-port structure and the exact `firedtimes` sequences are documented in full in `Incident_Response_Methodology.md` §6.2.*

### 3.4 Detection and analysis

- **Detection:** Wazuh stock ruleset — decisive alert **`40112` level 12** (`timeframe 240`, `if_group authentication_success` + `if_matched_group authentication_failures` + `same_source_ip`, MITRE T1078 + T1110). Supporting: `5763` L10 (brute force, freq 8/120 s), `40111` L10 (freq 12/160 s), `5758` L8 (max auth attempts), `5551` L10 (PAM failures), `5760` L5 (per-failure), `5501`/`5502` (session open/close), `5402` L3 (`passwd` command), internal `11` L4 (volume anomaly). **No custom rule exists** — every detection came from the shipped ruleset (`local_rules.xml` holds only the example `100001`).
- **Why volume did not decide the case:** the blocked run of 2026-09-30 (123 indexed failures, `5763` ×5, **zero** successes) versus the successful run of 10-01 shows **failure volume does not predict success** — only the presence of a success event (`40112`) separates them. Volume must be quoted as `rule.firedtimes` (614), not the indexed hit count (61) — an order-of-magnitude difference that is material in any notification.
- **Initial vector / enabling condition:** password authentication enabled on a reachable SSH service, a weak credential re-set three times the same day (last change 2 min 15 s before the attack), and a non-existent notification path (no email push, no Wazuh→TheHive connector).
- **Scope:** **one host** (agent `002`/`Kali`), **one account** (`labtester`, uid 1001, non-privileged), one source address. No privileged account targeted or accessed.
- **Post-access activity:** **none detected, within a stated telemetry bound.** The 4-day aggregation returned only benign infrastructure events. The honest conclusion is *"no post-access activity was **logged**"* — the agent's collection is authentication/journald-sourced, so a command that produced no log would not be visible. The 71 ms open/close pair with no `5402` in the window is strong evidence of credential **validation** rather than use.
- **Data impact:** **none assessed** — authentication telemetry about a purpose-created lab test account and lab infrastructure IPs; no natural person's credentials, no customer data. Recorded explicitly as *"assessed, not notifiable"*, because a decision not to notify must exist in writing. (Had this been a real user account, the GDPR Art. 33 72-hour clock would have started at 17:50:09.)
- **Indicators of compromise:** source `192.168.64.3` (**the monitored host's own address — self-generated lab test, not an external attacker**); account `labtester` (uid 1001); techniques T1110, T1078; 12 source ports in 3 batches × 4 parallel connections (tool attribution — a human does not type in parallel). The `203.0.113.77` address seen in EveBox is an **offline pcap replay artefact with synthetic 2002-08-28 timestamps** — an exercise indicator only, not threat intelligence for this event.
- **Evidence preserved:** original `40112` alert record (index doc `_id 4VOW-KABMZhxAQGakjXR`) quoted verbatim; the decisive `full_log` line; the same-PID/port failure→success sequence; the `5501`/`5502` session pair; `firedtimes` volume records; the three `5402` `passwd` events; the 2026-09-30 comparison run; the FIM attribution; the case audit trail. Chain of custody: original records quoted, never edited; every action timestamped and attributed.

### 3.5 Containment

- **Short term:** block the source at the lab-segment edge (**T+20**, reversible single rule); review and confirm account privileges; rotate the compromised `labtester` credential; suspend nothing else — blast radius was one unprivileged test account.
- **The isolation decision (declined, recorded):** endpoint isolation was explicitly **considered and declined** because the session had already closed (71 ms, before declaration), no post-access activity was found in the bounded window, and the source was identified. Isolation would have imposed downtime with no remaining threat to stop. **Recorded as a decision, not an omission** — evidence was captured *before* any state-changing action (capture → rotate → harden, never the reverse).
- **Long term / vector closure:** SSH **password authentication disabled, key-only enforced** within the first hour of the response — the control that would have prevented the whole incident; alerting-path review so a level-12 alert has a delivery path and a named owner.

### 3.6 Eradication

- **Nothing to remove — and that is a finding, not a gap:** no malware, no persistence mechanism, no backdoor account, no added SSH key was found. Eradication is documented as a distinct step precisely because here it had nothing to act on.
- Root cause patched (key-only SSH) and credential invalidated (rotation) — both conditions that produced the incident removed.
- FIM `/etc/shadow` changes on 10-01/10-02 were **attributed** to the legitimate `passwd labtester` command before any tampering conclusion was drawn.

### 3.7 Recovery

- **No restoration required** — no service interruption, no data loss, no encryption; the host remained in service throughout. Stated explicitly so the absence of a recovery phase is not mistaken for an omission.
- **Elevated monitoring, 30 days** on agent `002` (auth + FIM scrutiny, every subsequent alert cross-checked against this case's observables); the FIM baseline was deliberately **not** reset, so a recurrence would be detected rather than absorbed.
- **No extortion element:** this incident involved no ransomware, no encryption and no payment decision. The ransomware-specific response decisions (ransom payment, rebuild-vs-clean, backup validation) are handled in the §3.13 annex.

### 3.8 Communications log

| Date/Time (UTC) | Audience | Channel | Message | Owner |
| --- | --- | --- | --- | --- |
| 10-01 ~17:52 | Tier 2 on-call | Case update + message, both carrying `SOC-CASE-2026-0142` | L12 alert quoted verbatim; same-PID/port sequence; uid 1001; session 71 ms; severity High; **decision requested: isolation required?** | Tier 1 (Kyrell Green) |
| 10-01 ~17:57 | Tier 2 | Case update | Confirmed: no post-access activity in the bounded window; isolation **not** required; edge block sufficient | Tier 2 |
| 10-01 ~18:05 | System owner / lab admin | Ticket referencing the case | Disable SSH password auth; confirm segment ACL change | Tier 1 |
| 10-01 18:10 | Management / shift lead | Case update | High severity declared with scoring arithmetic; no Tier 3 trigger | Tier 1 |
| 10-01 18:10 | Legal / privacy | **Assessed and recorded, not notified** | No personal data (lab test account). *If a real user account: GDPR Art. 33 72-hour clock starts at detection* | Tier 1 |
| — | Tier 3 / forensics | Not engaged — no trigger | No persistence/C2/lateral movement; nothing to acquire beyond the indexer record | — |
| — | External (regulator / individuals / client) | Not applicable | No personal data, no contractual exposure; lab environment | — |
| Continuous | All case participants | TheHive case timeline | Every action, decision, approval and state change, timestamped and attributed | All |

### 3.9 Root cause and contributing factors

- **Root cause:** password-based SSH authentication was enabled on a reachable host, and the account's credential — re-set three times the same day, most recently 2 min 15 s before the attack — was weak enough to be guessed on the fourth attempt of a single connection.
- **Contributing factors (detection/response process):** no push notification path (email disabled, no Wazuh→TheHive connector), so nobody was *told* about a level-12 alert; no owner for low-severity anomaly alerts, so the 17:38 volume spike (10 minutes early) was never triaged; the enabling `passwd` commands were logged at level 3 and not correlated with the attack pressure on the same account; `40112` silently depends on `5715`'s group tag (a single point of failure with no error if it breaks).

### 3.10 Impact assessment

| Area | Impact |
| --- | --- |
| Operations | **None** — no service interruption, no downtime, host in service throughout |
| Data | **None** — no data access, exfiltration or loss; no personal data in scope (assessed, not notifiable) |
| Account security | One non-privileged account (`labtester`, uid 1001) credential compromised and rotated; no privileged account touched |
| Financial | Response effort only (lab environment); no recovery or restoration cost |
| Regulatory | Notification obligations **assessed and recorded as not applicable**; had a real user account been involved, GDPR Art. 33 72-hour clock would have applied |
| Detection quality | Two process gaps found (no notification path, unowned anomaly alert) plus four structural findings — recorded as `I.1`–`I.9` |

### 3.11 Lessons learned and corrective actions

| Action | Finding | Owner | Priority | Due |
| --- | --- | --- | --- | --- |
| Configure a working notification path — or formally designate indexer/dashboard as the sole monitored path **with a named owner and review cadence** | `I.2` — a level-12 alert notified nobody | Tier 2 + lab admin | Critical | 2026-10-12 |
| Assign an explicit owner and response for **low-severity anomaly alerts** below the high-severity queue | `I.3` — the level-4 spike fired 10 min early and was never owned | Tier 1 lead | High | 2026-10-12 |
| Enforce key-only SSH on all lab endpoints; treat "password auth on an exposed service" as a standing control failure | `I.7` — the condition that made the incident possible | Lab admin | High | 2026-10-12 |
| Document the `40112` → `5715` silent dependency and health-check it | `I.1` — correlation rule depends on another rule's metadata tag | Tier 2 | High | 2026-10-12 |
| Add an account-aggregation / spraying rule (current rules are `same_source_ip` only) | `I.8` — password spraying is undetectable | Tier 2 | High | 2026-10-19 |
| Correlate administrative credential changes (`5402`) with authentication-failure clusters on the same account | `I.9` — three `passwd` commands invisible to detection | Tier 2 | High | 2026-10-19 |
| Either deploy the intended custom detection rule or correct the documentation claiming it (rule `100010` does not exist) | `I.6` — documented capability that is not deployed | Kyrell Green | High | 2026-10-07 |
| Add "bound the session from the PAM open/close pair" as a mandatory template task | `I.4` — the cheapest decisive discriminator | Tier 1 | Medium | 2026-10-10 |

**What went well:** the stock rule set raised the correct level-12 alert within a minute of the compromise; the session was bounded to 71 ms and correctly classed as validation rather than use; same-PID/port correlation proved the exact successful attempt; severity was scored with recorded arithmetic and *capped* rather than inflated; the declined isolation decision was documented with its reason; the 09-30 blocked run and 10-01 successful run together gave a clean regression baseline.

**What to improve:** remote-access and password-authentication controls; the notification path; ownership of low-severity signals; documentation matching deployed capability (the `100010` gap); detection coverage for spraying and for credential-change correlation.

### 3.12 Closure and approval

| Field | Value |
| --- | --- |
| Case closed by | Kyrell Green (Tier 1), Tier 2 review complete |
| Date/time closed | 2026-10-01 18:15 UTC (operational response); documentation completed 2026-10-05 |
| Final severity | **High** (base Medium + confirmed-authentication override; capped — no persistence/C2/lateral movement) |
| Final status | **Contained — confirmed credential compromise of one non-privileged account, no post-access activity observed within telemetry bounds** |
| Time to declare | ≈ 2 minutes from the `40112` alert |
| Time to answer "did a login succeed?" | < 1 minute — the success was the alert's own subject |
| Time to contain | ≈ 20 minutes (source blocked, T+20) |
| Follow-ups outstanding | `I.1`–`I.9`, owners and dates above |
| Lessons-learned review | Held 2026-10-05 with Tier 2; outputs recorded as findings `I.1`–`I.11` |
| Sign-off | Incident Commander: ________  ·  Tier 2 reviewer: ________  ·  Date: __________ |

### 3.13 Ransomware annex (illustrative scenario — how this process applies)

*The assignment title names a ransomware report. The lab's real incident (§3.1–§3.12) was a credential compromise — no encryption, no ransom demand, no payment decision. This annex is therefore a **scenario extension**: fictional and illustrative, it shows that the same case-management and escalation machinery from Parts 1–2 covers a ransomware incident, and states what this lab does and does not have to support one.*

**Declaration.** Encryption behaviour or a ransom note on any host is **SEV1 on sight** (§2.1) — acknowledge in 15 minutes, convene the IC, open the bridge, and start the executive clock. Unlike §3, where severity was *scored up* to High, ransomware starts at the top: the encryption itself is the `D3`-equivalent success event.

**Decision points, in order:**

| # | Decision | Guidance |
| --- | --- | --- |
| 1 | **Isolate vs. shut down** | **Isolate, don't power off** — a powered-off host loses volatile evidence (memory, network connections, encryption keys in RAM). Same rationale as §3.5: capture evidence *before* any state change. Power-off is a last resort when isolation cannot stop spreading. |
| 2 | **Protect the backups first** | Before anything else, move backup systems out of the attacker's reach — ransomware crews target backups precisely because they force the payment decision. |
| 3 | **Scope the campaign, not the alert** | `D6` in action: search backwards (when did the first mass-file-modification signal appear?) and sideways (which accounts moved laterally?). Ransomware is almost never a single-host incident. |
| 4 | **Personal/regulated data involved?** | `D7` = YES almost by default — pre-encryption exfiltration ("double extortion") must be assumed until disproved. GDPR Art. 33 clock starts at **awareness**, not at containment. |
| 5 | **Ransom decision** | **Not paid** (the documented default): no guarantee of decryption or of data deletion; sanctions exposure; law-enforcement guidance discourages payment. The decision belongs to management + Legal with the cyber insurer engaged — **never to the SOC alone**, and it is recorded in the case either way. |

**Response phases mapped:** *Containment* — segment the network, disable compromised accounts, block attacker C2 IPs, keep clean backups isolated (as §3.5 did with the edge block and rotation). *Eradication* — **rebuild from known-good images rather than cleaning in place**; the §3.6 lesson ("nothing to remove" here) becomes "assume nothing was missed" under encryption malware; rotate all privileged and service-account credentials. *Recovery* — restore from **offline, immutable backups scanned before use**, in dependency order (identity → critical business services → file shares → endpoints), staged under 30-day enhanced monitoring — the same posture §3.7 already practises.

**Communication additions versus §3.8:** executives **at declaration** (not at T+20), Legal/Privacy immediately (data exposure assumed), insurer + external IR firm on notice, all-hands employee message ("do not open ransom notes, do not power devices on, use out-of-band channels"), customers/partners only after Legal review and regulatory assessment, law-enforcement liaison via Legal. All of it lands in the same place as §3.8: **the case timeline, with the case reference on every message.**

**What this lab has for a ransomware scenario, and what it does not:**

| Capability | Status |
| --- | --- |
| Case record, roles, tasks, audit trail (TheHive) | **Present** — §1.3 |
| Scored severity model + decision points + approval gate | **Present** — §2.4; containment is human-approved by design |
| Mass file-change detection | **Partially present** — Wazuh FIM (syscheck) monitors file changes and would catch mass renames; behavioural "encryption in progress" EDR detection exists only as a **mock** in the capstone's EDR API, not as live endpoint tooling |
| Offline/immutable backup practice | **Policy only** — a corrective action in the lab's own plans; no backup infrastructure in the lab to exercise |
| Notification path for a level-12/SEV1 alert | **Gap (`I.2`)** — email notification is disabled; a ransomware SEV1 would currently be found only by someone looking at the dashboard |
| Live EDR isolation / lateral-movement telemetry | **Gap** — isolation in §3.5 was an edge block and a documented decision, not an automated endpoint isolate |
| Out-of-band coordination channel | **Gap** — assumed by policy; no second channel deployed |

---

## Part 4. Response Methodology Summary

This documentation follows the standard incident response lifecycle (NIST SP 800-61: **Preparation → Detection & Analysis → Containment, Eradication & Recovery → Post-Incident Activity**). Core principles demonstrated:

- **Defined roles and authority** so decisions are fast and accountable — Tier 1/2/3 with explicit triggers, and a named human approving every containment action (§3.5's declined-isolation decision is logged like any action taken).
- **Severity-driven escalation** with explicit criteria rather than individual judgment alone — scored arithmetic with an override *and* a cap (§2.4), so `SOC-CASE-2026-0142` landed on High for recorded reasons, not feelings.
- **Evidence preservation** alongside speed of containment — capture → rotate → harden, in that order; original records quoted verbatim; chain of custody from minute one (§3.4–§3.5).
- **Single record of truth**, with chat used for coordination only — in this lab the case timeline *is* the coordination surface (§1.3), and every communication carries the case reference (§3.8).
- **Legal and communications involvement** early for incidents with data or regulatory impact — "assessed, not notifiable" was a *written decision* with its reasoning, not silence (§3.8), and the annex shows the same machinery carrying GDPR clocks and insurer notice for a ransomware scenario.
- **Human oversight of key decisions** (isolation scope, ransom, notification), consistent with the human-in-command principle in the uploaded Agentic SOC Guide, whose Phase 2 and governance sections recommend automating triage and enrichment while requiring human approval for containment and escalation.
- **Continuous improvement** through a blameless review and tracked corrective actions — findings `I.1`–`I.9` each with an owner and a due date (§3.11), and detection gaps treated as findings rather than background noise (the unactioned 17:38 anomaly, the silent `40112`→`5715` dependency, the undetectable-spraying gap).
- **Honesty about scope and telemetry** — conclusions about absence of activity are bounded by what the agent actually logs and say so (§3.4), and lab-test artefacts (the self-generated source IP, the replayed pcap timestamps) are labelled instead of presented as real adversary evidence.
