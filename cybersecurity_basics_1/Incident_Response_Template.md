# Incident Response Documentation Template

**Author:** Kyrell Green
**Date:** 2026-10-05
**Module:** Cyber Threats & Vulnerabilities — SOC Security Analyst track
**Purpose:** The reusable form every incident case file is completed against.
**Companion documents:**
- `Incident_Response_Methodology.md` — the response methodology this template implements, and a
  fully completed instance of this template for the 2026-10-01 SSH brute-force compromise
- `Incident_Response_Plan.md` — the lifecycle plan (detect → contain → eradicate → recover)
- `Comprehensive_Security_Policy.md` §3–§4 — the severity model and notification path this
  template's Section A and Section H feed

---

## How to use this template

1. **Copy** this file per incident (one file = one case). Name it
   `IR-CASE-YYYY-NNNN_<short-title>.md`.
2. **Fill every field.** An unfilled field is an unanswered question; if a field genuinely does
   not apply, write `N/A — <reason>` rather than deleting it. Blank fields are what make case
   files unusable during a post-incident review.
3. **Use UTC timestamps** to the second, taken from the sensor, not from memory. Every entry
   needs a **source** (which log/index/query it came from) so a reviewer can re-derive it.
4. **Never edit an original alert or log.** Quote it. Corrections go in a separate note.
5. **Every action in Section F needs a named human approver.** An automated or AI-recommended
   action is not actioned until a person approves it, and the approval is logged with its
   timestamp.
6. Severity is scored with the **Section A.9 factor matrix**, not by intuition. Escalation
   criteria that are not measurable are not criteria.

**Field-completion standard:** every field must be answerable by a third party who was not
present — a replacement analyst at 03:00, a responder picking up the case on shift change, a
manager, or an auditor.

---

## Section A — Case identification

Fill first; it is what every other team uses to find the case.

| # | Field | Value | Guidance |
|---|---|---|---|
| A.1 | Case reference | | `SOC-CASE-YYYY-NNNN` plus the case-management ID (e.g. TheHive `#142`) |
| A.2 | Incident title | | One line naming the behaviour, the target, and the account — a stranger must understand it |
| A.3 | Incident type (designated class) | | e.g. SSH brute force / credential compromise (T1110), ransomware (T1486), phishing (T1566) |
| A.4 | MITRE ATT&CK mapping | | Technique ID + name + tactic, taken from the **sensor's** `rule.mitre` field, not guessed |
| A.5 | Detection rule(s) / sensor(s) | | Rule ID **and level** **and** which sensor produced it; note if two sensors agree |
| A.6 | Date/time **detected** (machine) | | The sensor's timestamp for the first qualifying event |
| A.7 | Date/time **declared** (human) | | When a named analyst declared an incident. `A.7 − A.6` = detection-to-declaration time |
| A.8 | Reporter / detection source | | Automated sensor name, or the person who reported it |
| A.9 | **Severity** + score | | Score with the factor matrix below and show the arithmetic |
| A.10 | Status at declaration | | `Attempted` / `Attempted + blocked` / `Confirmed compromise` / `Contained` / `Eradicated` / `Recovered` / `Closed` |
| A.11 | Affected asset(s) | | Hostname, **agent ID as the SIEM reports it**, IP, service/port |
| A.12 | Affected account(s) | | Targeted account(s) and account(s) actually accessed; record privilege level (uid) |
| A.13 | Lead investigator | | Named person + tier |
| A.14 | Supporting staff / notified | | Who else was involved or notified, and their tier/role |
| A.15 | Case management system + template | | Which system holds the case and which template it was created from |
| A.16 | Personal data involved? (Y/N + reasoning) | | Triggers the notification obligation in Section H — decide explicitly, never leave blank |

### A.9 Severity factor matrix

Score three factors 1–4 each; **severity = the highest factor, not the sum**, then apply the
upgrade/override rules.

| Factor | 1 — Low | 2 — Medium | 3 — High | 4 — Critical |
|---|---|---|---|---|
| **Impact** (what is true now) | Attempted only; no access | Access gained to a non-privileged account, no data loss | Privileged access, credential theft, or data loss | Encryption/destruction, or confirmed C2 with exfiltration |
| **Scope** (breadth) | 1 host, 1 account | 1 host, few accounts | Multiple hosts or multiple accounts | Fleet/subnet or multi-site |
| **Urgency** (rate/direction) | Historic, over | Single wave, ended | Ongoing or recurring | Active, spreading, or destructive |

**Overrides (these beat the arithmetic):**
- Confirmed successful authentication to a valid account after brute force → **raise by one
  level** and force **mandatory Tier 2** escalation.
- Any post-compromise indicator (persistence, C2 beacon, lateral movement, privilege
  escalation) → **Critical**, mandatory Tier 3 + management notification.
- Personal data confirmed exfiltrated → **notification obligation starts** (Section H),
  regardless of technical severity.
- *No* successful authentication after a large, well-formed attack → do **not** escalate above
  Medium; verify existing hardening instead of assuming the worst case.

Record the arithmetic explicitly, e.g. `Impact 2 / Scope 1 / Urgency 2 → base Medium; override
"confirmed valid-account authentication" → **High**.`

---

## Section B — Initial response log (first 60 minutes)

The runbook this section records is in `Incident_Response_Methodology.md` §2. Timestamps are
`T+` minutes from alert receipt.

| # | Time (UTC / T+) | Action | Actor + tier | Decision or evidence that justified it | Result |
|---|---|---|---|---|---|
| B.1 | | Alert acknowledged / claimed in the case system | | Prevents duplicate work; starts the SLA clock | |
| B.2 | | Original alert payload read (rule, level, host, account, src IP, MITRE) | | Confirm the alert says what it claims to say (decision point **D1**) | |
| B.3 | | Detection corroborated or refuted by a second source | | Single-sensor alerts are hypotheses, not findings (**D2**) | |
| B.4 | | Evidence preserved unaltered; case page references original records | | Chain of custody starts now, before any action mutates state | |
| B.5 | | Identity evidence gathered (account history, risk factors) | | Answers "was this account used before, from where" | |
| B.6 | | Endpoint evidence gathered (process, network, file telemetry) | | Answers "what ran on the host during the window" | |
| B.7 | | Related SIEM events gathered (same src IP, same account, same host, ±window) | | Answers "what else happened" | |
| B.8 | | **Was any authentication successful?** | | The single highest-value question in the whole case (**D3**) | |
| B.9 | | Scope established: hosts, accounts, window, volume | | Volume must come from `rule.firedtimes`, not the indexed hit count | |
| B.10 | | Severity scored (Section A.9) and set in the case | | Drives the escalation path and the SLA | |
| B.11 | | First containment action(s) taken or explicitly declined | | **D4** — declining is a decision and must be recorded with its reason | |
| B.12 | | Escalations made, with time and target | | Per the escalation criteria, with the criterion that fired | |

**Do not skip B.8.** Every serious error in credential-attack response comes from treating a
successful login as "probably noise" or from never asking.

---

## Section C — Full incident timeline

One row per material event, chronological, in UTC. Include the pre-incident context that makes
the event intelligible (credential changes, prior waves, maintenance) — not just the attack.

| Time (UTC) | Event | Source (log / index / rule / query) | Significance |
|---|---|---|---|
| | | | |

---

## Section D — Evidence collected

| # | Evidence type | Artifact / exact reference | Where preserved (system + location) | Integrity note (unaltered? hash?) | Collected by / when |
|---|---|---|---|---|---|
| D.1 | Original alert record(s) | | | | |
| D.2 | Authentication logs | | | | |
| D.3 | Network sensor evidence | | | | |
| D.4 | Identity/account evidence | | | | |
| D.5 | Endpoint telemetry | | | | |
| D.6 | Threat-intelligence enrichment | | | | |
| D.7 | Screenshots / console captures | | | | |
| D.8 | Statements / interviews (if any) | | | | |

Guidance: quote `full_log` verbatim for the events that decide the case (the success or failure
of authentication, the session open/close, any command execution). A paraphrased log line is
not evidence.

---

## Section E — Analysis and determination

| # | Question | Determination | Evidence that proves it |
|---|---|---|---|
| E.1 | Did the attack succeed? | | |
| E.2 | If it succeeded, what was actually done in the session? | | Session duration, commands, files, processes |
| E.3 | Was there any post-access activity? | | State the query **and its window** — "no activity found" is only meaningful with both |
| E.4 | What was the root cause? (credential choice, exposed service, policy gap, missing control) | | |
| E.5 | What was the enabling condition? (why was the account reachable/valid/guessable) | | |
| E.6 | Why did the attacker have that password? | | Distinguish guessing from breach/reuse — they have different fixes |
| E.7 | Detection coverage: what fired, what should have fired and did not? | | Naming a *missed* detection is a finding, not a criticism of the tool |

**E.3 caveat to state explicitly in every case file:** conclusions about absence of activity are
bounded by telemetry availability. If the endpoint agent ships only authentication/journald
events, you cannot conclude "no commands were run" — you can only conclude "no commands were
*logged*". Write the limitation down.

---

## Section F — Response actions taken

Separate **containment** (stop it) from **eradication** (remove it) from **recovery** (restore).
Record declined actions too — "considered and declined because X" is a decision a reviewer needs.

| # | Phase | Action | Approved by (named human) | Time | Evidence of effect | Reversible? |
|---|---|---|---|---|---|---|
| F.1 | Containment | | | | | |
| F.2 | Containment | | | | | |
| F.3 | Eradication | | | | | |
| F.4 | Recovery | | | | | |

Guidance:
- Containment actions should be **cheap and reversible** — a source-IP block, not a reformat.
- Every containment action needs the approver's name and the approval time. An action taken
  without recorded authorisation is both a control failure and a documentation failure.
- Never destroy evidence to "clean up". Eradicate after the evidence is captured and preserved.

---

## Section G — Indicators of compromise

| Type | Value | First seen | Last seen | Confidence | Where observed | Action taken |
|---|---|---|---|---|---|---|
| IPv4 | | | | | | |
| Account | | | | | | |
| Host | | | | | | |
| File / hash | | | | | | |
| Process | | | | | | |
| Port / service | | | | | | |
| ATT&CK technique | | | | | | |

Guidance: never write an indicator you cannot source. If an IP is a lab/reserved range used for
demonstration, say so in the record — otherwise a future reader may treat it as real threat
intelligence.

---

## Section H — Communication and notification log

| # | Time (UTC) | Audience | Channel | Content summary | Sent by | Acknowledged by / when |
|---|---|---|---|---|---|---|
| H.1 | | Tier 2 on-call | | | | |
| H.2 | | Tier 3 / IR lead | | | | |
| H.3 | | Management / shift lead | | | | |
| H.4 | | System owner / IT | | | | |
| H.5 | | Legal / privacy (if personal data) | | | | |
| H.6 | | External (regulator / individuals / client) | | | | |

Notification obligations, if personal data is involved (Section A.16): notify the supervisory
authority within **72 hours** of becoming aware (GDPR Art. 33), and affected individuals without
undue delay where risk is high (Art. 34). Record the decision either way — a documented
"assessed, not notifiable, because Y" is as important as a notification.

---

## Section I — Post-incident review

| # | What worked | What did not work / nearly failed | Evidence of the gap | Fix | Owner | Due date | Status |
|---|---|---|---|---|---|---|---|
| I.1 | | | | | | | |
| I.2 | | | | | | | |

Review rules:
- Review **detection**, not just response. "We found out 5 days later" is a detection finding.
- Review **the human process**: was the alert seen by a person? was the escalation path used?
- Every finding needs an **owner** and a **date**. An unowned finding will not be fixed.
- The case is not closed until this section is complete and the case file is final.

---

## Section J — Closure

| Field | Value |
|---|---|
| Case closed by (named human) | |
| Date/time closed | |
| Final severity | |
| Final status | |
| Time to declare | |
| Time to contain | |
| Time to eradicate | |
| Time to recover | |
| Case file location | |
| Follow-up actions outstanding (IDs + owners) | |
| Lessons-learned review held on (date, attendees) | |

---

## Completed instances

| Case | Date | Incident | Where the completed form lives |
|---|---|---|---|
| SOC-CASE-2026-0142 | 2026-10-01 | SSH brute force that **succeeded** against `Kali` — rule 40112, MITRE T1078 + T1110 | `Incident_Response_Methodology.md` §6 (completed instance of this template) |