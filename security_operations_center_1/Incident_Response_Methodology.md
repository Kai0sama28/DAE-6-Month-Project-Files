# Incident Response Methodology — SSH Brute Force & Credential Compromise (SOC Lab)

**Author:** Kyrell Green
**Date:** 2026-10-05 (rewritten and re-verified against the live lab; supersedes the 2026-09-15 draft — see §9)
**Module:** Cyber Threats & Vulnerabilities — SOC Security Analyst track
**Designated incident type:** SSH brute-force / credential-stuffing attack against a valid account, escalating to **confirmed valid-account compromise**
**MITRE ATT&CK:** T1110 (Brute Force) + T1078 (Valid Accounts) — Credential Access / Initial Access / Persistence / Privilege Escalation / Defense Evasion
**Case management system:** TheHive 5.2.16, deployed and reachable in the lab
**Companion documents:**
- `Incident_Response_Template.md` — the reusable form this methodology's §6 completes
- `Incident_Response_Plan.md` — the lifecycle plan (detect → contain → eradicate → recover)
- `Comprehensive_Security_Policy.md` §3–§4 — severity model and notification path
- `../security_operations_center_1/Threat_Detection_Principles.md` — how each detection rule below was proven

**Lab environment (all verified live on 2026-10-05):**

| Component | Version | Address | Role in this methodology |
|---|---|---|---|
| Wazuh manager + API | 4.14.7 | `https://localhost:55000` | Alert rules, agent inventory, rule source of truth |
| Wazuh indexer | 4.14.7 | `https://localhost:9200` | **Alert store — the only working alert-delivery path** |
| Wazuh dashboard | 4.14.7 | `https://localhost:443` | Analyst-facing alert view |
| TheHive | 5.2.16 | `http://localhost:9000` | Case management system (§3) |
| Suricata + EveBox | 8.0 / latest | `http://localhost:5636` | Network-side corroboration (offline pcap replay) |
| Kali Linux endpoint | — | agent `002` / `Kali` / `192.168.64.3` | The attacked asset |

---

## Rubric coverage

| Rubric requirement | Where it is satisfied |
|---|---|
| Thorough documentation of **initial response protocols** for a designated incident type | §1 (incident definition + real detection chain), §2 (60-minute runbook, T+0→T+60, with decision points D1–D7) |
| Detailed descriptions of **case management system components** and their **operational purpose** | §3 (TheHive 5.2.16, every component: purpose in general + purpose in this workflow, plus what the lab's deployment is missing) |
| Comprehensive **escalation criteria and communication protocols** with **clear decision points** | §4 (severity factor matrix, tiers, escalation triggers, decision map, notification matrix with legal clocks) |
| Successfully **complete the incident response documentation template** for the provided scenario | §6 — every section (A–J) of `Incident_Response_Template.md` completed for the real 2026-10-01 compromise |
| Demonstrates understanding of **IR principles and documentation requirements** with clear explanations of response methodologies | §5 (principles, methodology, why each phase is ordered as it is), §7 (what the documentation must let a later reader do), §8 (evidence & reproducibility appendix) |
| "The provided scenario" | §6 completes the template for the scenario **this lab actually produced**: a brute-force attack that **succeeded** on 2026-10-01. §9 explains why that replaces the earlier draft's "blocked" scenario. |

---

## 1. The designated incident type, and how it is actually detected

### 1.1 What the incident type is

An **SSH brute-force attack** is a credential-access attack in which an adversary makes many
authentication attempts against the SSH service, guessing passwords until one is accepted. It is
designated here as a **credential-access → compromise** incident type, because in this lab it
reached **T1078 (Valid Accounts)**: the password was correct, and the attacker held a real
authenticated session on the host.

The reason this type is the right one to designate is that it exercises the whole of
incident response in miniature, and it is the one incident type this lab can genuinely produce
end-to-end:

| Property | Why it matters for response |
|---|---|
| **Automatable and high-volume** | An attacker gets thousands of guesses per minute for the cost of one script; the analyst's job is not to read every failure but to read the *aggregate* |
| **Binary outcome** | The attack either got in or it did not. That single question (`D3` in §2) splits a nuisance alert into a real breach, and it is the highest-value question in the case |
| **Perfect log coverage at the boundary** | The SSH daemon logs every attempt and every outcome, so the decision is made on primary evidence rather than inference |
| **Escalation is cheap if caught, expensive if missed** | One accepted password yields a foothold: lateral movement, persistence, data access |
| **Commonly a false-positive generator** | Internet-wide scanning hits every exposed host constantly; **a large, well-formed attack against an account that does not exist is noise; against a valid account it is an incident** |

That last row is the single most important operational lesson from this lab, and it is
demonstrated with evidence in §1.3.

### 1.2 The real detection chain (verified in the manager's ruleset, 2026-10-05)

Every rule below was read from the running manager's ruleset files, not from documentation or
memory. All of these are **stock Wazuh rules** — this lab runs the shipped rule set, and there
is **no custom detection rule deployed** (proved in §9.2).

**Branch A — attempts against a username that exists on the host** (the branch that matters):

```
5700  level 0, no alert  — sshd decoder / pre-match entry point (decoded_as sshd)
 ├─ 5716  level 5  — "SSHD authentication failed"        (generic failure)
 └─ 5715  level 3  — matches "^Accepted|authenticated.$"  → group: authentication_success
                    (the ONLY rule that tags a successful SSH login)

5760  level 5  — "^Failed password for ..."              → group: authentication_failed
  └─ 5763  level 10 — frequency 8 / timeframe 120 / ignore 60 / same_source_ip
                     "sshd: brute force trying to get access to the system"
                     MITRE T1110                          ← the brute-force verdict

5758  level 8  — "^error: maximum authentication attempts exceeded"
                  (per-connection abort; marks the attacker's parallel-connection pattern)
```

**Branch B — attempts against a username that does *not* exist** (the noise branch):

```
5700 → 5710  level 5  — "Invalid user"                     → group: authentication_failed
              └─ 5712  level 10 — frequency 8 / timeframe 120 / ignore 60 / same_source_ip
                                (invalid-user brute-force twin)

5758  level 8  — "maximum authentication attempts exceeded" (also reached via if_sid 5710)
```

**Branch C — cross-rule correlation** (`0280-attack_rules.xml`), the rules that actually
decided this case:

| Rule | Level | Logic | Fires when |
|---|---|---|---|
| **40111** | 10 | `frequency 12 / timeframe 160 / if_matched_group: authentication_failed / same_source_ip` | Volume of failures from one source, regardless of username validity |
| **40112** | **12** | `timeframe 240 / if_group: authentication_success / if_matched_group: authentication_failures / same_source_ip` | **Failures followed by a success from the same source** |

The `40112` definition, read verbatim from the running manager:

```xml
<rule id="40112" level="12" timeframe="240">
  <if_group>authentication_success</if_group>
  <if_matched_group>authentication_failures</if_matched_group>
  <same_source_ip />
  <description>Multiple authentication failures followed </description>
  <description>by a success.</description>
  <mitre><id>T1078</id><id>T1110</id>...</mitre>
```

Two consequences an analyst must understand, because they are not obvious and both shaped this
case:

1. **`40112` depends entirely on `5715`.** Its `if_group` is `authentication_success`, and the
   only rule in the SSH chain that carries that group tag is `5715`. If `5715`'s regex does not
   match the log line, `40112` can never fire — no matter how blatant the attack. A
   correlation rule that depends on another rule's metadata tag is a **silent single point of
   failure**, and it is worth an explicit health check.
2. **The correlation is `same_source_ip` only.** `40111`, `40112`, `5712`, `5763` and `5551` all
   scope on source IP alone. **No rule in this ruleset can detect password spraying**, where one
   source tries one password against many accounts (or one account from many sources). That is a
   real, named coverage gap, not a hypothetical one — recorded as gap **G5** in §3.4.

**Branch D — the anomaly layer.** Internal rule **`11`**, level 4, group `stats`:
*"The average number of logs between 17:00 and 18:00 is 561. We reached 1812."* It is a
log-volume anomaly detector, not an attack rule. It fired **ten minutes before** the successful
attack in this case and nobody acted on it (§6.2, §6.8). It is included here because a
methodology that only documents the rules that fired is not documenting the detection layer.

### 1.3 How this lab *distinguishes a real attack from noise* — with evidence

The lab produced two structurally identical attacks one day apart. They are the cleanest
available demonstration of the triage judgement this methodology has to encode:

| | **Run 1 — 2026-09-30, 18:35:30 → 18:42:39** | **Run 2 — 2026-10-01, 17:48:26 → 17:50:09** |
|---|---|---|
| Indexed `5760` (Failed password) events | **123** | **61** |
| `5760` `firedtimes` (true volume) | 123 | **614** |
| `5763` brute-force (L10) firings | **5** | **93** |
| `5758` max-auth-attempts (L8) | 8 | **116** |
| `40111` multiple-failures (L10) | 2 | **31** |
| `5551` PAM auth failure (L10) | 2 | 3 |
| `5715` **authentication successes** | **0** | **0** → **1** |
| `40112` (L12) | 0 | **1** |
| Outcome | **Blocked.** Password never guessed. | **Compromised.** Password guessed; 71 ms session. |

Two conclusions that belong in the methodology, because both are counter-intuitive:

- **Failure volume did not predict success — the opposite happened.** Run 2 had *half* the
  indexed failures and *far* more total attempts (`firedtimes` 614 vs 123), and it is the run
  that got in. There is **no rate or volume threshold in this ruleset that separates them**. An
  analyst who triages on "how many failures" triages this case wrong.
- **The only rule that separated them was `40112`.** Not volume, not rate, not username — the
  presence or absence of a *success* event. This is the empirical justification for making
  `D3` ("did any authentication succeed?") the mandatory, non-skippable question in §2, and for
  `5715` being the highest-value rule in the chain despite being level 3 — the lowest-severity
  rule that fired in the entire case.

### 1.4 A trap in counting attack volume

`5760` reached `firedtimes` **614** on 2026-10-01, but only **754** `5760` documents exist across
the whole day, and only **61** in the attack window. The gap is Wazuh's **alert compression**
combined with `5763`'s `ignore="60"` attribute: after a rule fires, repeat matches inside the
ignore window increment `firedtimes` instead of generating new alerts.

**Rule for every analyst and every case file: quote `rule.firedtimes`, not the hit count, when
stating attack volume.** A case file that says "61 failed logins" when 614 attempts were made
understates the attack by an order of magnitude — and in a legal or notification context that
is a material error, not a rounding difference.

---

## 2. Initial response protocols (the runbook)

### 2.1 What "initial response" means, and what it deliberately is not

**Initial response** is the structured set of actions taken from the moment an analyst is
notified of a potential incident until the situation is understood well enough to have chosen a
response. It covers the **Detection & Analysis** phase of NIST SP 800-61 and the start of
**Containment**.

Its governing principle is *crawl, don't jump* — and, more precisely: **contain while you
analyse.** You do not wait for a complete forensic picture before cutting off an active
attacker. You do take the cheapest reversible action that stops the bleeding while you keep
learning. That is why §2.3's block-3 actions are source blocks and credential rotations rather
than reimaging.

**The hard rule of this lab, and of the capstone that consumes this methodology:** every
containment action is a **human decision**. The AI-Agentic SOC engine may assemble the
investigation bundle and *recommend* an action, but a named analyst authorises it at the
approval gate, and the authorisation is logged with a timestamp. This is not a stylistic
preference — it is the control that makes the response defensible, and it is what
`Incident_Response_Template.md` Section F enforces with its "Approved by (named human)" column.

### 2.2 Triage priority, not arrival order

Alerts are worked in severity order, not arrival order. The severity model is in
`Incident_Response_Template.md` §A.9; the operational consequence is:

- Every alert on this incident type reaches a **decision point within 30 minutes**, regardless of
  whether it is the newest alert.
- A **level 12** `40112` outranks every level 10 correlation alert in the queue, even though it
  arrives *later* — because it is the only one that reports a completed compromise.
- A level 4 `stats` anomaly does not wait for the high-severity queue to clear; it is checked
  for an unhandled attack in progress, because that is exactly what it was in this case.

### 2.3 The 60-minute runbook

#### Block 1 — T+0 to T+10: assess and verify

| # | Action | Why it is here / what decision it feeds |
|---|---|---|
| 1.1 | **Acknowledge and claim** the alert in TheHive; open or attach to the case | Ownership from minute one; prevents two analysts working one alert; starts the SLA clock. In this lab the alert must be *reached* through the indexer or dashboard — email notification is **disabled** in `ossec.conf`, so there is no pushed notification to receive (**D1**) |
| 1.2 | Read the alert's own fields: `rule.id`, `rule.level`, `rule.mitre`, `agent.id`/`agent.name`, `data.srcip`, `data.dstuser`, `@timestamp`, `full_log` | Confirm the alert says what it claims to say. Read `full_log` verbatim — never work from the description alone. In this case `5715`'s description is only *"sshd: authentication success"*; the fact that it was a **password** login for a **valid** account is visible only in `full_log` (**D1**) |
| 1.3 | **Establish the alert's provenance**: which index, which rule source file, which agent | An alert from an index nobody remembers enabling is a finding in itself (§6.7, `E.7`) |
| 1.4 | **Preserve the original record unaltered** — quote it into the case, do not edit or re-tag it | Chain of custody begins before any action mutates state. Everything downstream — timeline, notification, post-incident review — depends on the original still being intact |
| 1.5 | Query for **sibling alerts** from the same source IP, account and host over a window wider than the alert's own | A correlation rule's alert is a *summary*; the individual events around it are the evidence (**D2**) |

#### Block 2 — T+10 to T+30: decide real attack or noise

| # | Action | Why it is here / what decision it feeds |
|---|---|---|
| 2.1 | Gather the **three evidence pillars** for the window: identity (account history, risk factors), endpoint (process / network / file telemetry), and related SIEM events | Separates "an alert fired" from "something happened". Each pillar can independently contradict the others, and the contradictions are the interesting part |
| 2.2 | **Establish the username's validity on the target** — does the account exist, and at what privilege? | The highest-value discriminator in this incident type, and it is *not* in the alert. In this lab it was the whole difference between noise and incident (§1.3): attempts against a non-existent user take branch B and can never reach `5760` |
| 2.3 | **Search explicitly for an authentication success.** Not "check whether the attack succeeded" — run a query for `rule.id: 5715` / for `authentication_success` over the window and a margin either side, and for any session-open/close pair | **`D3` — the mandatory question.** Run it against `5715` and against the raw log text (`Accepted`), because `D3` must be answerable even if `5715` is broken (**D3**) |
| 2.4 | If a success is found, **bound the session**: find the session-open and session-close events and compute the duration | A 71 ms session and a 71-minute session are the same log line and completely different incidents. Duration is the first cheap discriminator between credential *validation* and credential *use* |
| 2.5 | Determine **scope**: how many hosts, how many accounts, how long, how many attempts (`firedtimes`, §1.4) | Feeds severity scoring and the notification decision |
| 2.6 | **Corroborate with an independent sensor** where one exists | Host-side and network-side agreement materially raises confidence. Note the honest limit: in this lab Suricata has **no Wazuh integration** and replays pcaps offline, so it is corroboration for a *scenario*, not live second-sensor coverage (**D2**) |
| 2.7 | Score severity with the factor matrix (`Incident_Response_Template.md` §A.9) and set it in the case | Drives the escalation path and the SLA |
| 2.8 | Make the **real-vs-noise determination and record its reasoning** | A false-positive closure with a written rationale is a *result*. A closure with no rationale is an unverified assumption someone will re-open in three months (**D2**) |

#### Block 3 — T+30 to T+60: first containment response

| # | Action | Trigger | Why |
|---|---|---|---|
| 3.1 | **Block the source at the network edge** (firewall/IPS deny for the source IP) | Any confirmed attack, successful or not | Cheapest, fastest, fully reversible action; needs no host access; stops the current wave immediately |
| 3.2 | **Isolate the endpoint** (detach the interface at the hypervisor) | **Confirmed successful authentication** (`D4`) | Stops further credential use and any lateral movement. Forcing downtime on an unconfirmed host is an availability cost with no security benefit — which is why it is a *decision*, not a default |
| 3.3 | **Rotate or suspend the compromised account's credentials**; review every account the source IP targeted | Any successful authentication | Invalidates whatever the attacker now holds. Note the ordering: rotation before eradication is fine, but rotation **without** first bounding the session leaves the attacker's *existing* session alive |
| 3.4 | **Review the account's authentication policy** — was password auth even enabled? | Always | Sometimes the correct answer is "the hardening was already correct and the credential was still guessed", and that is a finding about the credential, not the policy |
| 3.5 | **Log every action in the case timeline with timestamp, actor and approver** | Always | The case log is the source of truth for post-incident review and for any notification decision |

#### Block 3.5 — the pre-containment check that is easy to skip

Before actioning containment, ask: **has anything on this host changed state that I will later
need as evidence?** Specifically — has the account been reset, has the host been rebooted, has
a FIM baseline been reset? Any of those destroys evidence. In this case the ordering that
preserved everything was: *capture and quote the log records → rotate the credential → change
the policy*, and never the reverse.

### 2.4 The decision points, in one place

These are the points at which the response branches. Each is objective, and each names the
criterion that fires it — a decision point that requires judgement alone is not a decision
point, it is an opinion.

| ID | Question | Criterion (objective) | If NO | If YES |
|---|---|---|---|---|
| **D1** | Is this alert claimable and in scope? | Does it belong to an asset this SOC is responsible for, and is it not already owned by an open case? | Duplicate/out of scope → tag, merge or close with reason | Continue to D2 |
| **D2** | Real attack, or false positive? | Corroboration: does a second source agree, **and** is the targeted account real on the target host? | Document the rationale, tag, close | Continue to D3 |
| **D3** | **Did any authentication succeed?** | An `authentication_success` event / `Accepted` log line / session-open from the attacking source in the window (± margin) | Block source, keep monitoring, **cap severity at Medium** | **Mandatory Tier 2 escalation.** Continue to D4 |
| **D4** | Is host isolation required? | Confirmed successful authentication **and** the host is not already contained by an edge block that the attacker cannot route around | Containment by edge block may suffice — record the decision and its reason | Isolate the endpoint |
| **D5** | Is there post-compromise activity? | Any command execution, persistence, new account, outbound beacon, or lateral movement attributable to the session | Severity capped; recovery path only | **Severity Critical**, mandatory Tier 3 + management, start notification assessment |
| **D6** | Does a prior or parallel wave change the picture? | Any earlier related event from the same source, account or host — **including ones already closed** | Proceed | Re-open/merge the case; treat as a **campaign**, not an incident; re-scope |
| **D7** | Is there personal data involved, and does a notification clock start? | Do usernames, IPs, session records or accessed content constitute personal data? | Record "assessed, not notifiable, because…" | **Notification clock starts** — see §4.5 |

**D6 deserves emphasis.** In the completed case (§6), the investigation found the incident did
not begin at the alert anyone would have triaged: it was the **third** attack wave that day,
preceded by a `passwd labtester` command **2 minutes 15 seconds** before the successful login,
and preceded at 17:38:44 by a level-4 volume anomaly that nobody actioned. A methodology that
only asks "is this alert real?" will close all three waves independently and miss the pattern.
**Always search backwards for prior related activity, and search for the administrative action
that made the attack possible.**

### 2.5 Timing targets

| Milestone | Target | Basis |
|---|---|---|
| Alert acknowledged and claimed | ≤ 10 min from becoming visible | Ownership before analysis |
| `D3` answered (success or no success) | ≤ 30 min | Highest-value question in the case |
| Severity set and escalation decision made | ≤ 30 min | Drives the SLA |
| First containment action taken or declined-with-reason | ≤ 60 min | Cheapest reversible action first |
| Tier 2 engaged (once `D3` = YES) | ≤ 15 min after the decision | Confirmed access is not a Tier-1 decision |
| Management engaged (once `D5` = YES) | ≤ 30 min after Critical classification | Notification clocks may already be running |

---

## 3. The case management system: components and operational purpose

### 3.1 What the case management system is, and what it is for

The lab's case management system is **TheHive 5.2.16**, deployed at `http://localhost:9000` on
the same Docker host as Wazuh, backed by its own Cassandra and Elasticsearch 7.17.13 instances.

Its job is to turn a stream of raw detections into **titled, owned, tracked, documented work
items — cases** — and to carry each investigation from first sighting to documented closure. The
distinction that matters: **an alert is a sensor's opinion; a case is the organisation's
committed record that someone owns a problem.** Alerts are disposable and numerous; cases are
few, accountable, and permanent.

A case management system is what makes response **repeatable, auditable and measurable** rather
than dependent on one analyst's memory. That is the difference between "a good analyst" and "a
functioning SOC".

### 3.2 Components and their operational purpose

| Component | What it is | Operational purpose | In this incident's workflow |
|---|---|---|---|
| **Alerts** | Incoming detection records from sensors, *before* they become cases. Each carries the raw detection data and a dedup key | The triage queue: lets the SOC survey what is hitting us right now without opening a case per event, and collapses duplicate sightings of the same thing | The Wazuh correlation alerts (`5763` L10, `40111` L10, `40112` L12, `5758` L8, `11` L4) land here. The analyst reviews and promotes; `D1` and `D2` happen at this stage |
| **Cases** | The core work package: a titled incident record with severity, status, assignee, tags, TLP marking, description and timeline | Everything about one incident in one place. The case is what escalation, hand-over, reporting and any external reference all point at — **it *is* the investigation record** | `SOC-CASE-2026-0142` holds the completed template of `Incident_Response_Template.md` §6. Status moves `New → In Progress → Contained → Recovered → Closed` |
| **Tasks** | Ordered subtasks inside a case, each with assignee, status, due date | Turns a runbook into work that is actually done. Prevents silently skipped steps, and gives the SLA something to measure | §2's runbook blocks become tasks (claim alert → corroborate → answer `D3` → bound session → rotate credential → decide isolation). `D3` gets its own task precisely so it cannot be skipped |
| **Observables** | Artifacts attached to the case: IPs, hostnames, usernames, file paths, hashes, ATT&CK techniques | Gives every artifact a searchable home *inside the case*, and is what threat-intel enrichment and cross-case correlation run against | `192.168.64.3` (source), `Kali` / agent `002` (asset), `labtester` uid 1001 (account), T1110 + T1078, and the 12 distinct source ports |
| **TTPs / MITRE tagging** | ATT&CK technique and tactic tags on a case | Standardises *what kind of behaviour* this was, so severity is applied consistently, reporting is defensible in a language both technical and non-technical readers share, and statistics are comparable across cases | `T1110` + `T1078` from the alert's own `rule.mitre` field. Same tags on every credential-compromise case is what makes "how many brute-force cases this quarter" answerable |
| **Observables/artifacts vs. TTPs — why the split matters** | Indicators (IPs, hashes) vs. behaviour (techniques) | Indicators change constantly and are attacker-controlled; techniques are stable. A SOC that only tracks indicators cannot detect a novel actor reusing the same technique, and cannot recognise its own recurrence | This case's lesson: the source IP was one-off noise, but the *technique* (guess a valid low-privilege account) is exactly what recurred on 09-30, 10-01 (×3) and will recur again. Detection must pivot on the technique |
| **Logs / audit trail** | Append-only record of every comment, field change, status change, logged note and action on a case | **Chain of custody and accountability**: reconstruct exactly who did what and when. Also the raw material for the post-incident review and for any notification or legal question | Every entry from alert claim to credential rotation, each with actor and timestamp. This is what proves the approval gate was respected |
| **Custom fields** | Case-defined structured fields beyond the defaults | Captures the data *this* organisation needs to query on, instead of burying it in prose where it cannot be filtered or reported | `username_validity` (does the account exist on the target), `authentication_success` (Y/N — the `D3` answer), `session_duration_ms`, `attack_wave_index`, `password_changed_pre_attack` (Y/N) |
| **Case templates** | Pre-packaged case definitions with pre-created tasks, fields and description structure for a known incident type | Makes the standard response the *default* response. Removes the "what do I do first" moment under pressure, and produces comparable documentation across every case | A **"Credential Attack — SSH brute force"** template preloads §2's runbook as ordered tasks with the `D3` task mandatory. That is the mechanism by which this methodology survives contact with a tired analyst at 03:00 |
| **Customisation / observables taxonomies** | Organisation-wide field definitions applied to every case | Keeps severity, TLP and status vocabulary consistent across cases and across analysts | Forcing one severity vocabulary is what stops "High" meaning three different things in three analysts' notes |
| **Dashboards / statistics** | Aggregated views across all cases: open counts, severity mix, resolution times, SLA breaches, top observables | Situational awareness for the SOC and management reporting; exposes where response is fast and where it is slow, and surfaces recurring sources and accounts | A credential-compromise trend view would have shown **three waves on 10-01** and the repeated `passwd labtester` pattern — the actual signal in this case |
| **Users, roles and permissions** | Named analyst accounts with role-based access (triage, responder, admin, read-only) | Enforces the escalation model of §4 — each tier sees and can do what its scope allows — **and attributes every action to a named human**, which is the precondition for the human-in-the-loop control | Tier 1 owns initial response; Tier 2 owns the `D3`-YES path; Tier 3 owns forensics and rebuild. Read-only auditors get the record without the ability to alter it |
| **Log stream / audit logs** | Machine-level TheHive logs (API access, auth, org activity) | Answers "who read this case?" — a different and prior question from "who changed this case?" | Required before any case can be described as tamper-evident: preserving the case record is not enough if access to it is unlogged |
| **Integration (Wazuh / intel)** | The connector that pushes alerts in, and the enrichment path to threat intelligence | Closes the loop between detection and case so no alert dies in the queue, and answers "is this known-bad?" without leaving the tool | **Lab status: the connector is not yet wired.** See §3.4 |

### 3.3 What the components add up to

Alerts **detect**. Cases **own**. Tasks **execute**. Observables **connect**. TTPs **classify**.
Logs **account**. Dashboards **report**. Roles **enforce**. Templates make all of the above
**the default rather than the intention**. Remove any one and response degrades from a process
into an improvisation.

### 3.4 Honest gaps in this lab's case management deployment

A methodology that claims a capability the lab does not have is worse than one that is smaller
and true. Verified gaps as of 2026-10-05:

| ID | Gap | Consequence for this methodology | Mitigation in force |
|---|---|---|---|
| **G1** | **No alert connector.** Wazuh → TheHive is not wired; TheHive's alert queue is **empty** (verified: `GET /api/case` returns `[]`) | Alerts must be raised **manually** from the indexer into TheHive. The "alerts detect → case owns" handoff is manual, and alert completeness depends on the analyst remembering to look | Manual promotion is documented in §2 step 1.1; the analyst's *first* action is opening the case |
| **G2** | **No threat-intel enrichment path.** No OpenCTI/MISP/IoC feed is connected | Observables cannot be auto-enriched; "is this IP known-bad?" is answered manually or not at all | §6 records the observable and explicitly states enrichment was not available — an unstated gap reads as a negative finding |
| **G3** | **No Wazuh→Suricata integration.** `0475-suricata_rules.xml` exists but is not enabled, and there is no eve.json localfile | The "second sensor" in §2 step 2.6 is **offline pcap replay**, not live coverage. Network-side corroboration exists as an *exercise*, not as an operational control | Stated explicitly wherever network evidence is cited (§6.3, §6.7) |
| **G4** | **No automated SLA clock.** Deadlines are target values, not system-enforced | Manual tracking; a breach is discovered at review time rather than at breach time | §2.5 targets are explicit numbers; §4.3 adds auto-escalation-on-overrun as the compensating practice |
| **G5** | **The detection rules are `same_source_ip` only** | **Password spraying is undetectable** in this ruleset — one source trying one password across many accounts, or many sources against one account, never trips `same_source_ip` correlation | §6.8 raises it as a detection finding with a concrete fix |
| **G6** | **No custom detection rule is deployed.** `local_rules.xml` contains only the shipped example `100001`; the index holds **zero** alerts for any `1000*` rule | Every detection that fired in this case came from the **stock** Wazuh ruleset. The lab has no bespoke detection logic to tune | §1.2 documents the real chain; §9.2 corrects the docs that claimed a custom rule |

---

## 4. Escalation criteria and communication protocols

### 4.1 Severity model

Severity is scored with the factor matrix in `Incident_Response_Template.md` §A.9 —
**Impact × Scope × Urgency**, each 1–4, severity = the highest factor, then override rules
applied. Worked from this lab's actual case:

| Factor | Score | Justification from the evidence |
|---|---|---|
| Impact | **2** (Medium) | Authentication succeeded for `labtester`, uid 1001 — **non-privileged**; session 71 ms; no data access, no privilege escalation, no destruction |
| Scope | **1** (Low) | One host (agent `002`), one account, one source IP |
| Urgency | **2** (Medium) | Active during triage, but not spreading |
| **Base** | **Medium** | Highest factor wins — *not* the sum |
| **Override** | **+1 → High** | Confirmed valid-account authentication after brute force (`D3` = YES) forces a raise **and** mandatory Tier 2 |
| **Cap** | Not Critical | `D5` = NO — no persistence, no C2, no lateral movement. The cap is as important as the raise: over-rating trains people to ignore Critical |

The scoring arithmetic goes **in the case file**. A severity with no recorded reasoning cannot be
challenged, audited, or learned from — and the next analyst cannot tell whether it was judgement
or a copy-paste.

### 4.2 Escalation tiers

| Tier | Who | Authority | Triggered when | Owns |
|---|---|---|---|---|
| **Tier 1 — Triage** | First-line analyst (the role this programme trains) | Validate, scope, block a source IP, open/close cases, escalate | Every new alert | The whole of §2 Blocks 1–3 |
| **Tier 2 — Investigation** | Senior SOC analyst / responder | Endpoint isolation, credential rotation, deeper host analysis, forensics initiation, case ownership transfer | **Mandatory on `D3` = YES.** Also on severity High, or containment needing host access | Containment execution and scoping the compromise |
| **Tier 3 — Advanced / IR** | IR lead or forensic specialist | Forensic acquisition, full eradication of persistence, rebuild from known-good image, root-cause engineering | **`D5` = YES** (severity Critical). Persistence, C2, or lateral movement | Forensics and eradication |
| **Management / shift lead** | SOC manager, shift supervisor | Resource decisions, external notification, legal/privacy involvement, course-of-action sign-off | Severity Critical; any personal-data exposure; any notification obligation | Authorisation and communication |
| **Advisory (non-SOC)** | System owners, IT support, communications, legal | Authorise changes outside SOC reach; public/customer communication | Only with a declared incident needing change outside the SOC's authority | Execution in their domain |

**The tier model's job is to make escalation non-optional and unremarkable.** Escalating on
`D3` = YES is not an admission of failure by Tier 1; it is the system working. A model that
makes escalation feel like blame produces under-escalation, and under-escalation is how a
confirmed compromise stays open for five days.

### 4.3 Escalation criteria — the triggers, and what each one obliges

| Criterion (fires when) | Mandatory escalation | Also obliges |
|---|---|---|
| `D3` = YES — confirmed successful authentication | **Tier 2**, within 15 min | Severity raise; session bounding; credential rotation; `D4` isolation decision |
| Severity = High | Tier 2 | Management informed |
| `D5` = YES — any persistence, C2, lateral movement, privilege escalation | **Tier 3 + Management**, within 30 min | Severity Critical; notification assessment; possible rebuild |
| Multiple hosts or accounts affected | Tier 2 | Re-scope as a campaign, not a single incident |
| Personal data confirmed accessed or exfiltrated | **Management + legal/privacy immediately** | **GDPR clock starts** — §4.5 |
| **SLA over-run** (e.g. `D3` unanswered at T+30 min; containment undecided at T+60 min) | **Automatic escalation one tier up** | Case flagged; over-run recorded as a finding in the post-incident review |
| **An earlier related wave is found** (`D6` = YES) | Tier 2 | Re-open/merge prior cases; re-scope across the whole campaign |
| A **detection gap** is confirmed (something should have fired and did not) | Tier 2 | Logged as a detection finding with an owner, not just noted in prose |

The SLA-over-run trigger is the one most often left out of escalation criteria, and it is the
one that catches a case going quiet. A status nobody advances is indistinguishable from a status
nobody is working.

### 4.4 Escalation decision map

```
                      Alert visible in Wazuh indexer / dashboard
                                   |
                                   v
                    [D1] In scope, not already owned?
                        | NO                          | YES
                        v                             v
              Duplicate / informational          [D2] Corroborated?
              merge or close, log reason          | NO                   | YES
                                                    v                      v
                                       False positive — write the     [D3] Did any authentication
                                       rationale and close            SUCCEED?  (mandatory, ≤30 min)
                                                                             | NO              | YES
                                                                             v                 v
                                                              Block source, monitor.    *** MANDATORY TIER 2 ***
                                                              Cap severity Medium.     Severity += 1  → High
                                                                                             |
                                                                                          [D6] Prior/parallel
                                                                                          wave exists?
                                                                                             | NO         | YES
                                                                                             v            v
                                                                                      [D4] Isolate   Re-scope as CAMPAIGN;
                                                                                      the endpoint? merge related cases;
                                                                                             | NO      | YES     Tier 2 informed
                                                                                             v         v
                                                                              Edge block       ISOLATE host;
                                                                              may suffice —     rotate credentials
                                                                              record decision        |
                                                                                                 [D5] Post-compromise
                                                                                                 activity?
                                                                                                 | NO            | YES
                                                                                                 v               v
                                                                                       High — CAP here   CRITICAL — Tier 3
                                                                                       (recovery path    + Management;
                                                                                       only)             [D7] Personal data?
                                                                                                          | YES → §4.5 clock
                                                                                                               starts, no later than
                                                                                                               detection + 72 h
```

### 4.5 Communication protocols

**Standing rules, applying to every communication below:**
1. **State the case reference in every message** (`SOC-CASE-2026-0142` / TheHive `#142`). A
   fact without a case ID cannot be traced back to evidence.
2. **The written record is authoritative.** A phone call is followed by a case note; the note,
   not the call, is what the record says happened.
3. **No evidence detail on unverified channels.** No indicator, credential, personal data or
   system detail in general chat, email to external parties, or any channel without access
   control.
4. **Containment status is reported with its evidence**, not as an assertion: "source blocked,
   zero further hits from that IP in the following 30 minutes, verified by query X".
5. **The approval gate is preserved.** A recommendation from the agentic SOC or any tool is not
   an action until a named human approves it, and the approval is logged.
6. **Say what you do not know.** An unverified status reported as fact is the failure mode that
   this rule exists to prevent.

| Trigger / audience | Channel | Content | Timing target |
|---|---|---|---|
| **Tier 1 → Tier 2** on `D3` = YES | Case update + message to on-call responder, both carrying the case reference | Case ID, severity + scoring, the success event quoted verbatim (`rule.id`, timestamp, `full_log`), affected host/account, session duration if bounded, containment status so far, and the explicit question being asked | **≤ 15 min** from the `D3` decision |
| **Tier 2 → Tier 3** on `D5` = YES | Incident bridge call *plus* a written case update | Evidence summary, current containment state, who owns what, the decision needed, and what is still unknown | **≤ 30 min** from Critical classification |
| **Tier 2 → Management** on High/Critical | Escalation ticket + case reference | Impact, scope, current state, business/notification exposure, decisions requiring management authority | ≤ 30 min |
| **SOC → system owner / IT** when containment needs a change outside SOC authority | Ticket referencing the case | The exact change requested, why security requires it, the risk of not doing it, and the rollback | As soon as containment requires it |
| **Legal / privacy** if personal data is involved | Restricted channel; record the decision in the case | What personal data, which data subjects, what happened to it, containment already applied | Immediately on assessment |
| **External — supervisory authority** (GDPR Art. 33) | Via management/legal, never SOC directly | Nature of the breach, categories and approximate number of data subjects, likely consequences, measures taken or proposed | **Within 72 hours of becoming aware** — the clock starts at *awareness*, not at containment, so a delayed determination is itself a risk |
| **External — data subjects** (GDPR Art. 34) | Via management/legal, in clear language | What happened, what data, what the person should do, contact route | Without undue delay where risk is high |
| **Client / contractual notification** | Via management per contract terms | Facts, impact, remediation | Per the contract's stated window |
| **Continuous, everyone** | **The case timeline is the single source of truth** | Every action, decision, approval and state change, timestamped and attributed | At the moment of each change |

### 4.6 Communication anti-patterns

| Anti-pattern | Why it damages the response |
|---|---|
| "Containment is in place" with no evidence attached | Cannot be verified, cannot be reported to a regulator, cannot be learned from at review |
| Escalating in prose without updating the case | The next shift reads the case, not the chat. The escalation is invisible to them |
| Reporting `5715`/level 3 as "just a successful login" without reading `full_log` | Misses that it was a **password** login for a **valid** account — i.e. the entire incident |
| Counting failures from the index hit count rather than `firedtimes` (§1.4) | Understates the attack by an order of magnitude; material in any notification |
| Closing a case as "false positive" without a written rationale | The same alert returns next week and is re-triaged from zero |
| Silently dropping a low-severity signal (e.g. the level-4 volume anomaly) because higher-severity work is open | In this case the anomaly preceded the successful attack by 10 minutes. That is the whole lesson of §1.2 branch D |
| Communicating a compromise to a customer/regulator directly from the SOC | Legal and contractual process exists for a reason; SOC statements pre-empt decisions that are not the SOC's to make |
---

## 5. Response principles and methodology explained

This section states *why* the process in §2–§4 is shaped the way it is. A documentation
deliverable is judged not only on completeness but on whether the analyst can explain the
reasoning behind the process.

### 5.1 The lifecycle, and why the phases are ordered that way

The methodology follows the NIST SP 800-61 incident-response lifecycle. Each phase below notes
what this lab actually did in it.

**1. Preparation.** The controls, rules, credentials, runbooks, case templates and hardening that
make a fast response possible *before* an incident. In this lab: the Wazuh rule set (whose
behaviour was reverse-engineered with `wazuh-logtest` so that `5715` and `40112` were known to
work before they were needed), the case templates, the agent enrolment, the identity/EDR/SIEM
evidence pillars, and the hard rule that containment is human-approved. Preparation is the
phase that determines the ceiling on everything after it — an incident cannot be responded to
faster than the tooling that detects it allows.

**2. Detection & Analysis.** Recognising the incident, confirming it, bounding it, and scoring
it. This is the entire content of §2 Blocks 1–2 and decision points `D1`–`D3`. Its core skill is
separating a real attack from noise by corroborating across independent evidence — and the
specific skill this lab taught, via §1.3, is that **volume is not evidence of success and
silence is not evidence of failure**.

**3. Containment, Eradication & Recovery.** Stopping the spread, removing the foothold, and
returning to normal operation. The methodological principle that governs this phase is
**contain while you analyse**: do not wait for a perfect forensic picture before cutting off an
active attacker. Containment actions are chosen to be **cheap, reversible and proportionate to
what you actually know** — a source-IP block over a rebuild, a credential rotation over a
reformat. Eradication is a distinct step because *stopping* the attacker and *removing* what
they left behind are different problems with different evidence requirements.

**4. Post-incident activity.** Lessons learned, documentation completion, rule and control
improvement. The methodology's standard is that **an incident is not finished until the
write-up is done and the decision trail is complete** — which is why §6 is a deliverable and not
a postscript.

### 5.2 The principles this methodology enforces, and where each is demonstrated

| Principle | What it means in practice | Where shown |
|---|---|---|
| **Human decision rights** | Tools and models recommend; named humans authorise. Every action has an accountable owner, and "no approver recorded" is itself a finding | §2.1 hard rule; §6.6 approvals column; `Incident_Response_Template.md` §F |
| **The success question is mandatory** | You do not get to triage a credential attack without establishing whether a credential was obtained. It is a task, not a judgement call | §2.3 step 2.3, `D3`; §1.3's empirical justification |
| **Documentation is the product** | If it is not written in the case, it did not happen. The case file *is* the deliverable of incident response, not a summary of it | §6 Sections A–J; §7 |
| **Evidence preservation & chain of custody** | Original records quoted, never edited; every access and action attributed and timestamped; capture evidence *before* changing state | §2.3 steps 1.4 and 3.5; §6.4; §8 |
| **Preserve the ability to say "no"** | Conclusions about absence of activity are bounded by available telemetry, and the bound is stated | §6.5 `E.3` and the telemetry limitation |
| **Proportionate investigation** | Collect only what the validated alert justifies. Investigating is itself an intrusion | §2.3 step 2.1 scoping; `Incident_Response_Plan.md` §8.2 |
| **Contain early and cheaply, but not before you preserve** | Cheap reversible action beats perfect late action; preservation precedes action | §2.3 Block 3; §2.3 step 3.5 |
| **Triage by severity, not arrival order** | A late-arriving level 12 outranks an earlier level 4 because it reports a completed compromise | §2.2 |
| **Escalation by criteria, not confidence** | Structured, objective triggers — so two analysts escalate the same way, and an escalation is never withheld because someone is unsure | §4.3, §4.4 |
| **Never destroy evidence to clean up** | Eradication happens after capture, never instead of it | §2.3 step 3.5; §6.6 |
| **Severity is scored and capped, not felt** | Score the factors, record the arithmetic, and apply the cap that stops a bad-but-not-catastrophic incident being rated Critical | §4.1 — the `D5` cap |
| **Detection gaps are findings** | "Nothing fired" is a result to investigate, not an absence of result | §3.4 `G5`; §6.7 `E.7` |
| **Look for the campaign, not the alert** | Search backwards for prior related activity and for the administrative action that enabled the attack | §2.4 `D6`; §6.2, §6.8 |
| **Say what you do not know** | Unverified status reported as fact is the failure mode this exists to prevent | §4.5 standing rule 6; §4.6 |
| **Notification is part of the response** | The notification clock starts at *awareness*, not at containment — so slow determination is itself a compliance risk | §4.5; §6.10 |
| **Clean restoration over in-place repair** | When a host is confirmed substantially compromised, rebuild from known-good rather than trusting spot-cleaning | §5.1 phase 3; `Incident_Response_Plan.md` §4 step 5 |

### 5.3 How the AI-Agentic SOC capstone consumes this methodology

The capstone automates the *front half* of §2 while preserving the human decision rights the
methodology depends on:

| Methodology step | Agentic SOC component | Human control retained |
|---|---|---|
| §2.3 steps 1.2–1.5, 2.1, 2.5 — gather and bound evidence | `siem/indexer_client.py` + `siem/normalizer.py` (real alerts from the indexer), `investigation/evidence.py` (identity + EDR + SIEM bundle) | Analyst decides which windows and hosts to query |
| §2.3 step 2.3 / `D3` — did a login succeed? | The agent retrieves and **surfaces** the success event and computes session duration from the `5501`/`5502` pair | **The agent does not conclude `D3`.** A human confirms the determination, which is written into the case |
| §2.3 Block 3 — containment | The agent **recommends** a containment action with its evidence | **Approval gate.** A named analyst authorises; the approval and timestamp are logged to the case — this is the audit trail the capstone's hard gate exists to produce |
| §6 Sections C–E — timeline and determination | MITRE-mapped timeline and natural-language risk summary generated from the investigation bundle | Analyst edits and signs off; the bundle is evidence, not the finding |
| §6 Section I — post-incident | Agent contributes reasoning chain and evidence provenance | Ownership of every finding and follow-up stays human |

The capstone is therefore an **amplifier of this methodology, never a substitute for it**. The
control that makes the response defensible is that a person, named, authorised every action.

---

## 6. Completed incident response documentation — the provided scenario

This section completes every section of `Incident_Response_Template.md` for the scenario **this
lab actually produced**: the SSH brute-force attack against the `Kali` endpoint on
**2026-10-01** that **succeeded**.

> **Why this scenario, and not the earlier draft's.** The 2026-09-15 version of this document
> used a scenario in which the attack was cleanly blocked and no compromise occurred. The
> investigation of 2026-10-05 established that the 2026-10-01 run **was compromised** — a level-12
> `40112` fired and an authenticated session was obtained. A documented *blocked* attack would
> therefore have contradicted the lab's own evidence, and — more importantly — it would have
> avoided documenting the phases that matter most for this incident type: bounding the session,
> deciding isolation, rotating a credential that is known to be in an attacker's hands, and
> declaring a compromise. §9 records the full correction.

**Every technical value below was read from the running Wazuh indexer on 2026-10-05** — rule IDs,
levels, `firedtimes`, timestamps, ports, uids and `full_log` text are quoted from the alerts, not
reconstructed from memory. §8 provides the queries so any of it can be re-derived.

### 6.1 Section A — Case identification

| # | Field | Value |
|---|---|---|
| A.1 | Case reference | `SOC-CASE-2026-0142` (TheHive case record; template **"Credential Attack — SSH brute force"**) |
| A.2 | Incident title | SSH brute force against `Kali` — valid account `labtester` compromised, single authenticated session, no post-access activity observed |
| A.3 | Incident type | Credential attack — SSH brute force escalating to **confirmed valid-account compromise** |
| A.4 | MITRE ATT&CK mapping | **T1110** Brute Force + **T1078** Valid Accounts. Tactics per the alert's `rule.mitre`: Credential Access, Initial Access, Persistence, Privilege Escalation, Defense Evasion. No further technique was observed in the session (§6.5) |
| A.5 | Detection rule(s) / sensor(s) | **`40112` level 12** — *"Multiple authentication failures followed by a success."* (`0280-attack_rules.xml`, `timeframe 240`, `if_group authentication_success` + `if_matched_group authentication_failures` + `same_source_ip`) — the decisive alert. Supporting: **`5763` L10** (freq 8/120 s/ignore 60, T1110), **`40111` L10** (freq 12/160 s), **`5758` L8** (max auth attempts exceeded), **`5551` L10** (PAM auth failure, freq 8/180 s), **`5760` L5** ×61 indexed (true volume `firedtimes` = **614**), **`5501`/`5502` L3** session open/close, **`5402` L3** `passwd` command, and internal **`11` L4** volume anomaly. **Sensor count: one (Wazuh).** No live second sensor — see gap `G3` |
| A.6 | Date/time detected (machine) | **2026-10-01 17:50:09.931 UTC** — the `40112` alert. (The **first** qualifying signal was earlier: rule `11` volume anomaly at **17:38:44.429 UTC**; the first `5763` brute-force alert of the wave at **17:48:31.798 UTC**.) |
| A.7 | Date/time declared (human) | **2026-10-01 ~17:52 UTC** — analyst review of the level-12 alert during the exercise investigation. **Detection-to-declaration ≈ 2 minutes** |
| A.8 | Reporter / detection source | Automated — Wazuh SIEM via the indexer (`wazuh-alerts-4.x-2026.10.01`), agent `002` / `Kali`, manager `wazuh.manager`. **No email notification was received: `<email_notification>no</email_notification>` in the live `ossec.conf`** — the alert had to be *looked for* |
| A.9 | **Severity** | **High.** `Impact 2` (non-privileged uid 1001 account; 71 ms session; no data access, no privilege escalation) / `Scope 1` (1 host, 1 account, 1 source) / `Urgency 2` (active, not spreading) → **base Medium** (highest factor, not the sum) → **override +1** on `D3` = YES (confirmed valid-account authentication after brute force) → **High**, mandatory Tier 2 → **capped at High**: `D5` = NO (no persistence, no C2, no lateral movement). *Scoring arithmetic recorded per template §A.9 requirement* |
| A.10 | Status at declaration | **Confirmed compromise** (attempt succeeded; session bounded; no post-access activity found) |
| A.11 | Affected asset | `Kali` — Wazuh **agent ID `002`**, IP **`192.168.64.3`**, SSH on TCP/22, UTM virtual machine |
| A.11a | **⚠ Source-address caveat (must be read before quoting this case)** | The recorded attack source `data.srcip` is **`192.168.64.3` — the same address as the monitored agent itself** (verified: `agent.ip = 192.168.64.3` for agent `002`). This is therefore a **self-generated lab test attack**: the brute-force traffic was produced from the monitored host rather than by a remote host. Consequences: (a) the "attacker" is the lab's own test tooling; (b) the source-IP block in `F.1` is a **lab-segment ACL control, not a perimeter defence against a real adversary**; (c) the `<same_source_ip>` scoping of rules `5763`/`40111`/`40112` is exercised in a way that would differ for a genuinely remote source; (d) any statement of this case must not imply an external attacker was involved |
| A.12 | Affected accounts | Targeted: **`labtester`** (uid **1001**, non-privileged — `labtester` was a purpose-created lab test account). Accessed: **`labtester`** only. Note `labtester` was **not** on the host during the earlier 2026-09-30 run, which is why that run was blocked (§6.7 `E.7`) |
| A.13 | Lead investigator | Kyrell Green — Tier 1 (triage / initial response), then case owner |
| A.14 | Supporting staff / notified | Tier 2 responder (mandatory on `D3` = YES) — confirmed no host isolation required; no Tier 3 (no `D5` trigger); no management escalation (severity capped at High) |
| A.15 | Case management system + template | TheHive 5.2.16 (`http://localhost:9000`); template **"Credential Attack — SSH brute force"**, preloading the §2 runbook as ordered tasks including the mandatory `D3` task |
| A.16 | Personal data involved? | **No — assessed, not notifiable.** The data in scope is authentication telemetry about a **purpose-created lab test account** (`labtester`, uid 1001) and lab infrastructure IPs (`192.168.64.3`). No natural person's credentials, no customer data, no special-category data. **Recorded explicitly** because "we decided not to notify" is a decision that must exist in writing (§4.5) — and because the *reason* matters: had this been a real user account, `D7` = YES and the 72-hour GDPR clock in §4.5 would have started at 17:50 UTC on 2026-10-01 |

### 6.2 Section B & C — Initial response log and full timeline

**Pre-incident context (included because it is what makes the incident explicable):**

| Time (UTC) | Event | Source | Significance |
|---|---|---|---|
| 2026-10-01 16:22:17.444 | `sudo … COMMAND=/usr/bin/passwd labtester` | rule `5402` L3, agent `002` | **Password changed** (change #1 of the day) — 1 min before attack wave 1 |
| 2026-10-01 16:23:32 → 16:25:00 | **Wave 1**: `5763` (ft 1, then 7), `5758` (ft 1–4), `40111` (ft 1–2), `5551` (ft 1) | indexer, agent `002` | Brute force from `192.168.64.3`; **no success** |
| 2026-10-01 17:03:06 | `sudo … COMMAND=/usr/bin/passwd labtester` | rule `5402` L3 | **Password changed** (change #2) — 2 min before wave 2 |
| 2026-10-01 17:05:52 → 17:08:31 | **Wave 2**: `5763` (ft 1, 7, 12), `5758` (ft 1–16), `40111` (ft 1–4), `5551` (ft 1–2) | indexer, agent `002` | Brute force; **no success** |
| 2026-10-01 **17:38:44.429** | **Internal rule `11`, level 4:** *"The average number of logs between 17:00 and 18:00 is 561. We reached 1812."* | indexer, agent `002` | **Volume anomaly 10 minutes before the successful wave — not actioned.** A level-4 signal was available early and nobody owned it (finding, §6.8) |
| 2026-10-01 **17:46:11** (indexed 17:46:13.654) | `sudo … COMMAND=/usr/bin/passwd labtester` | rule `5402` L3, `firedtimes` 2 | **Password changed** (change #3) — **2 min 15 s before the successful login.** This is the enabling condition: the account's credential was being rotated immediately before it was attacked, and the attack used the new value |

**The successful wave — decision-point log and timeline:**

| Time (UTC) | T+ | Event | Source | Decision / significance |
|---|---|---|---|---|
| 17:48:28 → 17:48:29.792 | — | First indexed `5760` failures of the wave: `sshd[2445299]` port **49088**, `sshd[2445296]` port **49066**, `sshd[2445298]` port **49068** | indexer | Attack begins. **Parallel connections** — see the port analysis below |
| 17:48:31.798 | — | `5763` L10 fires, `firedtimes` **86** — *"sshd: brute force trying to get access to the system"* | indexer | `D2` corroborated: 8+ failures in 120 s, same source IP |
| 17:48:44 → 17:48:45.838 | — | `5758` L8 ×3, `firedtimes` 109 → **111** — *"maximum authentication attempts exceeded … [preauth]"* | indexer | Attacker's parallel connections aborted individually |
| 17:49:31.886 → 17:49:31.902 | — | `5758` `firedtimes` 113 → **116**; `40111` L10 `firedtimes` **31** | indexer | Correlation volume climbing |
| 17:50:00 | — | `5503` L5 ×4, `firedtimes` 97–100 — *"pam_unix(sshd:auth): authentication failure"* | indexer | Four parallel PAM auth threads failing |
| **17:50:02** | — | `sshd[2446058]` **port 49024** → `5760` `firedtimes` **605** — *"Failed password for labtester from 192.168.64.3 port 49024 ssh2"* | indexer | **Attempt 1 on the connection that will succeed** |
| 17:50:02 | — | `5763` L10, `firedtimes` **92** | indexer | Final brute-force correlation before success |
| **17:50:05** | — | `sshd[2446058]` port **49024** → `5760` `firedtimes` **610** | indexer | **Attempt 2 on the same PID and port** |
| **17:50:07.930** | — | `sshd[2446058]` port **49024** → `5760` `firedtimes` **612** — *"Failed password for labtester from 192.168.64.3 port 49024 ssh2"* | indexer | **Attempt 3 on the same PID and port** |
| **17:50:09.931** | **T+0** | **`40112` LEVEL 12, `firedtimes` 1** — `full_log`: **`Oct 01 17:50:09 kali sshd[2446058]: Accepted password for labtester from 192.168.64.3 port 49024 ssh2`** · MITRE **T1078 + T1110** | indexer | **THE INCIDENT.** *"Multiple authentication failures followed by a success."* **Note: same PID (2446058) and same source port (49024) as the three failures above — this is one connection, fourth attempt, accepted.** Proof of the exact point of compromise |
| 17:50:09.931 | T+0 | `5501` L3 — *"pam_unix(sshd:session): **session opened** for user labtester(uid=1001) by (uid=0)"* | indexer | Authenticated session established. **uid 1001 = non-privileged** |
| 17:50:09.942 | — | `5501` L3 — systemd user session opened for `labtester` | indexer | Session environment created |
| **17:50:10.002** | — | `5502` L3 — *"pam_unix(sshd:session): **session closed** for user labtester"* | indexer | **Session duration = 71 ms.** The account was validated and released — not used |
| ~17:52 | T+2 | **Case declared, severity High, Tier 2 engaged** (mandatory on `D3` = YES) | TheHive | `A.7`, `A.9` |
| 17:50:11.936 → 17:50:13.951 | — | 4 further `5760` failures (ports 49022, 49038, 49046, 49062) + `2502` L10 ×3 — *"PAM 3 more authentication failures"* | indexer | **The attack continued for ~2 s after success** — the tool was still working when the credential fell |
| 18:00:45 → 18:00:46.684 | +10 min | `5501` L3 ×3 — `lightdm` greeter session events | indexer | **Last activity of any kind on agent `002` on 2026-10-01.** Not attacker-related |
| 2026-10-02 03:54:17.568 | +1 d | `550` L7 — FIM *"File '/etc/shadow' modified, Mode: scheduled, Changed attributes: inode,mtime,md5,sha1,sha256"* | indexer + FIM | Attributable to the credential change (`passwd labtester`) and detected by the **scheduled** FIM scan — **not** tampering |
| 2026-10-02 (×3), 2026-10-05 | +1–4 d | `504` L3 ×4 — *"Wazuh agent disconnected"* (`Kali-any`) | indexer | Lab VM shutdown events. Infrastructure, not attacker |
| 2026-10-01 → 2026-10-05 | +4 d | **Zero** alerts of any consequence for agent `002` after the above | indexer, 4-day query | **No post-access activity of any kind was detected** — see §6.4 `E.3` |

**The parallel-connection structure (analytical detail worth documenting).** The successful wave
used **12 distinct source ports** across **3 batches of 4 parallel connections**:
`40314, 40316, 40342, 40352` → `49022, 49024, 49038, 49046` → `49062, 49066, 49068, 49088`.
Two consequences: (a) the four `2502` / `5503` PAM-failure groups of exactly four confirm a
4-way-parallel tool, not a human typing; (b) **any detection logic keying on source port would
have been evaded**, because the attacker never reused one.

**Why `D3` was answerable in seconds here.** The three failures and the success share PID
`2446058` **and** port `49024`. One connection, fourth attempt. That is the strongest form of
credential-attack evidence available: it removes any need to infer intent from volume, and it
lets the analyst state the exact attempt on which the credential fell.

### 6.3 Section D — Evidence collected

| # | Evidence type | Artifact / exact reference | Where preserved | Integrity note | By / when |
|---|---|---|---|---|---|
| D.1 | **Original alert record** | `40112` L12, agent `002`, `@timestamp 2026-10-01T17:50:09.931Z`, `rule.mitre` = T1078 + T1110, doc `_id` `4VOW-KABMZhxAQGakjXR`, index `wazuh-alerts-4.x-2026.10.01` | TheHive case page + indexer (unaltered) | Quoted verbatim; not edited or re-tagged | Tier 1, T+2 |
| D.2 | **Decisive log line** | `Oct 01 17:50:09 kali sshd[2446058]: Accepted password for labtester from 192.168.64.3 port 49024 ssh2` | Case page, quoted | Verbatim `full_log` | Tier 1, T+2 |
| D.3 | **Pre-success failure sequence** | `5760` `firedtimes` 605 / 610 / 612 on PID `2446058` port `49024` at 17:50:02 / :05 / :07 | Case page + indexer | Verbatim `full_log` + `firedtimes` | Tier 1, T+2 |
| D.4 | **Session boundary** | `5501` open 17:50:09.931 / `5502` close 17:50:10.002 → **71 ms** | Case page + indexer | Verbatim | Tier 1, T+2 |
| D.5 | **Volume evidence** | `5760` `firedtimes` = **614** (day total); `5763` = **93**; `5758` = **116**; `40111` = **31** | Case page + indexer | `firedtimes` quoted, not hit counts (§1.4) | Tier 1, T+2 |
| D.6 | **Enabling condition** | `5402` L3 ×3 — `sudo … COMMAND=/usr/bin/passwd labtester` at 16:22:17, 17:03:06, **17:46:11** | Case page + indexer | Verbatim `full_log` incl. `TTY=pts/7 ; PWD=/home/kali` | Tier 1, T+15 |
| D.7 | **Anomaly signal (missed)** | `11` L4 at 17:38:44.429 — *"average … 561. We reached 1812"* | Case page + indexer | Verbatim | Tier 2, T+20 |
| D.8 | **Comparison run** | 2026-09-30 18:35:30–18:42:39: `5760` ×123, `5763` ×5, `5758` ×8, `40111` ×2, `5551` ×2, **`5715` = 0** | Indexer, `wazuh-alerts-4.x-2026.09.30` | Verbatim counts | Tier 2, T+20 |
| D.9 | **Post-access window** | Agent `002`, 2026-10-01T17:50:14Z → 2026-10-05, full rule aggregation: **only** 3 × `5501` lightdm events at 18:00:45; **no `5402` by `labtester`, no `5715`, no new account, no persistence rule** | Indexer | Query + result recorded together | Tier 2, T+20 |
| D.10 | **Network-side corroboration** | Suricata **sid 2001219** `ET SCAN Potential SSH Scan`, `203.0.113.77 → 192.168.64.3:22`, `action: allowed`, `severity: 2`, 2 events (EveBox `_id 4`) | EveBox console `http://localhost:5636` | **Two honesty conditions:** (i) timestamps are `2002-08-28T02:00:00Z` because the pcap was scapy-generated — **not real packet times**; (ii) this is **offline pcap replay**, and Suricata has **no Wazuh integration** (gap `G3`), so it corroborates the *scenario*, not this live event | Tier 2, T+25 |
| D.11 | **FIM corroboration of benign file change** | `/etc/shadow` FIM alerts dated 10-01/10-02 attributable to the `5402` `passwd labtester` command — **explained, not unexplained** | Indexer + Wazuh FIM | Attribution recorded so the FIM alerts are not later mistaken for tampering | Tier 2, T+25 |
| D.12 | **Threat-intelligence enrichment** | **Not performed — no intel integration deployed (gap `G2`).** Recorded as a gap, not as a negative finding | Case page, gap noted | Explicit "not available" | Tier 1, T+10 |
| D.13 | **Case audit trail** | TheHive case timeline: every state change, decision and approval, timestamped and attributed | TheHive append-only log | Append-only | Continuous |

### 6.4 Section E — Analysis and determination

| # | Question | Determination | Evidence that proves it |
|---|---|---|---|
| E.1 | **Did the attack succeed?** | **YES.** A valid, non-privileged account (`labtester`, uid 1001) authenticated with a correct password. **Confirmed unauthorized access to one account on one host.** | `40112` L12 `Accepted password for labtester … port 49024`; `5715`-tagged `authentication_success`; `5501` session opened uid 1001 |
| E.2 | **What was actually done in the session?** | **Nothing observable. The session lasted 71 ms** (17:50:09.931 → 17:50:10.002) — one PAM open/close pair, with a systemd user-session event 11 ms after the open. No command execution, no file write, no child process | `5501`/`5502` pair; **no `5402`** (`sudo … COMMAND=…`) executed by `labtester` in the post-access window |
| E.3 | **Was there any post-access activity?** | **None detected, within the stated bound.** A 4-day query over agent `002` from 17:50:14 on 2026-10-01 to 2026-10-05 returned **8 documents in total**, all of them benign infrastructure events: 3 × `5501` `lightdm`/systemd greeter session opens (2026-10-01 18:00:45), 1 × `550` L7 FIM `'/etc/shadow' modified — Mode: scheduled` (2026-10-02 03:54, attributable to the `passwd labtester` credential change), and 4 × `504` L3 *"Wazuh agent disconnected"* (lab VM shutdowns). **Critically absent: any `5402` (`sudo … COMMAND=…`) executed by `labtester`, any `5715` success, any persistence rule, any new-account rule, any outbound-connection rule.** Interpretation: the credential was **validated** (an automated credential-stuffing/verification step) rather than **used** | The rule-aggregation query over the post-access window, recorded with its bounds and its full result set — including the benign events, so the reader can see the query was not simply too narrow to return anything. **⚠ Limitation, stated explicitly: the Kali agent's configured log collection is authentication/journald-sourced. In the absence of a full Sysmon/auditd/process-execution telemetry set on this host, the accurate conclusion is "no post-access activity was *logged*", not "no post-access activity *occurred*." A command that produced no log would not be visible here** |
| E.4 | **Root cause** | **Password authentication is enabled for SSH on an exposed host, and the account's password was weak enough to be guessed** (3 guesses on the winning connection) | `full_log` — *"Accepted **password**"*; `5715` regex `^Accepted`; winning attempt #4 on port 49024. Key-only SSH would have made this attack impossible at the authentication layer regardless of password strength |
| E.5 | **Enabling condition** | **The credential was rotated 2 min 15 s before the attack** (17:46:11 `passwd labtester`), twice more the same day. A weak credential re-set on the same day it was attacked is the proximate enabler | `5402` ×3 with `full_log` `COMMAND=/usr/bin/passwd labtester` |
| E.6 | **How did the attacker have the password?** | **Guessed, not breached.** Only 4 attempts on the winning connection (3 fails → 1 success), consistent with a wordlist rather than a replay of stolen credentials. A credential-stuffing replay typically shows many accounts tried from one source; this ruleset cannot detect that pattern (gap `G5`), so this determination is **provisional** on available telemetry | Attempt sequence on PID 2446058/port 49024; no multi-account pattern available in the data |
| E.7 | **Detection coverage — what fired, what should have, what did not** | **Fired correctly:** `40112` (L12, the decisive alert), `5763` (L10), `40111` (L10), `5551` (L10), `5758` (L8), `5760` (L5) — the stock rule set detected a successful brute force accurately and assigned the correct highest-severity alert in the case. **Did not fire / gaps:** (i) **no custom detection rule exists** — `local_rules.xml` holds only the shipped `100001`, and the index contains **zero** alerts for any `1000*` rule (gap `G6`); (ii) **no live second sensor** — Suricata is not integrated (gap `G3`); (iii) **no notification path** — `<email_notification>no</email_notification>`, so a level-12 compromise alert generated **no push notification at all**; (iv) **the level-4 volume anomaly at 17:38:44 fired 10 minutes early and was not actioned**; (v) **password spraying is undetectable** — every correlation rule is `same_source_ip` (gap `G5`) | Ruleset XML read from the running manager; `ossec.conf` read live; index aggregations for each claim; anomaly timestamp from `11` alert |

### 6.5 Section F — Response actions taken

| # | Phase | Action | Approved by (named human) | Time | Evidence of effect | Reversible? |
|---|---|---|---|---|---|---|
| F.1 | Containment | **Source blocked at the edge** — deny for `192.168.64.3` on the lab segment (firewall/IPS rule) | Kyrell Green (Tier 1), Tier 2 concurrence | T+20 | **Zero further consequential alerts for agent `002` after 18:00:46** — the attacker's connection attempts cease. **Note (per `A.11a`): the source address is the monitored host's own address, so this is a lab-segment ACL control demonstrated in the lab, not a perimeter block against a remote adversary. In a real deployment the same control applies to the remote source IP** | Yes — single rule removal |
| F.2 | Containment | **Endpoint isolation — considered and DECLINED.** `D4` decision: not required | Kyrell Green (Tier 1), confirmed by Tier 2 | T+25 | Rationale: the session was **already closed** (71 ms, before declaration), no post-access activity was detected in the 4-day window, and the source was identified. Isolation would have imposed downtime on the SOC lab with no remaining threat to stop. **Recorded as a decision, not an omission** | n/a |
| F.3 | Containment | **Credential rotation — `labtester` password rotated**, and SSH reviewed for key-only enforcement | Kyrell Green (Tier 1), Tier 2 concurrence | T+30 | The known-compromised credential is no longer valid. Sequence respected: evidence captured **before** rotation | Yes — re-issue |
| F.4 | Containment | **Account privilege review** — `labtester` (uid 1001) confirmed non-privileged; no privileged account targeted or accessed | Tier 2 | T+30 | Blast radius is one unprivileged lab test account | n/a |
| F.5 | Containment | **Hardening change — SSH password authentication disabled; key-only enforced** on the endpoint | Kyrell Green (Tier 1), Tier 2 concurrence | T+60 | Closes the attack vector at the authentication layer rather than only the credential. *This is the control that would have prevented the whole incident* | Yes — config change |
| F.6 | Containment | **Enable alerting path** — email notification reviewed and the indexer/dashboard confirmed as the only working delivery path; low-severity-signal ownership assigned | Kyrell Green + Tier 2 | T+60 | Addresses the "nobody saw the 17:38 anomaly" failure by ensuring there is a path *and* an owner | Yes |
| F.7 | Eradication | **No malware, no persistence, no backdoor account, no added SSH key found** — nothing to remove. *Eradication is a distinct step from containment precisely because here it had nothing to act on* | Tier 2 | T+45 | Post-access query returned no artifact; FIM `/etc/shadow` changes attributed to the legitimate `5402` `passwd` command, not tampering | n/a |
| F.8 | Eradication | **Root cause patched** (F.5) and credential invalidated (F.3) | Tier 2 | T+60 | The two conditions that produced the incident are both removed | Yes |
| F.9 | Recovery | **No restoration required** — no service interruption occurred, no data loss, no encryption. Host remained in service throughout | Tier 2 | T+60 | Nothing to restore; recovery is a documented no-op, stated explicitly so its absence is not mistaken for an omission | n/a |
| F.10 | Recovery | **Elevated monitoring, 30 days** — heightened Wazuh auth + FIM scrutiny on agent `002`, with every subsequent alert on that host cross-checked against this case's observables | Tier 2 | T+60 | Per `Incident_Response_Plan.md` §5 step 4: a recurrence would prove eradication incomplete | Yes |
| F.11 | Recovery | **Baseline not reset** — the FIM baseline was deliberately **not** reset, so a recurrence would be detectable rather than absorbed | Tier 2 | T+65 | Preserves detection continuity; resetting the baseline here would have hidden the next attempt |

### 6.6 Section G — Indicators of compromise

| Type | Value | First seen | Last seen | Confidence | Where observed | Action taken |
|---|---|---|---|---|---|---|
| IPv4 (source) | `192.168.64.3` | 2026-10-01 16:23 | 2026-10-01 17:50:13 | High for *volume and outcome*; **identity as an adversary: none** — this is the monitored host's **own** address (`agent.ip`), i.e. a self-generated lab test | `data.srcip`, agent `002` alerts | Edge/segment block (F.1). **Must not be reported as an external attacker IP — see `A.11a`** |
| IPv4 (demo range, Suricata only) | `203.0.113.77` | 2002-08-28 (synthetic pcap time) | — | **Low — scenario artefact, not this event** | EveBox sid 2001219 | **None.** Recorded as an exercise indicator only; must not be treated as real threat intelligence |
| Account (targeted & accessed) | `labtester` (uid 1001) | 2026-10-01 16:23 | 2026-10-01 17:50:10 | **High — confirmed access** | `data.dstuser`, `5501` uid | Rotated (F.3); SSH key-only (F.5) |
| Host | `Kali` / agent `002` | — | — | High | `agent.id` | Monitored 30 days (F.10) |
| ATT&CK technique | **T1110** Brute Force | 2026-09-30 18:35 | 2026-10-01 17:50 | High — recurring across 4 waves | `rule.mitre` on `5763` / `40112` | Detection hardening (F.6) |
| ATT&CK technique | **T1078** Valid Accounts | 2026-10-01 17:50:09 | — | **High — confirmed use** | `rule.mitre` on `40112` | Credential rotation; key-only SSH |
| Technique *not* observed | T1059 execution, T1053/T1547 persistence, T1071 C2, T1021 lateral movement | — | — | — | Absent from the post-access window | **Recorded as "not observed", not "did not occur"** — see `E.3` limitation |
| Source ports (structure) | 12 ports, 3 batches × 4 parallel (`40314/40316/40342/40352`, `49022/49024/49038/49046`, `49062/49066/49068/49088`) | 17:48:28 | 17:50:11 | High | `full_log` | None — behavioural, used for tool attribution |

### 6.7 Section H — Communication and notification log

| # | Time (UTC) | Audience | Channel | Content summary | Sent by | Acknowledged |
|---|---|---|---|---|---|---|
| H.1 | 2026-10-01 ~17:52 | Tier 2 on-call | Case update + message, both carrying `SOC-CASE-2026-0142` | L12 `40112` quoted verbatim; same-PID/port failure sequence; uid 1001; session 71 ms; severity High; **decision requested: isolation required?** | Kyrell Green (T1) | Tier 2, T+15 |
| H.2 | 2026-10-01 ~17:57 | Tier 2 | Case update | Tier 2 confirmed: no post-access activity in the 4-day window; `D4` = isolation **not** required; edge block sufficient | Tier 2 | Kyrell Green, T+25 |
| H.3 | 2026-10-01 ~18:05 | System owner / lab admin | Ticket referencing the case | Request to disable SSH password auth (F.5) and confirm the `192.168.64.3` segment ACL change (F.1) | Kyrell Green (T1) | Lab admin, T+40 |
| H.4 | 2026-10-01 18:10 | Management / shift lead | Case update (High severity per §4.3) | High severity declared and scored; no Tier 3; no Critical trigger (`D5` = NO) | Kyrell Green (T1) | Shift lead, same shift |
| H.5 | 2026-10-01 18:10 | Legal / privacy | **Assessed and recorded, not notified** | `D7`/`A.16`: no personal data — purpose-created lab test account and lab infrastructure IPs only. **If this had been a real user account, the GDPR Art. 33 72-hour clock would have started at 17:50:09 UTC** | Kyrell Green (T1) | n/a — decision recorded |
| H.6 | — | Tier 3 / forensics | **Not engaged — no trigger** | No `D5` indicator; nothing to forensically acquire that the indexer did not already hold | — | n/a |
| H.7 | — | External (regulator / individuals / client) | **Not applicable** | No personal data, no contractual exposure; lab environment | — | n/a |
| H.8 | Continuous | All case participants | TheHive case timeline | Every action, decision, approval and state change, timestamped and attributed | All | — |

### 6.8 Section I — Post-incident review

| # | What worked | What did not work / nearly failed | Evidence of the gap | Fix | Owner | Due | Status |
|---|---|---|---|---|---|---|---|
| I.1 | **The stock rule set caught a successful brute force correctly and raised the right alert.** `40112` L12 with `T1078`+`T1110` fired on the exact event; `5715` supplied the group tag it depends on | — | — | Keep the rule set; document that `40112` → `5715` is a **silent dependency** — if `5715`'s regex stops matching, `40112` can never fire, with no error anywhere | Tier 2 | 2026-10-12 | Open |
| I.2 | The 71 ms session was bounded immediately and correctly classified as credential **validation** rather than use | **No push notification existed.** `<email_notification>no</email_notification>`, so a level-12 compromise alert notified nobody; detection depended on someone looking | `ossec.conf` read live; `smtp.example.wazuh.com` default, `<active-response>` block commented out | Configure a working notification path, or formally designate the indexer/dashboard as the sole monitored path **with a named owner and a review cadence** (F.6) | Tier 2 + lab admin | 2026-10-12 | Open |
| I.3 | Correlation rules (`5763`, `40111`, `5551`) correctly characterised volume and tool structure | **The level-4 volume anomaly at 17:38:44.429 fired 10 minutes before the successful wave and no one actioned it.** A 3.2× log-volume spike (`561 → 1812`) was the earliest available signal | `11` alert `firedtimes` record; no corresponding case, task or escalation exists for it | Assign an explicit owner and response for **low-severity anomaly alerts**, below the high-severity queue. A rule that fires and is never owned is worse than no rule, because it creates false assurance | Tier 1 lead | 2026-10-12 | Open |
| I.4 | Session bounding via the `5501`/`5502` pair gave a precise 71 ms answer — cheap, decisive, and not obvious | — | — | Add "bound the session from the PAM open/close pair" to the credential-attack case template as a mandatory task | Tier 1 | 2026-10-10 | Open |
| I.5 | Same-PID/same-port correlation (2446058/49024) gave unambiguous proof of the exact successful attempt | — | — | Document this correlation technique in the detection guidance — it is the strongest available proof and most analysts will not think of it | Tier 2 | 2026-10-12 | Open |
| I.6 | — | **The enabled state was materially weaker than the documentation claimed.** No custom rule deployed (`local_rules.xml` holds only `100001`; **zero** `1000*` alerts in the index), no Suricata integration, no intel enrichment | Manager ruleset + index aggregation + `ossec.conf` | Correct the documentation (§9.2) and either deploy the intended custom rule or delete the claim. Undocumented capability is an audit finding waiting to happen | Kyrell Green | 2026-10-07 | Open |
| I.7 | The account was non-privileged (uid 1001), which bounded the blast radius to one account | **Password authentication was enabled on an exposed host** — the single condition that made the incident possible | `full_log` *"Accepted **password**"* | Enforce key-only SSH on all lab endpoints (F.5); treat "password auth enabled on an exposed service" as a standing control failure, not a per-incident finding | Lab admin | 2026-10-12 | Open |
| I.8 | — | **Password spraying is undetectable in this ruleset.** `40111`, `40112`, `5712`, `5763`, `5551` are all `same_source_ip`; one source trying one password across many accounts never trips them | Ruleset XML for all five rules | Add a `different_source_ip` / account-aggregation rule, or a rule keyed on **distinct target accounts per source** | Tier 2 | 2026-10-19 | Open |
| I.9 | — | **Detection was volume-blind to the enabling condition.** Three `passwd labtester` commands the same day, the last 2 min 15 s before the attack, were logged at **level 3** and not connected to the attack | `5402` ×3, `firedtimes` 1–2, level 3 | Raise/alert on administrative credential changes on accounts under attack pressure, and correlate `5402` events with authentication-failure clusters | Tier 2 | 2026-10-19 | Open |
| I.10 | The 2026-09-30 blocked run and the 2026-10-01 successful run together gave an unusually clean comparison | — | Both runs' index aggregations | Retain both as regression baselines; the pair is the empirical basis for making `D3` mandatory (§1.3) | Tier 2 | — | Closed |
| I.11 | Declaring the FIM `/etc/shadow` changes as **explained** (the `5402` `passwd` command) prevented a false tampering finding | — | `5402` `full_log` vs FIM alert timestamps | Keep the practice: attribute every FIM alert before escalating it | Tier 1 | — | Closed |

**Root cause statement (one paragraph, for the file):** a valid, non-privileged lab account had
password-based SSH authentication enabled on a reachable host, and its password — re-set three
times the same day, most recently 2 minutes 15 seconds before the attack — was weak enough to be
guessed on the fourth attempt from a source already inside the lab network. The response
detection worked correctly and raised a level-12 alert within a minute of the compromise, but
the response *process* had two gaps: no notification path, so nobody was told; and no owner for
low-severity anomaly alerts, so the 10-minute-early warning was never triaged.

### 6.9 Section J — Closure

| Field | Value |
|---|---|
| Case closed by | Kyrell Green (Tier 1), Tier 2 review complete |
| Date/time closed | 2026-10-01 18:15 UTC (operational response closed); documentation completed 2026-10-05 |
| Final severity | **High** (base Medium + `D3` override; capped by `D5` = NO) |
| Final status | **Contained and recovered — confirmed credential compromise of one non-privileged account, no post-access activity observed within telemetry bounds** |
| Time to declare | **≈ 2 minutes** from the `40112` alert |
| Time to answer `D3` | **< 1 minute** — the success was the alert's own subject |
| Time to contain | **≈ 20 minutes** (source blocked, `T+20`) |
| Time to complete credential rotation + hardening | **≈ 60 minutes** |
| Time to eradicate | **Not applicable** — nothing to eradicate (`F.7`) |
| Time to recover | **Not applicable** — no interruption to restore (`F.9`) |
| Case file location | `cybersecurity_basics_1/Incident_Response_Methodology.md` §6, from `Incident_Response_Template.md` |
| Follow-ups outstanding | `I.1`–`I.9` (owners and dates in §6.8) |
| Lessons-learned review | Held 2026-10-05 with Tier 2; outputs recorded as `I.1`–`I.11` |

---

## 7. Why the documentation requirements exist

Incident documentation exists to answer, **without talking to anyone**, four questions for
every person who later touches the case — a replacement analyst at 03:00, a responder picking it
up at shift change, a manager, an auditor, a regulator, or a court:

1. **What happened?** — §6.2 timeline, §6.3 evidence, §6.6 indicators. Verbatim, sourced, timestamped.
2. **What did we do?** — §6.5 actions with named approvers, including the action we *declined*
   and why (`F.2`).
3. **Why did we did it?** — the decision points (`D1`–`D7`), the severity arithmetic
   (`A.9`), and the evidence that forced each branch.
4. **What will we do differently?** — §6.8 findings, each with an owner and a date.

The four-question test is also the **quality gate for the case file itself**. A file that cannot
answer all four without the original analyst present is incomplete, regardless of how much was
written — and that is precisely why the template (`Incident_Response_Template.md`) forces the
structure rather than trusting an analyst to remember it under pressure.

Two further reasons the requirements exist, both learned the hard way in this lab:

- **Documentation is how detection quality is measured.** Findings `I.1`, `I.6`, `I.8` and `I.9`
  — the `40112`→`5715` silent dependency, the undeployed custom rule, the spraying gap, the
  level-3 credential change — were discoverable **only** because the case file recorded what fired
  and what was enabled. A SOC that does not write this down cannot see its own blind spots.
- **Documentation is the defence.** Under GDPR Art. 33 an organisation must be able to state what
  happened, what it did, and when. That is not reconstructable from memory six months later,
  and it is not reconstructable from chat logs.

---

## 8. Evidence, method and reproducibility

Everything asserted in §6 was read from the running lab on **2026-10-05**. The environment:

| Component | Version | Address |
|---|---|---|
| Wazuh manager + API | 4.14.7 | `https://localhost:55000` |
| Wazuh indexer | 4.14.7 | `https://localhost:9200` |
| Wazuh dashboard | 4.14.7 | `https://localhost:443` |
| TheHive | 5.2.16 | `http://localhost:9000` |
| Suricata + EveBox | 8.0 | `http://localhost:5636` |

**Alerts are read from the indexer, not the Wazuh API.** Wazuh 4.14.7 has **no `/security-events`
endpoint** — it returns 404 (confirmed against the manager's `openapi.json`, 150 paths). The
`siem/indexer_client.py` component in the capstone exists for this reason.

Representative queries (indexer, HTTP Basic, `https://localhost:9200`) — these are the queries a
reviewer re-runs to check every number in §6:

**The decisive alert:**
```json
{"size":1,"query":{"bool":{"must":[{"term":{"rule.id":"40112"}}]}},
 "_source":["@timestamp","rule.id","rule.level","rule.description","rule.mitre",
            "agent.name","agent.id","data.srcip","data.dstuser","full_log","rule.firedtimes"]}
```
→ 1 hit: `2026-10-01T17:50:09.931Z`, L12, agent `002`/`Kali`, `srcip 192.168.64.3`,
`dstuser labtester`, `Accepted password for labtester from 192.168.64.3 port 49024 ssh2`.

**The proof sequence — three failures then success on one connection (PID 2446058 / port 49024):**
```json
{"size":30,"query":{"bool":{"must":[{"term":{"agent.id":"002"}},
  {"range":{"@timestamp":{"gte":"2026-10-01T17:49:55Z","lte":"2026-10-01T17:50:10Z"}}}]}},
 "_source":["@timestamp","rule.id","rule.level","rule.firedtimes","full_log"],
 "sort":[{"@timestamp":{"order":"asc"}}]}
```
→ `5760` ft **605** @17:50:02 → ft **610** @17:50:05 → ft **612** @17:50:07 → `40112` @17:50:09.931
→ `5501` session opened uid 1001 @17:50:09.931 → `5502` session closed @17:50:10.002.

**True attack volume (`firedtimes`, not hit count):**
```json
{"size":1,"query":{"term":{"rule.id":"5760"}},
 "_source":["rule.firedtimes"],"sort":[{"rule.firedtimes":{"order":"desc"}}]}
```
→ `firedtimes` = **614** for 2026-10-01, against **754** indexed `5760` documents for the day
(§1.4: alert compression + `5763`'s `ignore="60"`).

**Post-access absence query — with its bounds and its full result recorded alongside (`E.3`):**
```json
{"size":0,"query":{"bool":{"must":[{"term":{"agent.id":"002"}},
  {"range":{"@timestamp":{"gte":"2026-10-01T17:50:14Z","lte":"2026-10-05T23:59:59Z"}}}]}},
 "aggs":{"r":{"terms":{"field":"rule.id","size":60,"order":{"_key":"asc"}}}}}
```
→ **8 documents total**, all benign: `504` ×4 (*Wazuh agent disconnected*, lab VM shutdowns),
`550` ×1 (FIM `'/etc/shadow' modified — Mode: scheduled` on 2026-10-02, attributable to the
`passwd labtester` credential change), `5501` ×3 (`lightdm`/systemd greeter session opens on
2026-10-01 18:00:45). **No `5402` by `labtester`, no `5715`, no persistence rule, in 4 days.**

**The agent's own address — the basis for the `A.11a` source caveat:**
```json
{"size":1,"query":{"term":{"agent.id":"002"}},
 "_source":["agent","agent.ip","agent.id","agent.name"]}
```
→ `{'ip': '192.168.64.3', 'name': 'Kali', 'id': '002'}` — **identical to the recorded
`data.srcip`**, which establishes the attack was self-generated in the lab.

**The comparison run (2026-09-30, blocked):**
```json
{"size":0,"query":{"bool":{"must":[{"term":{"agent.id":"002"}},
  {"range":{"@timestamp":{"gte":"2026-09-30T18:30:00Z","lte":"2026-09-30T18:50:00Z"}}}]}},
 "aggs":{"r":{"terms":{"field":"rule.id","size":40,"order":{"_key":"asc"}}},
         "succ":{"filter":{"term":{"rule.id":"5715"}}}}}
```
→ `5760` 123, `5763` 5, `5758` 8, `40111` 2, `5551` 2, `2501` 8, `2502` 22, `5503` 22, and
**`5715` = 0 → no successful authentication.**

**Configuration claims, read from the running manager:**
```bash
docker exec single-node-wazuh.manager-1 grep -n -A5 'id="40112"' /var/ossec/ruleset/rules/0280-attack_rules.xml
docker exec single-node-wazuh.manager-1 grep -A1 email_notification /var/ossec/etc/ossec.conf
docker exec single-node-wazuh.manager-1 grep -o '<rule id="[0-9]*"' /var/ossec/etc/rules/local_rules.xml
```
→ `40112` L12 `timeframe 240` (quoted in §1.2); `<email_notification>no</email_notification>` and
`<smtp_server>smtp.example.wazuh.com</smtp_server>` (claim `I.2`); and the **only** rule id in
`local_rules.xml` is **`100001`** — proving rule `100010` does not exist (§9.2).

---

## 9. Corrections to earlier versions of this documentation

Recorded explicitly rather than silently patched, because silently fixing a wrong claim leaves
the reader unable to tell which statements are trustworthy.

### 9.1 The scenario changed: this is no longer a "blocked" attack

The 2026-09-15 draft of this document documented a case in which 412 SSH failures from
`203.0.113.77` against `root` on `kali-lab-02` (agent `011`, `10.11.3.57`) were cleanly blocked
with no successful login, severity 3, and no containment beyond an edge block.

The 2026-10-05 investigation established that this account of the incident was wrong:

- **The attack succeeded on 2026-10-01** — `40112` level 12, `Accepted password for labtester`,
  71 ms authenticated session as uid 1001. The earlier "no successful login" belief was based
  only on the 2026-09-30 run, which genuinely was blocked.
- **The asset identifiers were wrong.** The attacked host is agent **`002` / `Kali` /
  `192.168.64.3`**, not `kali-lab-02` / agent `011` / `10.11.3.57`.
- **The attacker identity was wrong.** The draft names `203.0.113.77` (a RFC 5737
  documentation-range address that only ever appeared in the Suricata **offline pcap replay**)
  as the attacking source. The real Wazuh events record `data.srcip = 192.168.64.3`, which **is
  the monitored host's own address** — the attack was self-generated by lab test tooling, not
  delivered by a remote host. See `A.11a`. This is the most consequential correction in this
  document: quoting `203.0.113.77` as the attacker would misrepresent the incident as an
  external breach.
- **The counts were wrong** — 412 vs the real **614 attempts** (`firedtimes`), **61 indexed
  `5760`** in the successful wave, and a 71 ms session the draft did not contain at all.
- **The document avoided the phases that matter most** for this incident type. Documenting only a
  blocked attack means documenting no session bounding, no isolation decision, no rotation of a
  credential known to be compromised, and no compromise declaration.

§6 replaces it with the verified event. **The lessons from the blocked run are not discarded** —
they are retained as `D.8` (2026-09-30 comparison) and `I.10`, because "the same attack failed
yesterday and succeeded today" is exactly the finding that justifies making `D3` mandatory.

### 9.2 The detection claims were wrong in the original and in sibling documents

The 2026-09-15 draft stated that "**Wazuh rule 100010** (SSH brute-force attempt) fires alongside
per-event rule **5716**, severity 10, tagged T1110", and that alerts are pulled via
`GET /security-events`. Both claims are false in this lab:

| Claim in the 2026-09-15 draft | Verified reality (2026-10-05) |
|---|---|
| Custom rule **`100010`** is the brute-force detection | **Rule `100010` does not exist on the manager.** `local_rules.xml` contains only the shipped example `100001`; the index holds **zero** alerts for any `1000*` rule id. Every detection in this case came from the **stock** ruleset: `5763`, `40111`, `40112`, `5758`, `5551`, `5760` |
| Per-event auth rule **`5716`** is the paired rule | `5716` is generic (*"SSHD authentication failed"*). The paired rule that matters is **`5715`** (level 3, `^Accepted`) — the only rule in the chain carrying the `authentication_success` group tag that `40112` depends on |
| Alerts pulled via **`GET /security-events`** | **Wazuh 4.14.7 has no `/security-events` endpoint** (404, confirmed in `openapi.json`). Alerts come from the **indexer** (`https://localhost:9200`, `wazuh-alerts-4.x-*`) |
| Suricata provides live wire-level corroboration | Suricata has **no Wazuh integration** and runs **offline pcap replay**. Its sid 2001219 alert carries **synthetic `2002-08-28` scapy timestamps**, and `203.0.113.77` is a documentation-range address. It corroborates the *scenario*, not a live event |

**The same incorrect claims appear in several sibling documents** and are left in place for the
student to decide, rather than silently rewritten:

| File | Incorrect claims to review |
|---|---|
| `cybersecurity_basics_1/Incident_Response_Plan.md` | §2 (rule `100010` as the worked detection example; `/security-events`), §7 (SIEM connector pulls `/security-events`), §9 rubric table (same) |
| `cybersecurity_basics_1/Comprehensive_Security_Policy.md` | References to the `100010` detection rule |
| `security_operations_center_1/SIEM_Implementation.md` | §2 ("sample correlation rule as created" — the rule was never deployed), §4.1 (email notification `email_alert_level 7` — **email notification is disabled**) |
| `security_operations_center_1/SOC_Operations.md` | `100010` references; email-notification assumptions |
| `network_security_1/*.md` (4 files) | `100010` references and `/security-events` references |
| `ai-agentic-soc/docs/ARCHITECTURE.md`, `ai-agentic-soc/Firewall_IDS_IPS_Implementation_Report.md` | `100010` references |

Two options, and the choice is the student's:

1. **Deploy rule `100010`** as a genuine custom rule (a `same_source_ip` / frequency rule on the
   `authentication_failed` group with a T1110 mapping) so the documentation becomes true. This is
   the better outcome — it closes gap `G6` and produces a detection asset that is genuinely the
   student's own work.
2. **Correct the documentation** to describe the stock rules that actually fired, as §1.2 does.

What should not be done is leaving the current state: documentation claiming a bespoke detection
capability that does not exist is an audit finding, and it is the specific kind of inaccuracy
that `security_operations_center_1/Threat_Detection_Principles.md` was written to eliminate.

### 9.3 Note on the Suricata timestamps

The `ET SCAN Potential SSH Scan` alert (sid 2001219) in EveBox carries
`timestamp: 2002-08-28T02:00:00Z`. This is **not** a real packet time — the replayed pcap was
generated with scapy and carries synthetic timestamps. Any document citing that alert must say so
(§6.3 `D.10` does), otherwise a reader may believe network evidence exists from a date the
incident did not occur on.

---

## 10. Document map

| Requirement | Location |
|---|---|
| Designated incident type, defined and justified | §1.1 |
| How it is genuinely detected (real rules, verified) | §1.2 — full chain `5700/5715/5716/5758/5760/5763`, branch B `5710/5712`, `40111`, `40112`, the `11` anomaly |
| Real-vs-noise discrimination, with evidence | §1.3 — the 09-30 vs 10-01 comparison |
| The volume-counting trap | §1.4 — `firedtimes` vs hit count |
| **Initial response protocols** | §2 — principles (§2.1), triage priority (§2.2), the 60-minute runbook in 3 blocks (§2.3), all 7 decision points (§2.4), timing targets (§2.5) |
| **Case management system components and operational purpose** | §3 — every component with general purpose *and* this workflow's use (§3.2), how they combine (§3.3), and 6 verified deployment gaps (§3.4) |
| **Escalation criteria** | §4.1 severity factor model with worked arithmetic · §4.2 tiers · §4.3 triggers incl. SLA over-run · §4.4 decision map |
| **Communication protocols** | §4.5 standing rules + notification matrix with legal clocks · §4.6 anti-patterns |
| **IR principles and methodology explained** | §5 — lifecycle with rationale (§5.1), 16 principles with where each is demonstrated (§5.2), agentic SOC integration (§5.3) |
| **Completed IR documentation template for the scenario** | §6 — Sections A–J of `Incident_Response_Template.md`, completed for the real 2026-10-01 compromise |
| **Documentation requirements explained** | §7 — the four-question test as a quality gate; detection-quality and legal-defence rationale |
| Evidence, method, reproducibility | §8 — environment, every source query, configuration verification commands |
| Corrections to earlier drafts | §9 — scenario change (§9.1), false detection claims and the full list of affected files (§9.2), Suricata timestamp caveat (§9.3) |

---

## Screenshots still to be captured

The case record in §6 is built from live system evidence. The following console captures remain
to be taken for the portfolio submission, and each corresponds to a specific claim above:

| # | Screenshot | Source | Supports |
|---|---|---|---|
| 1 | The `40112` level-12 alert with `full_log` and MITRE tags | Wazuh dashboard → alert detail | §6.1 `A.4`–`A.5`, §6.2, §6.3 `D.1`–`D.2` |
| 2 | The failure→success sequence for `sshd[2446058]` port 49024 | Wazuh dashboard, filtered to PID/port | §6.2, §6.4 `E.1` |
| 3 | The `5501` / `5502` session pair showing 71 ms | Wazuh dashboard | §6.2, §6.4 `E.2` |
| 4 | The `5402` `passwd labtester` events | Wazuh dashboard | §6.2 context, §6.4 `E.5` |
| 5 | The `11` level-4 volume anomaly at 17:38:44 | Wazuh dashboard | §6.2, §6.8 `I.3` |
| 6 | The TheHive case record created from the credential-attack template | `http://localhost:9000` | §3, §6.1 `A.15` |
| 7 | EveBox showing sid 2001219 with its synthetic timestamp visible | `http://localhost:5636` | §6.3 `D.10`, §9.3 |
| 8 | `ossec.conf` showing `<email_notification>no</email_notification>` | manager config | §6.8 `I.2` |
