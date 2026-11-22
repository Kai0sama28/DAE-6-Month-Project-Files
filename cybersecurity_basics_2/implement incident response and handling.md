# Implement Incident Response and Handling

**Workspace:** `DAE-6-Month-Project-Files` (DAE 6-month cybersecurity program, capstone `ai-agentic-soc`)
**Prepared:** 2026-11-22
**Purpose:** Map the project's existing incident response artifacts to the five rubric requirements, with file paths and line-level evidence. The work is a real lab IR capability — a NIST-aligned plan, a documented case with live containment execution, forensic collections with chain of custody, three scored incident types, and a post-incident review. No new implementation is claimed.

---

## Rubric coverage at a glance

| Rubric requirement | Status | Primary evidence |
|---|---|---|
| Incident response plan (IRP) with 5 steps: preparation, identification, containment, eradication, recovery | **Met** — NIST wording uses "Detection & Analysis" for identification | `cybersecurity_basics_1/Incident_Response_Plan.md`; `incident_response_1/IR Documentation & Reporting.md`; `security_operations_center_1/Incident_Response_Methodology.md` |
| At least one forensic tool used for data collection | **Met** — several tools used with hashes; Volatility/Sleuth Kit are planned, not executed | `incident_response_1/Incident Response and Containment.md`; `Security_Monitoring_1/Digital Evidence Management.md` |
| Evidence collection and documentation with chain of custody, ≥2 evidence forms | **Met** — logs/alerts, screenshots, pcaps, memory cores | `Security_Monitoring_1/Digital Evidence Management.md` §5 |
| Triage and prioritization of 3 incident types by severity and business impact | **Met** — High / Medium / Low with arithmetic and impact rationale | `incident_response_1/Incident Detection and Analysis.md` §4 |
| Post-incident outcome summary and ≥2 lessons learned | **Met** — 11 recorded findings (I.1–I.11), root cause, closure record | `security_operations_center_1/Incident_Response_Methodology.md` §6.8–6.9; `incident_response_1/Post-Incident Procedures.md` §5.7 |

---

## 1. Five-step incident response plan

The plan follows **NIST SP 800-61**, whose "Detection & Analysis" phase is the rubric's "Identification". The mapping is explicit and consistent across the documents.

- `cybersecurity_basics_1/Incident_Response_Plan.md:12–18`: "This plan defines how security incidents are **detected, contained, eradicated, and recovered from** in the SOC lab, using the NIST SP 800-61 incident-response lifecycle (Preparation → Detection & Analysis → Containment → Eradication → Recovery → Post-Incident)." It also records the governing rule: "the human analyst keeps final authority over every response action — the same hard rule the AI-Agentic SOC project enforces with its human-in-the-loop approval gate."
- `incident_response_1/IR Documentation & Reporting.md:21–30` tabulates every phase with objective, key activities and evidence collection: **Preparation** ("Tool setup, playbooks, contacts, baselines"), **Detection & Analysis** ("Alert triage, correlation, scoping, severity classification"), **Containment** ("system isolation"), **Eradication** ("malware removal, credential resets, vulnerability patching"), **Recovery** ("System restoration, monitoring, validation"), and Post-Incident ("Lessons learned").
- `incident_response_1/Incident Detection and Analysis.md:50–71` gives the seven-phase investigation method (0 Prepare, 1 Validate, 4 Assess, 5 Decide & act, 6 Document & learn) and cites the NIST lineage at line 56.

The IRP is **operationalized**, not just described:

- Timed playbook phases in `incident_response_1/IR Documentation & Reporting.md:47–130`: Detection & Analysis (0–15 min), Containment (15–30 min) with the warning at line 61 **"CRITICAL: Capture volatile evidence BEFORE containment"**, Eradication (30–90 min), Recovery & Validation (90+ min).
- Rules of engagement in `incident_response_1/Incident Response and Containment.md:440–449`: "**Human approval gate.** No containment action executes without a named approver", "**Capture volatile evidence first** … then isolate", "**Cheapest reversible action first** (firewall rule before NIC down before VM stop)."
- A **live-executed** containment drill at `incident_response_1/Incident Response and Containment.md:583–604`: "The playbook was executed end-to-end on the Kali stand-in … Each level was isolated, probed from the host, and reversed before the next"; L1 firewall, L2 interface down, L3 hypervisor suspend, L3b service/account lock all "produce the claimed observable effect and are reversible."
- `security_operations_center_1/Incident_Response_Methodology.md:688–702` records completed case actions mapped to phases: containment (F.1 edge block at T+20, F.3 credential rotation, F.5 key-only SSH), eradication (F.7 "No malware, no persistence, no backdoor account, no added SSH key found"), recovery (F.9 "No restoration required"; F.10 "Elevated monitoring, 30 days").

**Caveat:** the exact phrase "Identification" is not used; "Detection & Analysis" is the NIST equivalent. Live platform fidelity is limited: `incident_response_1/Incident Response and Containment.md:656–666` records that Parrot OS was not rebooted, the procedures ran on the Kali/UTM stand-in, full-RAM/Volatility work is pending, and L4 (`utmctl stop`) was not executed. These limit platform coverage, not the existence or structure of the IRP.

## 2. Forensic tools for data collection

Multiple basic forensic collection tools were **actually used**; advanced memory tools are documented as planned/pending.

- **Tool inventory** — `incident_response_1/IR Documentation & Reporting.md:400–423` lists Wazuh Agent, `tcpdump`, Wireshark/`tshark`, `hashdeep`, `journalctl`, `ss`/`netstat`/`ip`, `ps`/`pstree`/`lsof`, `iptables`, `auditd`/`ausearch`; planned: Volatility 3, Sleuth Kit, `dcfldd`, `testdisk`, `gcore`/`gdb`, LiME, AVML.
- **Order of volatility collection** — `Security_Monitoring_1/Digital Evidence Management.md:16–38`: "Live data collection was performed following the order of volatility principles (RAM → running processes/network → logs → disk)"; commands `uname -a`, `cat /etc/os-release`, `uptime`, `date -u`, `env`. Process/network collection at lines 40–78 includes `ps aux`, `ps -ef --forest`, `pstree -p`, `ss -tulnp`, `ip addr show`, `ip route show`, `iptables -L -n -v`, with line 78 stating "All collected artifacts were immediately hashed with SHA-256 for integrity verification."
- **Network capture** — `incident_response_1/Incident Response and Containment.md:331–353`: `tcpdump -i eth0 -s 0 -c 20 -w demo_icmp.pcap "icmp"` → `capinfos demo_icmp.pcap` → `sha256sum demo_icmp.pcap`; result: "10 packets captured … file 1164 bytes, SHA-256 `7a14870d0fc7c489dced468a8c69366aad29d44afff59592413e77387e0a69a1`." A repeat run is at lines 423–430, with full hash in `incident_response_1/IR_Containment_Live_Demo_Transcript_2026-10-26.txt:302`.
- **Log collection** — `incident_response_1/Incident Response and Containment.md:303–305`: `journalctl --no-pager -n 60 > …/journal_tail_60.txt` → `sha256sum` = `aee9b020259722f8cd3f41a788883db0ee66e66d9799b23140976c081bcd155c`.
- **Memory (process core)** — `incident_response_1/Incident Response and Containment.md:361–378`: "**Method A — kernel core dump of a live process … executed and verified [S6]:**" via `ulimit -c unlimited`, `nohup sleep 600 &`, `kill -ABRT $PID`; result "ELF 64-bit LSB core file, ARM aarch64 … 400 960 bytes, SHA-256 `045460872fe3bec6233bb943012252660515dd05973200745538c73ac299e930`".
- **Automated evidence pack** — `ai-agentic-soc/investigation/evidence.py:47–76` defines `gather_evidence()` (alert, identity, login history, risk factors, endpoint, processes, network, files, SIEM). `ai-agentic-soc/reports/SOC-20261022-008.md:244–253` records reproducible provenance: "Agent run id: `877a0776-26c5-4545-b20f-6cb893622269`", "Evidence pack sha256: `ad3672335c00a4510ebfa99d5a457f73`", "LLM prompt sha256: `51051e9b805996be564f1b41521c4b5d`".

**Caveat:** Volatility 3 was planned, not installed (`incident_response_1/IR Environment Setup.md:306–308`); Wireshark on Parrot pending (lines 284–292); full-RAM acquisition, Volatility 3, Sleuth Kit and `gcore`/`gdb` were not live-demonstrated (`Incident Response and Containment.md:658–659`). The rubric only requires ≥1 tool for collection, which is clearly satisfied.

## 3. Evidence collection, chain of custody, and ≥2 evidence forms

Four distinct evidence forms are documented: **logs/alerts**, **screenshots**, **network pcaps**, and **memory cores** (plus filesystem copies).

- **Logs/alerts** — `security_operations_center_1/Incident_Response_Methodology.md:658–674`: "**Original alert record** | `40112` L12 … doc `_id` `4VOW-KABMZhxAQGakjXR`, index `wazuh-alerts-4.x-2026.10.01`"; "**Decisive log line** | `Oct 01 17:50:09 kali sshd[2446058]: Accepted password for labtester from 192.168.64.3 port 49024 ssh2`"; session boundary `5501` open / `5502` close = **71 ms**.
- **Screenshots** — `incident_response_1/Incident Detection and Analysis.md:412–421` lists `Wazuh Mitre Att&ck BF detection.png`, `Kali Brute Force Attack Access.png`, `Kali Brute Force test.jpg`, `Brute Force Threat detection.jpg`, `Windows_vulnerability_detection.png`, `Wazuh_CVE-2026-106190.png`, `5x5_risk_matrix_reference.png`, `agent deployed.png`; all confirmed present in the workspace. `Incident Response and Containment.md:630–635` adds `Parrot_7.4_UTM_last_running_state.png`.
- **Pcaps and cores with hashes** — `Security_Monitoring_1/Digital Evidence Management.md:312–324` (E-1 `/etc/passwd` `d66440fc…`, E-3 journal `aee9b020…`, E-4 pcap `7a14870d…`, E-5 core `04546087…`, plus R-1–R-6 rerun artifacts).
- **Chain-of-custody principles** — `Security_Monitoring_1/Digital Evidence Management.md:274–280`: "**Documentation from minute one:** Every action logged with UTC timestamp, operator, case ID", "**Never work on original:** Hash original → copy with preserved metadata → verify copy → analyze copy only", "**Evidence integrity:** SHA-256 hashes for all artifacts at collection and verification points", "**Complete audit trail:** All transfers, analyses, and accesses documented."
- **Case CoC record** — `Security_Monitoring_1/Digital Evidence Management.md:284–306`: Case ID `SOC-CASE-2026-0142`, Lead Investigator Kyrell Green, Case Type "SSH Brute Force - Credential Compromise (INC-1)", systems involved, and a CoC log with Date/Time (UTC), Action, Performed By, Evidence Affected, Notes/Verification (e.g. "2026-10-20T [S5] | Network capture | Kyrell Green | ICMP traffic pcap | tcpdump with BPF filter, SIGINT flush, verified with capinfos").
- **Hash audit** — `incident_response_1/Incident Response and Containment.md:401–434` fills E-1…E-6 and R-1…R-6; line 430: "`hashdeep -r` manifests; `hashdeep -a` audit **PASSED** for both trees"; transcript confirmation at `IR_Containment_Live_Demo_Transcript_2026-10-26.txt:335` and `:692`.
- **Automated CoC in the lab kit** — `incident_response_1/containment_lab/scripts/40-evidence-preserve.sh:39–47` writes `chain_of_custody_case_id=`, `operator=`, `host=`, `started_utc=`, `action=evidence_preservation`; lines 168–173 write `ended_utc`, manifest and `sha256sum`. Validation: `incident_response_1/containment_lab/evidence/validation/validation-report.txt:46–47` — "pass=36 warn=1 fail=0".

**Provenance caveat:** `incident_response_1/Incident Response and Containment.md:412–414` states the original artifacts E-1…E-5 live at `/home/kali/evidence/SOC-CASE-2026-0142/` on the guest; the repository holds the documented inventory, hashes, manifests and transcripts rather than the originals. This is disclosed in the source documents. Some screenshot captions are filename-derived and flagged for visual verification (`Incident Detection and Analysis.md:419`, `:470`).

## 4. Triage and prioritization of three incident types

The severity model comes from `cybersecurity_basics_1/Incident_Response_Template.md:61–64`: "Score three factors 1–4 each; **severity = the highest factor, not the sum**, then apply the upgrade/override rules." Overrides at lines 72–80 include successful authentication after brute force → +1 level and mandatory Tier 2, and post-compromise indicators → Critical/Tier 3. `incident_response_1/Incident Detection and Analysis.md:303–320` restates the matrix (Impact / Scope / Urgency) with the 5×5 reference image.

The three incidents at `incident_response_1/Incident Detection and Analysis.md:321–388`:

| ID | Type | Scoring arithmetic | Final | Business-impact rationale / disposition |
|---|---|---|---|---|
| **INC-1** — SSH brute force succeeded (`40112`), case `SOC-CASE-2026-0142` | Active credential attack | `Impact 2 / Scope 1 / Urgency 2 → base Medium; override +1 (D3=YES) → High; cap (D5=NO) → not Critical` | **High** | One non-privileged account (`labtester`, uid 1001), 71 ms session, no data access or lateral movement; Tier 2 mandatory, campaign handling via D6 |
| **INC-2** — 7 active CVEs + CIS SCA 27% (agent `007`) | Vulnerability / hardening exposure | `Impact 1 / Scope 2 / Urgency 2 → base Medium` | **Medium** | No attack observed; "one host, but machine-wide control failures affect **all** local accounts"; Tier 1 owns, remediation ticket to system owner, re-scan |
| **INC-3** — `/etc/shadow` FIM change | Integrity alert → authorised activity | `Impact 1 / Scope 1 / Urgency 1 → base Low` | **Low** | Attributed to `COMMAND=/usr/bin/passwd labtester`; "closed with written rationale", tagged "authorised admin action" (FP3) |

Line 386 summarizes: "Three distinct incident types (attack / exposure / integrity), three different matrix outcomes, each with the arithmetic in the record — per the taught principle: *severity is scored and capped, not felt*." A worked contrast at lines 371–376 shows that scoring INC-3 *before* attribution would produce a false High — the reason validation precedes scoring.

Business consequences are mapped in `security_operations_center_1/Incident Response Documentation_ Case Management, Escalation, and Ransomware Report.md:68–73` (SEV1 Critical through SEV4 Low) and applied to the case at lines 223–232: "Operations | **None** — no service interruption, no downtime…", "Data | **None** — no data access, exfiltration or loss…", "Account security | One non-privileged account … credential compromised and rotated", "Regulatory | Notification obligations assessed and recorded as not applicable." Additional AI-generated cases provide more examples: `ai-agentic-soc/reports/SOC-20261022-008.md:14–27` (Medium, rule `100002`) and `SOC-20261027-011.md:15–26` (High, rule `100032`).

## 5. Post-incident outcome and lessons learned

**Closure record** — `security_operations_center_1/Incident_Response_Methodology.md:754–770`:
- "Final severity | **High** (base Medium + D3 override; capped by D5 = NO)"
- "Final status | **Contained and recovered — confirmed credential compromise of one non-privileged account, no post-access activity observed within telemetry bounds**"
- "Time to declare | **≈ 2 minutes** from the 40112 alert"; "Time to contain | **≈ 20 minutes** (source blocked, T+20)"
- "Time to eradicate | **Not applicable** — nothing to eradicate"; "Time to recover | **Not applicable** — no interruption to restore"
- "Lessons-learned review | Held 2026-10-05 with Tier 2; outputs recorded as I.1–I.11"

**Root cause** — `security_operations_center_1/Incident_Response_Methodology.md:746–752`: "a valid, non-privileged lab account had password-based SSH authentication enabled on a reachable host, and its password — re-set three times the same day, most recently 2 minutes 15 seconds before the attack — was weak enough to be guessed on the fourth attempt… the response *process* had two gaps: no notification path, so nobody was told; and no owner for low-severity anomaly alerts, so the 10-minute-early warning was never triaged."

**Lessons learned (11 findings, I.1–I.11, with owner/due/status)** — `security_operations_center_1/Incident_Response_Methodology.md:730–744`. Examples:
1. **I.2 — No notification path**: "`<email_notification>no</email_notification>`, so a level-12 compromise alert notified nobody; detection depended on someone looking" → fix: working notification path or named owner + review cadence.
2. **I.3 — Unowned early warning**: "The level-4 volume anomaly at 17:38:44.429 fired 10 minutes before the successful wave and no one actioned it" → fix: explicit owner for low-severity anomaly alerts. "A rule that fires and is never owned is worse than no rule, because it creates false assurance."
3. **I.7 — Password-auth exposure**: "Password authentication was enabled on an exposed host — the single condition that made the incident possible" → fix: key-only SSH on all lab endpoints.
4. **I.8 — Spraying gap**: "Password spraying is undetectable in this ruleset" (`same_source_ip` rules only) → fix: account-aggregation rule.
5. **I.1 — Silent rule dependency**: "`40112` → `5715` is a **silent dependency**" → document it.

A second lessons summary at `incident_response_1/Post-Incident Procedures.md:596–613` records "What Went Well" (Wazuh detection/correlation, multi-source attack-chain reconstruction, forensic evidence handling, FIM correlation distinguishing authorized vs unauthorized changes) and "What Could Be Improved" (early-warning action, automated response, Linux endpoint telemetry, SIEM self-monitoring), with the takeaway: "The defense-in-depth approach with correlation is valuable, but prevention controls (brute force protection) and automated response are critical gaps." `security_operations_center_1/Incident Response Documentation_ Case Management, Escalation, and Ransomware Report.md:234–249` turns the lessons into a corrective-action table with Owner, Priority and Due.

**Caveat:** follow-ups I.1–I.9 remain open (line 769), so remediation is incomplete — but the rubric asks for analysis and lessons learned, which are clearly present.

## 6. Conclusion

All five IR requirements are met with direct evidence: a structured NIST-aligned IRP that was executed in a live containment drill, several forensic collection tools used with cryptographic hashes, four forms of evidence under a documented chain of custody, three distinct incident types scored by severity and business impact, and a post-incident review with eleven recorded lessons and owners. The honest qualifications are that "Identification" is expressed in NIST terminology, some advanced forensic tooling remains planned, the live work used a Kali/UTM stand-in rather than the Parrot host, original artifacts are guest-side, and several corrective actions are still open.
