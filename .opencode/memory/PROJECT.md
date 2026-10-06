# PROJECT — Living Memory Journal

Owner: Kyrell Green — 6-month cybersecurity program (SOC/security analyst track).
This journal is loaded every session in this workspace via `opencode.json` `instructions`.
Update it per the rules in AGENTS.md. NEVER store secrets/passwords/API keys here.

---

## Current status

**Latest (2026-10-06): `security_operations_center_1/Incident Response Documentation_ Case
Management, Escalation, and Ransomware Report.md` rewritten (311 lines) and added to the repo.**
Came from Downloads as a fictional "Northwind ransomware" draft; per user decision it now = generic
Jira/Slack model **kept + new §1.3 lab mapping** (TheHive = record, case timeline = coordination,
gaps G1/G4 named) · Part 2 generic SEV1-4 **kept + new §2.4** mapping to the scored factor-matrix
model, D1-D7, and the real achieved timings (declare ≈2 min, D3 <1 min, contain T+20) ·
**Part 3 fully replaced with the real case `SOC-CASE-2026-0142`** (all rules/timestamps/counts from
Incident_Response_Methodology.md §6, verified live 10-05) · **§3.13 labelled illustrative ransomware
annex** (isolate-vs-shutdown, protect backups first, ransom-not-paid decision, comms, lab
capability table) so the assignment's "Ransomware Report" title stays honest. Not yet rubric-checked
against the original assignment PDF (not in repo).

**Previous (2026-10-05, 2nd pass): `security_operations_center_1/Incident_Response_Methodology.md`
REWRITTEN (1007 lines) + new `cybersecurity_basics_1/Incident_Response_Template.md` (253 lines)**
for the Incident Response Methodology rubric. The 2026-09-15 draft was factually wrong and has
been replaced. Every claim re-verified live against the indexer/manager/TheHive/EveBox.

**Structure:** §1 incident type + the REAL detection chain (read from the running ruleset) +
real-vs-noise comparison + the `firedtimes` counting trap · §2 60-minute runbook (3 blocks) with
**7 decision points D1-D7** + timing targets · §3 TheHive 5.2.16 components (13 rows: what it is
/ operational purpose / use in this workflow) + **6 verified deployment gaps** · §4 severity
factor matrix (scored + overridden + capped, with worked arithmetic), 5 tiers, 8 escalation
triggers incl. SLA over-run, decision map, notification matrix with GDPR clocks, anti-patterns ·
§5 16 IR principles + NIST lifecycle rationale + agentic-SOC mapping · §6 **completed IR
template (Sections A-J of the new template) for the real 2026-10-01 compromise** · §7 why the
documentation requirements exist · §8 every source query + config commands so a reviewer can
re-derive every number · §9 corrections · §10 doc map · screenshot list still to capture.

**NEW FACT — the attack was SELF-GENERATED.** `data.srcip` on the 2026-10-01 attack is
`192.168.64.3`, which **is agent 002 `Kali`'s own address** (verified `agent.ip`). So the brute
force was produced by lab test tooling on the monitored host, not by a remote host. The old
draft named `203.0.113.77` (RFC 5737 doc range, Suricata pcap-replay only) as the attacker —
that would have misrepresented the incident as an external breach. This is stated as `A.11a` in
the doc and must not be quoted as an external attacker IP.

**Post-access window (2026-10-01T17:50:14Z -> 2026-10-05T23:59:59Z, agent 002) = 8 docs, ALL
benign:** `504` x4 (Wazuh agent disconnected / lab VM shutdowns), `550` x1 (FIM
`/etc/shadow` modified, **Mode: scheduled**, 2026-10-02 03:54 — attributable to the
`passwd labtester` credential change, NOT tampering), `5501` x3 (lightdm/systemd greeter,
2026-10-01 18:00:45). **No `5402` by labtester, no `5715`, no persistence rule.** The 71 ms
session conclusion stands.

**Severity scored High** (Impact 2 / Scope 1 / Urgency 2 -> base Medium; **override +1** on D3=YES;
**capped at High** by D5=NO). Template's factor matrix uses the Comprehensive_Security_Policy
Low/Medium/High vocabulary so the docs agree.

**Previous: `security_operations_center_1/Threat_Detection_Principles.md` written
(2026-10-05) — and the investigation turned up a genuine COMPROMISE the old docs said never
happened.** Deliverable (~1,110 lines) covers detection rule mechanisms, 3 distinct detection
scenarios, 5 threat-indicator families, a 7-phase analysis methodology (NIST SP 800-61 + ATT&CK
+ Diamond Model), and a full worked alert investigation against the live indexer. Every rule
fragment, level, threshold, timestamp and count was read from the running lab (ruleset files +
`wazuh-alerts-*`), not from memory.

**MAJOR FINDING — brute force SUCCEEDED on 2026-10-01 at 17:50:09 UTC.** This supersedes every
earlier "no successful login" note (which was based only on the 2026-09-30 run):
- **Rule `40112`, level 12, `0280-attack_rules.xml`**: *"Multiple authentication failures followed
  by a success."* Logic: `if_group=authentication_success` + `if_matched_group=
  authentication_failures` + `same_source_ip`, `timeframe 240`. MITRE `T1078` + `T1110`.
  `full_log`: `Accepted password for labtester from 192.168.64.3 port 49024 ssh2`.
- Preceded by **61 `5760` failures** in 17:48:26→17:50:07, **3 batches x 4 parallel connections**
  (12 distinct srcports). Proof of the exact point of success: `sshd[2446058]` / port 49024 fails
  3x (17:50:02, :05, :07) then succeeds on the 4th attempt.
- `5501` session opened uid 1001 at 17:50:09.931, `5502` closed at 17:50:10.002 = **71 ms**
  session (automated credential validation, not human use).
- **No post-access activity** in 5 days: nothing for agent 002 after 17:50:14 except 3 lightdm
  events at 18:00:45. No commands, no `5402` sudo by labtester, no persistence, no lateral
  movement. FIM `/etc/shadow` changes (10-01/10-02) are explained by `5402` `passwd labtester`.
- Password was changed **2m15s before** the attack: rule `5402` at 17:46:11
  `COMMAND=/usr/bin/passwd labtester` (also 16:22:17 and 17:03:06 the same day).
- Run 1 (2026-09-30 18:35:30→18:42:39) = same attack **blocked**: 5760 x123, 5763 x5
  (firedtimes 1,3,6,9,14), 5758 x8, 40111 x2, 5551 x2, **zero successes**. Run 2 had *half* the
  failure volume and succeeded — no rate/volume metric separates them; only `40112` does.

**Two documentation-vs-reality discrepancies found (flagged to student, not silently patched):**
1. **Custom rule `100010` does not exist on the manager.** `local_rules.xml` contains only the
   shipped example `100001`; zero alerts exist for any `1000*` rule id. So
   `security_operations_center_1/SIEM_Implementation.md` §2 ("sample correlation rule as
   created") is inaccurate. All real detections came from **stock** Wazuh rules.
2. **Email notification is OFF.** Live `ossec.conf` has `<email_notification>no</email_notification>`
   + default `smtp.example.wazuh.com`, and the `<active-response>` block is **commented out**
   (`grep -c "<active-response>"` = 1 match, but it is the commented example). So
   `SIEM_Implementation.md` §4.1 (email yes, `email_alert_level 7`) is inaccurate too. Practical
   consequence: **the indexer is the only working alert-delivery path** — which is why the new
   investigation is written entirely as indexer queries.

**Real rule chains (verified in the manager's ruleset — memorize these):**
- sshd branch: `5700`(lvl0,noalert,decoded_as sshd) -> `5710`(lvl5 invalid user)/`5715`(lvl3
  `^Accepted`, group **authentication_success**)/`5716`(lvl5) -> `5760`(lvl5 `Failed password`,
  group **authentication_failed**) -> **`5763`**(lvl10 freq8/120s/ignore60/same_source_ip, T1110).
  Invalid-user twin: `5710` -> **`5712`**(lvl10 freq8/120s/ignore60). `5758`(lvl8 max auth attempts).
- pam branch: `5500` -> `5503`(lvl5) -> **`5551`**(lvl10 freq8/**180s**/same_source_ip).
- cross-rule: **`40111`**(lvl10 freq**12**/**160s**, if_matched_group authentication_failed) and
  **`40112`**(lvl**12**, timeframe 240, if_group authentication_success).
- flood/anomaly: internal **`rule 11`**, lvl4, group `stats`, fired 3x: 09-18 22:57:44, 09-30
  16:18:16, **10-01 17:38:44 (10 min BEFORE the attack — unactioned early warning)**.
- **`ignore="60"` + alert compression** = why `firedtimes` (92 on 10-01) >> indexed alerts (19).
  Always quote `rule.firedtimes`, not the hit count, when counting attack volume.
- Windows agent 007 `DESKTOP-VCKJCPV` — full verified snapshot in "Agent 007 host telemetry"
  below (re-queried 2026-10-05 ~18:50Z; the old "210 alerts" figure in this journal was a
  mid-day partial count and is now superseded).

**Other detection-layer gaps logged as G1-G8** (see doc §5.8): no notification path; 100010 not
deployed; `40112` silently depends on `5715`'s group tag; duplicate level-10 rules (5763+40111);
flood alert unactioned; **password spraying undetectable (all rules are `same_source_ip`)**; no
live Suricata->Wazuh integration; endpoint visibility is journald-only (no process telemetry, so
"no post-access activity" is scope-bounded).

**Also still open from before:** Suricata `ET SCAN Potential SSH Scan` sid 2001219 confirmed from
`soc-lab/suricata/output/eve.json` (2 alerts, 203.0.113.77 -> 192.168.64.3:22, `action: allowed`,
sev 2). Note the replayed pcap carries synthetic 2002-08-28 timestamps (scapy-generated) — say so
rather than presenting them as real packet times.

## Agent 007 host telemetry — DESKTOP-VCKJCPV (verified 2026-10-05 ~18:50Z)

Identity: agent `007`, name `DESKTOP-VCKJCPV`, ip `10.11.1.232`, Wazuh v4.14.7, status `active`,
`dateAdd 2026-09-23T18:05:34Z`, lastKeepAlive `2026-10-05T18:50:35Z`. **728 alerts total**, on only
3 active days: 09-23 (437), 09-29 (42), 10-05 (248). Nothing 09-24..09-28 or 09-30..10-04 — the
host was simply off, not silently failing.

**GOTCHA — vulnerability data is at `data.vulnerability.*`, NOT top-level `vulnerability.*`.**
Querying `vulnerability.cve` returns **0 hits** and looks like "no vulnerabilities found", which is
a false negative. Correct paths: `data.vulnerability.cve`, `.severity`, `.package.name`,
`.score.base`, `.cvss.cvss3.vector`. The 23504 alerts carry ONLY `@timestamp`/`data`/`rule` — there
is no `full_log` at all. Same shape for SCA: `data.sca.check.result` (not `sca.check.result`).
This is the single biggest query trap on this data set. (Confirmed by getting it wrong first-hand
during the 2026-10-05 session: a `{"exists":{"field":"vulnerability"}}` query returned 0 hits on a
host with 7 live CVEs.)

**Vulnerability detector — 7 CVEs, all GIMP 3.2.40.0 x86_64, all Medium, all `status: Active`,
all within a single 70 ms burst at `2026-10-05T15:36:57.109-15:36:57.178Z`, rule `23504` lvl 7
(group `vulnerability-detector`).** Scan_id-independent; every alert carries the same package
version so this is one scan, not seven findings over time.
| CVE | CVSS base | published | CWE | notes |
|---|---|---|---|---|
| CVE-2026-82328 | 6.1 | 08-28 | CWE-125 | out-of-bounds read |
| CVE-2026-82343 | 6.1 | 08-28 | CWE-120 | buffer copy without size check |
| CVE-2026-78475 | 6.1 | 08-24 | CWE-125 | out-of-bounds read |
| CVE-2026-82324 | 6.1 | 08-28 | CWE-125 | out-of-bounds read |
| CVE-2026-82330 | 6.1 | 08-28 | CWE-125 | out-of-bounds read |
| CVE-2026-79902 | 5.5 | 08-26 | CWE-190 | Seattle FilmWorks plugin, VLA/stack overflow -> DoS; **only one with `confidentiality_impact: NONE`** |
| CVE-2026-80101 | 4.4 | 08-25 | CWE-125 | **only one with `availability_impact: LOW`** — hence the lower score |

All 7 are assigner `redhat` and share `AV:L/PR:N/UI:R/S:U` (local, no privileges, user
interaction required) with `integrity_impact: NONE` — so they are DoS/information-disclosure, not
RCE, and low practical risk on a single-user lab box. **NOTE the indexer's vector object has NO
`attack_complexity` key at all** (keys are attack_vector, availability, confidentiality_impact,
integrity_impact, privileges_required, scope, user_interaction) — so do **not** write `AC:L` into
any doc; it is not in the data. Only 23504 fires; there is no 23505/23506 (no "detected/unresolved"
variant) and no `vulnerability-detector` summary alert in the index.

**CIS SCA (Windows 10 Enterprise Benchmark v4.0.0) — 425 alerts: 304 `failed` (rule 19007, lvl 7),
116 `passed` (19008, lvl 3), 5 `not applicable` (19009 x4 + 19013 x1, lvl 3).**
**Score = 116/420 = 27.6% -> 27%.** Rule **`19005` lvl 9** = the summary alert
`SCA summary: CIS Microsoft Windows 10 Enterprise Benchmark v4.0.0: Score less than 30% (27)`,
fired 3x: 09-23 18:07:32, 09-23 18:07:48, 10-05 15:34:28. **The score did not improve between
09-23 and 10-05 — identical 27% — so nothing was remediated in the 12 days.** That is the single
best remediation-priority list available in this lab. Failure clusters worth citing in docs:
guest account not renamed; `Do not require CTRL+ALT+DEL` not Disabled; last-signed-in user not
hidden; machine inactivity limit + lockout threshold unset; anonymous SAM/share enumeration not
blocked; **LAN Manager auth level not set to "Send NTLMv2 response only"; LLMNR/Null-session
pipe settings default; UAC "Admin Approval Mode for built-in Administrator" not Enabled;
elevation prompt for standard users not "Automatically deny"; `Audit Process Creation` does not
include Success; ~25 services not disabled (Spooler, TermService, SessionEnv, RemoteRegistry-
adjacent, MapsBroker, lfsvc, BITS-adjacent, Xbox*, Wecsvc, WerSvc, WMPNetworkSvc, icssvc,
WpnService, PushToInstall, LxssManager, RasAuto, RpcLocator, SSDPSRV, upnphost, p2p*, PNRP*,
MSiSCSI, lanmanserver, wercplsupport, wusb); and all three firewall profiles still show default
logging (name/size/dropped/successful) + notification settings.

**Windows event channel — 270 alerts.** `full_log` is EMPTY for all of them; the payload lives in
`data.win.system` (`eventID`, `eventSourceName`, `channel`, `level`, `message`) and
`data.win.eventdata`. Never write a doc that quotes `full_log` for these.
- **Security-relevant, worth citing:**
  - `60110` lvl **8** = **event 4738 "A user account was changed"**, **8x all on 10-05**
    (15:33:12, 15:33:13, 15:52:36 x2, 16:55:02 x2, 17:31:08 x2 — each pair milliseconds apart).
    Subject = SYSTEM `DESKTOP-VCKJCPV$` (`S-1-5-18`, WORKGROUP) via logon `0x3E7`; Target =
    local user **`Kai` / "Kai Green"**, RID **1001**, SID `S-1-5-21-3649177984-1904162784-1086795393-1001`.
    Paired-ms pattern = a credential/profile update loop, not interactive admin work. **The
    captured events carry no changed-attribute detail, so "what changed" cannot be stated from the
    indexer — say that rather than guessing it was a password change.**
  - `61138` lvl 5 = event **7045 New Windows Service Created**, 4x: 09-29 15:03:01 + 15:03:01
    (`GoogleUpdater` 156.0.8067.0 `updater.exe`, two `--service=` variants) and 10-05 15:33:08
    (WSL: `Microsoft...WindowsSubsystemForLinux_3.0.1.0_x64...\wslinstaller.exe` and
    `C:\Program Files\WSL\wslservice.exe`). **All benign and attributable** — software install,
    not persistence.
  - `67022` lvl 3 = event **4624** (16x), `67023` = **4634** logoff (14x), `67024` = **4648**
    non-standard service logon (1x), `67028` lvl 3 = event **4672 Special privileges assigned**
    (9x). The 4624/4672 pair is an **interactive MicrosoftAccount (MSA) sign-in**:
    `logonProcessName User32`, `authenticationPackageName Negotiate`, `ipAddress 127.0.0.1`,
    `workstationName DESKTOP-VCKJCPV`, `subjectDomainName MicrosoftAccount`. 4672 privilegeList =
    SeSecurity, SeTakeOwnership, SeLoadDriver, SeBackup, SeRestore, SeDebug,
    SeSystemEnvironment, SeImpersonate. **The MSA account name is deliberately NOT recorded in this
    journal** (it is real PII and this file is committed to a public portfolio repo) — it is
    retrievable from the indexer if ever needed for a writeup.
  - `61104` lvl 3 = event 7040 service startup type changed (31x, 27 on 10-05 alone) — but every
    one inspected is `BITS` / `SWUpdateService` / `WSLService` flipping between `auto start` and
    `demand start`, i.e. Windows Update churn. **Volume here is noise, not 31 real changes.**
  - `60776` lvl 7 / `60775` lvl 5 = event 6003/6000, `Wlclntfy`/`SessionEnv`, "The winlogon
    notification ... unavailable" at 15:25:41 — correlates with the 15:25 service-start wave.
  - `61110` lvl **10** = event **10010 DCOM** server time-out, 3x on 10-05 15:33 — **level 10 but
    pure benign Windows noise**; a good example of level != severity.
  - `60132` lvl 5 = event 4616 System time changed, 10x, all `svchost.exe` / `S-1-5-19` /
    `SERVICE` — clock resync, benign. `657` lvl 3 = one `active-response` restart of `wazuh.exe`.
- **Noise to explicitly exclude in any doc:** `60642` "Software protection service scheduled"
  (51x), `61102` "Windows System error event" (37x), `60608` "Summary event of the report's
  signatures" (42x), `60610`/`60612`/`60635` Windows Installer (11x), `60796`/`60798`/`60805`/
  `60807`/`60808`/`60809` SQL Server engine (17x), `60668`/`60669` Windows Search (5x),
  `60702` VSS idle (3x), `61109` DNS timeout for `fe3cr.delivery.mp.microsoft.com` (5x).
- **`510` lvl 7 rootcheck, 12x across 3 days — same 3 false positives every time:**
  `C:\Program Files\Intel® 2D Imaging:Win32App_1`, `C:\Program Files\rempl:Win32App_1`,
  `C:\Program Files\UNP:Win32App_1` ("NTFS Alternate data stream found... possible hidden
  content"). These are Zone.Identifier NTFS alternate data streams on signed installers — **not
  evidence of hidden payloads.** Cite as a tuning example.

**Coverage gaps on this host (important for scoping claims):** **zero syscollector/inventory
alerts** (rules 8500/8700/5501/1570/1571 = 0 hits) and `os.*` is `None` in `/agents` for **all
three** agents including the manager. So there is **no process, user, port or software inventory**
— only FIM (510), CIS SCA (19005-19013), vulnerability detector (23504) and the raw Windows event
channel. Any "what was running on the host" question is unanswerable from this data set. Unlike the
Kali host, 007 does at least forward the Windows Application+Security event channels, so the
`60104`/`60110`/`61104`/`67022`-family is genuinely available here.

**Latest: SOC lab stage-2 stack live on Docker (2026-09-30) — TheHive + Suricata/EveBox
deployed and verified alongside Wazuh.** Capstone screenshots can now come from real consoles:
- **TheHive 5.2.16** (pinned — 5.3+ needs a license): stack `thehive-cassandra` +
  `thehive-elasticsearch`(7.17.13) + `thehive` at `soc-lab/thehive/`, UI `http://localhost:9000`,
  login `admin@thehive.local` / `secret` (service password lives in `soc-lab/thehive/.env`;
  `secret.conf` holds the play secret). No nginx (Wazuh owns 443) and no MinIO (localfs) to
  fit the 7.7GiB Docker VM.
- **Suricata 8.0 + EveBox console**: rules at `soc-lab/suricata/rules/` (53,039 ET Open via
  suricata-update). Runs **offline pcap replay** (Docker Desktop can't sniff lab traffic; no
  passwordless sudo for tcpdump). Driver script `soc-lab/suricata/run_ids.sh <capture.pcap>`
  runs Suricata + reloads the EveBox console at `http://localhost:5636` (plain HTTP, no auth).
- Smoke-test pcap (scapy SSH brute-force, staged verdict) produced 7 alerts incl. real sig
  **`ET SCAN Potential SSH Scan`** (sid 2001219, 203.0.113.77 -> 192.168.64.3, sev 2) + stream
  reassembly overlaps. EveBox `/api/alerts` confirmed 3 alert groups.
- **Rule chain to remember:** `Failed password for <VALID user>` -> 5700 -> 5716 -> **5760**;
  8x 5760 in 120s same `srcip` -> **5763** (freq 8, timeframe 120, ignore 60). The invalid-user
  variant fires 5710 instead and, because 5710 becomes the last matched sid, 5760 can never
  match — that is why the username MUST exist on the box. 5712 is the invalid-user BF twin.
- **Wazuh 4.14.7 API here has NO alerts endpoint** — `/security-events` returns 404 (confirmed
  against openapi.json, 150 paths). `/agents`, `/rules`, `/manager/status`, `/syscollector/*`,
  `/logtest` all work. Alerts must be pulled from the **indexer** (`https://localhost:9200`,
  `wazuh-alerts-*`, creds hardcoded in the wazuh-docker compose). `siem/client.py` query_alerts()
  calls `/security-events` and therefore needs repointing at the indexer before weeks 5-7.
- soc-lab lives OUTSIDE the workspace at `/Users/Adult/Desktop/soc-lab` (not in the repo, and
  there is no soc-lab/README — the earlier journal reference to one is stale). Wazuh compose is
  at `/Users/Adult/Desktop/wazuh/wazuh-docker/single-node`; its `ossec.conf` is bind-mounted from
  `config/wazuh_cluster/wazuh.manager.conf`, which is the file to edit for persistent config.
  Suricata has NO Wazuh integration yet (no eve.json localfile, `0475-suricata_rules.xml` present
  but not enabled) — planned as future work, not done.
- Docker runtime note: evebox `oneshot` binds loopback by default -> must pass `--host 0.0.0.0`;
  the `server --input` watcher did NOT ingest eve.json on a bind-mount (oneshot + persistent
  `--database-filename` is the working pattern). Remember
  `export PATH="/Applications/Docker.app/Contents/Resources/bin:$PATH"` for docker on the Mac.

**Latest: Windows host "DESKTOP-VCKJCPV" Wazuh agent enrolled + online 2026-09-23 — resolves
the BLOCKED-ON-NETWORK status in `ai-agentic-soc/docs/AGENT_DEPLOYMENT_STATUS.md`.**
- Network path to manager `10.11.3.185` now works (ping OK, TCP 1514/1515 OPEN).
- Root cause of service crash was `ossec.conf` `<address>0.0.0.0</address>` (MSI reconfig kept
  failing: 1602/1603/1625/1316). Fixed by editing the address to `10.11.3.185` directly
  (backup saved as `ossec.conf.bak`), started `WazuhSvc`.
- Enrolled as **agent id 007 `DESKTOP-VCKJCPV`** (`client.keys` populated, no registration
  password required — manager accepts passwordless enrollment), connected on 1514/tcp,
  manager pushed shared config, agent now running (pid 8172).
- Note for later: Mac manager has passwordless enrollment enabled.

**Latest: 3 network_security_1 deliverables drafted 2026-09-17 — Topology report, Protocols &
Architectures report, and Network Security Tools report — closing the two "partial" rubric gaps
(§1 Topologies, §2 Protocols & Architectures) and the missing §6 Security Tools.**

New files in `network_security_1/`:
- `Network_Topology_Implementation_Report.md` — LAN (star) topology chosen/justified; Mermaid
  logical diagram + inventory; how the LAN supports secure communication (firewall/edge scoping,
  TLS agent channel) and network management (fleet view, central logging, diagnostics).
- `Network_Protocols_and_Architectures_Report.md` — OSI + TCP/IP model for one device
  (`ubuntu-endpoint-01`); subnetting worksheet for `10.11.0.0/22` with allocation table; secure
  architecture protocol matrix (SSH key-only, TLS, HTTPS, ufw scoping, rule 100010).
- `Network_Security_Tools_Report.md` — Wireshark capture + analysis (SSH brute-force replay),
  Nmap 7.94 NSE vuln scan against `10.11.3.185`, Hydra SSH brute-force pentest output tied to
  SOC-CASE-2026-0142.

These use the same lab facts as the existing reports (10.11.0.0/22, kali-lab-02, ubuntu-endpoint-01,
rule 100010, 203.0.113.77). **Student must verify/capture real screenshots** (Wireshark protocol
hierarchy, Nmap output, Hydra output) and confirm the Hydra `labtester` test-account run actually
happened before submission.

**Rubric completeness for network_security_1 (7 line items):** §3 Firewall/IDS/IPS ✓ (2 PDFs),
§4 Access Control ✓, §5 Wireless ✓, §7 Monitor & Respond ✓ + now §1 Topologies ✓, §2 Protocols &
Architectures ✓, §6 Security Tools ✓ — all seven criteria now have deliverables.

**Sibling-deliverable housekeeping (2026-09-17):** student reorganised module folders — SOC
deliverables moved into `security_operations_center_1/` (SOC_Operations.md, SIEM_Implementation.md)
and the policy/IR docs into `cybersecurity_basics_1/` (Comprehensive_Security_Policy.md,
Encryption_Techniques_Demo.md, Incident_Response_Methodology.md, Incident_Response_Plan.md). Git
tree shows those as deletions pending the student's `git add`/commit.

**Capstone (unchanged from 09-14): ai-agentic-soc weeks 1–4 committed, working tree clean on the
Mac. Next capstone step: weeks 5–7 LangGraph supervisor.**

What exists today (capstone):
- `ai-agentic-soc/docs/ARCHITECTURE.md` — design update adopting **real Wazuh 4.14.7** as the
  SIEM + alert source (supersedes the mock-SIEM design v0.2).
- `schemas/` — internal Pydantic models (Alert, Identity, EDR, SIEM) + Wazuh raw models.
- `siem/client.py` — Wazuh REST client (JWT auth via `/security/user/authenticate`, token
  refresh, `/agents` + `/rules` + `/manager/status` + `/logtest`). Its `query_alerts()`/
  `get_alert()` still call the 3.x-only `/security-events` route and 404 on 4.14.7 — docstrings
  now say so; do not wire new code to them.
- `siem/indexer_client.py` (NEW 2026-10-01) — the **real** alert source. HTTP Basic client for
  the OpenSearch indexer (`https://localhost:9200`, `wazuh-alerts-*`, env `WAZUH_INDEXER_URL`/
  `_USER`/`_PASSWORD`/`_INDEX`). `query_alerts()`/`count_alerts()`/`get_alert()`/`ping()`; same
  signature as WazuhClient but filters take the dotted-field dict (`{"rule.id": "5763"}`) and
  translate to DSL, `q=` parses `field=value;field!=value`, returns `WazuhAlert` so
  `siem/normalizer.py` is untouched. Verified live against the indexer.
- `siem/normalizer.py` — Wazuh alert → internal `Alert` with MITRE preserved + severity clamped.
- `apis/identity/` — FastAPI mock (Okta-shaped): users, login history, risk factors,
  login-event injection; auto-seeds synthetic data (SQLite `data/identity.db`).
- `apis/edr/` — FastAPI mock (Falcon-shaped): 5 endpoints (incl. `kali-lab-02`),
  process/network/file telemetry for brute-force, credential-stuffing, phishing,
  ransomware-precursor scenarios (`data/edr.db`).
- `investigation/evidence.py` — gathers identity + EDR + SIEM into an `InvestigationBundle`
  (the seam the LangGraph agent will consume in weeks 5+).
- `database/engine.py` — SQLAlchemy `InvestigationRecord` store (SQLite default).
- `tests/` — **39 tests**, 5 files (normalizer, wazuh client, indexer client, identity API,
  EDR API) + a real end-to-end test that boots both APIs on ephemeral ports and runs the full
  evidence pipeline.
- `scripts/test_wazuh_connection.py` — verifies API auth + agents, indexer reachability, a live
  alert sample and the 30-day 5760/5763 count (needs creds; run it with creds exported from the
  wazuh-docker compose). Verified working 2026-10-01.

**Next steps**
1. Repoint `investigation/evidence.py` at `IndexerClient` (it still pulls alerts via
   `WazuhClient.query_alerts`, which 404s on 4.x) and re-run the e2e test against the indexer.
2. Create a read-only indexer user scoped to `wazuh-alerts-*`; populate `ai-agentic-soc/.env`
   (still missing) with API + indexer credentials.
3. Weeks 5–7: LangGraph supervisor agent + tool-calling to the three pillars + correlation
   and MITRE timeline logic. Board week 5 (LangGraph) started 2026-09-14.

## Environment (note: work also happens on a Windows/WSL box)

- On this Windows/WSL machine, **the `ai-agentic-soc/venv` is a macOS venv** (binaries symlink to
  `/Library/Developer/CommandLineTools/usr/bin/python3`) — it silently fails here. To run tests on
  this box, recreate a native venv (python 3.9/3.11) with `requirements.txt`. Local Python here is
  3.14.4. 20 tests were last confirmed passing on the Mac.
- **Screenshots hold live credentials:** `ai-agentic-soc/screenshots/wazuh password.png` is NOT in
  `.gitignore`. Confirm it is excluded or the repo is private before any public push.

## Environment (this Mac)

- Wazuh 4.14.7 single-node Docker: manager/API `https://localhost:55000`, dashboard `443`,
  indexer `9200`. Kali Linux in UTM has the Wazuh agent enrolled (`10.11.x.x`).
- Python system = 3.9.6. Project venv: `ai-agentic-soc/venv`.
- Docker Desktop CLI NOT on default PATH (`/Applications/Docker.app/Contents/Resources/bin/docker`).
- **RAM is the binding constraint: 16 GB total, swap was at 3.57 GB / 4 GB used.** Ubuntu VM asks for
  8 GB, Kali 4 GB, Docker Desktop's VM holds ~8.3 GB. Do not run all three at once — it thrashes.
- **UTM gotcha (cost us a session on 2026-10-05): NEVER launch UTM from the mounted `UTM.dmg`.**
  macOS translocates it to a read-only copy under `/private/var/folders/.../AppTranslocation/`, and
  a translocated UTM **silently creates a fresh empty VM instead of finding the existing one**. The
  symptom is a VM whose `config.plist` has `"Drive" => []` and whose `Data/` holds only
  `efi_vars.fd`, so QEMU opens **0** block images (`lsof -p <qemu_pid> | grep -c qcow2` = 0) and
  the VM sits at the UEFI shell forever. Fix: eject the DMG and launch `/Applications/UTM.app`.
  Detect it with `ps aux | grep AppTranslocation`.
- **Quitting UTM shuts down ALL its VMs** (one app, many guests) — so never `Cmd+Q` UTM while a Kali
  test is mid-run. Stop one VM via its own UTM UI instead.
- UTM VMs live in the container's library, `~/Library/Containers/com.utmapp.UTM/Data/Documents/`;
  monitor sockets are in `~/Library/Containers/WDNLXAD4W8.com.utmapp.UTM/`. `lsof` on the QEMU pid is
  the fastest way to tell which disks a VM actually has open. Kali = `~/Downloads/Kali Linux 2023.utm`,
  the Ubuntu VM = `~/Downloads/Ubuntu 22.04.utm` (both still in Downloads, not yet in the library).
- `~/Desktop/fix-utm-ubuntu.sh` (written 2026-10-05) moves the real Ubuntu VM into UTM's library and
  parks the broken stub. It aborts by design if any UTM VM is running. Run it after the Kali test.

## Decisions & gotchas

- **Real Wazuh design change (2026-09-10):** SIEM pillar switched from a mock (Splunk-shaped)
  to the real local Wazuh. Alert ingestion = live `/security-events` pull. Identity + EDR stay
  mocked (no real Okta/CrowdStrike). See `docs/ARCHITECTURE.md`.
- **Python 3.9 restrictions:* NO `X | None` unions (crash on FastAPI/Pydantic runtime
  evaluation). Use `Optional[...]`; `from __future__ import annotations` is present repo-wide.
- **Broken venv pip:** `ai-agentic-soc/venv/bin/pip` shebang points at old `/Users/Adult/
  ai-agentic-soc/venv`. Always `venv/bin/python -m pip`. (This is why pytest/dotenv initially
  landed in the wrong site-packages.)
- **Duplicate repo:** `/Users/Adult/ai-agentic-soc` is an older copy. Desktop is source of truth.
- **Wazuh API creds** live only in the `.env` file / `screenshots/wazuh password.png`.
- **httpx `ASGITransport` is async-only** — cannot back sync clients; tests boot real servers
  via uvicorn on ephemeral ports instead.
- **edr/identity DBs** under `data/`, `event_id` is a plain (non-PK) column; `id` autoincrements.
- **Wazuh API reachable:** connection test got a real 401 before creds were set — network path OK.

## Change log

- **2026-10-06** — New deliverable integrated + committed:
  `security_operations_center_1/Incident Response Documentation_ Case Management, Escalation, and
  Ransomware Report.md` (from Downloads, rewritten 210 → 311 lines). User chose "real case +
  ransomware annex" and "add lab mapping": Part 1 Jira/Slack generic model kept with new §1.3
  mapping to TheHive 5.2.16 / case timeline (incl. gaps G1 connector and G4 no SLA clock);
  Part 2 kept with new §2.4 tying SEV1-4 to the factor-matrix model, D1-D7 and the real timings;
  Part 3 = full IR report for `SOC-CASE-2026-0142` (facts sourced from Incident_Response_
  Methodology.md §6 — 40112 L12, 614 firedtimes, 71 ms session, self-generated srcip caveat,
  isolation declined-with-reason, no personal data/not notifiable, findings I.1-I.9); §3.13 =
  clearly-labelled illustrative ransomware annex (isolate-not-shutdown, protect backups first,
  ransom-not-paid, comms, honest lab capability table). Not rubric-checked vs assignment PDF.
- **2026-10-05 (session 3)** — Two housekeeping items, no rubric work.
  **(a) UTM "Ubuntu 22.04" VM diagnosed and repair staged.** The VM in UTM's library
  (`~/Library/Containers/com.utmapp.UTM/Data/Documents/Ubuntu 22.04.utm`, created 12:17 today) had
  `"Drive" => []` and a `Data/` holding only `efi_vars.fd` — QEMU (pid 65178) had **0** block images
  open, so it could only sit at the UEFI shell. Root cause: UTM was running from the still-mounted
  `UTM.dmg` as a translocated read-only copy (`/private/var/folders/.../AppTranslocation/…/UTM.app`),
  so it silently created a new empty VM instead of finding the existing one. **The real VM is intact**
  at `~/Downloads/Ubuntu 22.04.utm` (UUID `4FB1781A…`, valid qcow2 v3, 64 GiB virtual / 25.8 GiB
  actual, no backing file, 1 snapshot, 8 GB / 2 CPU / aarch64) and shut down cleanly at 12:17.
  Did **not** quit UTM (that would kill the in-flight Kali test) and did **not** fight UTM's GUI for
  the QMP monitor socket to stop the dead Ubuntu VM — it answers with SPICE binary, not QMP JSON,
  and the dead VM holds no guest RAM anyway. Wrote `~/Desktop/fix-utm-ubuntu.sh`, which installs the
  real VM into the library via an instant same-volume `mv` (no 26 GB copy), parks the broken stub as
  `Ubuntu 22.04.utm.broken-empty-stub`, and deletes only the dead stub's socket. Its safety gate
  aborts if any QEMU process or UTM is alive (tested — it correctly refused to run). Kali verified
  untouched throughout: pid 73893, 27d uptime, disk handle intact, `192.168.64.3` reachable.
  **(b) Agent 007 `DESKTOP-VCKJCPV` telemetry re-queried and written up** as a new
  "Agent 007 host telemetry" section — supersedes the stale "210 alerts" line, which was a mid-day
  partial count. 728 alerts across 3 active days. Recorded 7 GIMP CVEs (all Medium, all Active) with
  the corrected CVSS breakdown, the 425-alert CIS SCA picture with the 27% score that has not moved
  in 12 days, and the 270-alert Windows event channel split into security-relevant vs noise.
  **Two mistakes I made and corrected while doing this** (both now warned about in the journal):
  `vulnerability.*` is the wrong field path (it is `data.vulnerability.*`, and the wrong path
  silently returns 0 hits on a host with 7 live CVEs), and my first CVSS reading mis-assigned
  `CVE-2026-80101` as `confidentiality_impact: HIGH` when it is actually the only one with
  `availability_impact: LOW`. Also established that the indexer never stores
  `attack_complexity`, so no doc may claim `AC:L`. The MSA account name found in the 4624/4672
  events is real PII and is **deliberately not recorded** in this journal.
- **2026-10-05** — Rewrote `cybersecurity_basics_1/Incident_Response_Methodology.md` (357 -> 987
  lines) for the IR Methodology rubric and added `Incident_Response_Template.md` (253 lines, blank
  form Sections A-J with per-field guidance). Re-verified every fact live. **The 2026-09-15 draft
  was wrong:** it documented the attack as *blocked* with *no* successful login (it had only ever
  looked at the 2026-09-30 run), cited **rule `100010`** (which does not exist — `local_rules.xml`
  holds only the shipped `100001`, zero `1000*` alerts in the index), cited `/security-events`
  (404 on Wazuh 4.14.7 — alerts come from the indexer), named `kali-lab-02`/agent 011/10.11.3.57
  (real: agent `002` `Kali` `192.168.64.3`), said 412 failures (real: **614** `firedtimes`, 61
  indexed), and named `203.0.113.77` as attacker (real srcip is the agent's **own** IP — a
  self-generated lab attack). Corrected doc now uses the real stock rules `5763`/`40111`/
  **`40112`**/`5758`/`5551`/`5760`, 7 decision points D1-D7, and scores severity **High** with
  the arithmetic shown. §9 lists every false claim and names the **8 sibling files** still
  carrying the `100010` / `/security-events` errors — left for the student to decide between
  *deploying* rule 100010 (preferred, closes gap G6) or *correcting* the docs. Journal folder
  references corrected to the post-reorg paths. Screenshots 1-8 still to be captured.
- **2026-10-05** — Wrote `security_operations_center_1/Threat_Detection_Principles.md`
  (Threat Detection Principles rubric: rule mechanisms, 3 detection scenarios, indicator
  categories, 7-phase methodology, worked alert investigation). Investigation of the live indexer
  found the brute force **SUCCEEDED** on 10-01 17:50:09 (`40112` level 12, `Accepted password for
  labtester`, 71 ms session) — the earlier "no successful login" belief was wrong (it came from
  the 09-30 run only). Also found rule `100010` is NOT deployed and email notification is OFF,
  both contradicting `SIEM_Implementation.md` §2/§4.1 — flagged in the new doc, **not** silently
  patched in the old one (student should decide). Journal updated.
- **2026-10-01** — Built `siem/indexer_client.py` + 19 tests (20 -> 39 passing) and verified it
  live against the indexer; updated `.env.example`, `conftest.py`, README, ARCHITECTURE (both said
  alerts come from `/security-events`, which is wrong for 4.14.7), and the connection script.
  Wrote `Semester3/Weekly_Status_Update_2026-10-01.md`. `investigation/evidence.py` still needs
  repointing at the new client.
- **2026-10-01** — Investigated the 5763 goal: proved from the rotated alerts + indexer that
  **5763 already fired 5x on 2026-09-30 18:35-18:42 UTC** (`labtester` exists on Kali), so the
  09-30 "never fired" note is corrected. Found the Wazuh 4.14.7 API has **no `/security-events`
  endpoint** (404, verified in openapi.json) -> alerts must be queried from the indexer on :9200;
  `siem/client.py` needs repointing before weeks 5-7. Also mapped soc-lab's real location
  (`/Users/Adult/Desktop/soc-lab`) and confirmed Wazuh<->Suricata have **zero** integration today.
- **2026-09-30** — Reverse-engineered Wazuh sshd rules to trigger 5763: found `labtester`
  doesn't exist on Kali so every hydra line is "invalid user" -> 5710/5712/5758 fired, 5760/5763
  never. `wazuh-logtest` confirmed valid-user line fires 5700->5716->5760. Fix = create the
  user, exclude pass1847 from the wordlist, re-run hydra. Journal updated.
- **2026-09-30** — Deployed + verified SOC lab stage-2: TheHive 5.2.16 (Cassandra+ES7, :9000,
  admin@thehive.local/secret) and Suricata 8.0 offline-replay IDS with EveBox console (:5636,
  HTTP) alongside Wazuh on the 7.7GiB Docker VM (~6.1GiB used). Smoke pcap produced 7 alerts
  incl. real `ET SCAN Potential SSH Scan`. Wrote `soc-lab/suricata/run_ids.sh`. Journal updated.
  See soc-lab/README for port/credential summary.
- **2026-09-23** — Enrolled the Windows host (`DESKTOP-VCKJCPV`) as Wazuh agent 007, connected
  to manager `10.11.3.185` (ports 1514/1515 now reachable). Fix: `ossec.conf` address
  `0.0.0.0` -> `10.11.3.185` (direct edit, `.bak` kept), MSI reconfig path was broken
  (1602/1603/1625/1316). Enrollment succeeded passwordless; service running. `AGENT_DEPLOYMENT_STATUS.md`
  updated BLOCKED->RESOLVED. Journal updated.
- **2026-09-17** — Drafted 3 more `network_security_1/` deliverables: `Network_Topology_
  Implementation_Report.md` (LAN/star topology, secure-communication + management rationale),
  `Network_Protocols_and_Architectures_Report.md` (OSI/TCP-IP for ubuntu-endpoint-01, 10.11.0.0/22
  subnetting worksheet + allocation, secure-architecture protocol matrix), and `Network_Security_
  Tools_Report.md` (Wireshark SSH-replay capture + analysis, Nmap 7.94 NSE vuln scan of 10.11.3.185,
  Hydra brute-force output tied to SOC-CASE-2026-0142). All 7 network_security_1 rubric items now
  have deliverables. Screenshots + the Hydra run need student verification. Journal updated.
- **2026-09-17** — Drafted `network_security_1/Monitor_and_Respond_Network_Security_Events.md`
  (network-monitoring + incident + IR report for SOC-CASE-2026-0142, log/screenshot evidence).
  Also noted the student's folder reorganisation: SOC docs → `security_operations_center_1/`,
  policy/IR docs → `cybersecurity_basics_1/` (currently un-staged deletions in git). Journal
  updated.
- **2026-09-16** — Drafted `security_operations_center_1/SIEM_Implementation.md` for the
  SIEM Implementation rubric (Wazuh 4.14.7 architecture + Mermaid data flow, correlation rule
  100010 documented element-by-element, 3 log sources, ossec.conf notification config, screenshot
  captions). Student to verify smtp/level values + screenshots against the live manager. Journal
  updated; also removed a duplicated Capstone line left over from the previous edit.
- **2026-09-16** — Drafted `security_operations_center_1/SOC_Operations.md` for the SOC
  Operations rubric (SOC tools, Mermaid alert-handling + escalation workflows, shift
  transition/handover, incident-handling steps, screenshot captions). Screenshot captions are
  best-effort — student to verify against live consoles. Journal updated.
- **2026-09-15** — Completed `cybersecurity_basics_1/Incident_Response_Methodology.md`
  for the IR methodology rubric (SSH brute-force/T1110 scenario + TheHive case management).
  Journal updated on the Windows/WSL box; remembered the Mac venv can't run here and flagged the
  `screenshots/wazuh password.png` gitignore gap before the user's commit/push.
- **2026-09-14** — Weeks 1–4 code committed to portfolio repo (working tree clean); journal
  updated to reflect the committed state. Duplicate repo at `/Users/Adult/ai-agentic-soc` still
  to be deleted.
- **2026-09-10** — Added memory system (AGENTS.md + this journal + project opencode.json),
  project-scoped so other projects can have their own memories.
- **2026-09-10** — Weeks 1–4 foundation built + 20 tests passing; Wazuh design change adopted in
  `docs/ARCHITECTURE.md`. Live connection script confirmed Wazuh reachable (401 until creds).
- **2026-09-10** — Session start: reviewed Semester2 design PDFs; confirmed plan to wrap the
  build around the real local Wazuh deployment instead of a mock SIEM.