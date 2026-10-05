# PROJECT — Living Memory Journal

Owner: Kyrell Green — 6-month cybersecurity program (SOC/security analyst track).
This journal is loaded every session in this workspace via `opencode.json` `instructions`.
Update it per the rules in AGENTS.md. NEVER store secrets/passwords/API keys here.

---

## Current status

**Latest (2026-10-05, 2nd pass): `cybersecurity_basics_1/Incident_Response_Methodology.md`
REWRITTEN (987 lines) + new `cybersecurity_basics_1/Incident_Response_Template.md` (253 lines)
for the Incident Response Methodology rubric.** The 2026-09-15 draft was factually wrong and has
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
- Windows agent 007 `DESKTOP-VCKJCPV` has 210 alerts on 10-05 (61104 x20, 60110 x4, 60132 x7,
  23504 CVE-2026-82328 GIMP x7, 510 rootcheck NTFS ADS x3) — usable as host-state detection examples.

**Other detection-layer gaps logged as G1-G8** (see doc §5.8): no notification path; 100010 not
deployed; `40112` silently depends on `5715`'s group tag; duplicate level-10 rules (5763+40111);
flood alert unactioned; **password spraying undetectable (all rules are `same_source_ip`)**; no
live Suricata->Wazuh integration; endpoint visibility is journald-only (no process telemetry, so
"no post-access activity" is scope-bounded).

**Also still open from before:** Suricata `ET SCAN Potential SSH Scan` sid 2001219 confirmed from
`soc-lab/suricata/output/eve.json` (2 alerts, 203.0.113.77 -> 192.168.64.3:22, `action: allowed`,
sev 2). Note the replayed pcap carries synthetic 2002-08-28 timestamps (scapy-generated) — say so
rather than presenting them as real packet times.

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