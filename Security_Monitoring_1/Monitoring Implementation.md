# Monitoring Implementation

**Project:** AI-Agentic SOC Triage & Investigation Engine
**Author:** Kyrell Green
**Platform:** Wazuh 4.14.7 single-node Docker (manager / indexer / dashboard / API) + Suricata 8.0
**Monitored fleet:** 3 OS endpoints — Kali `002`, Windows 10 `007`, Ubuntu 22 `008` (all `active`)
**Source rubric:** *monitoring implementation* — (a) a monitoring **architecture diagram** showing
components and data flows, and (b) **≥3 different data sources integrated with evidence of
successful data collection**.

> All rule IDs, levels, timestamps and counts below were read from the **live lab indexer**
> (`https://localhost:9200`, index pattern `wazuh-alerts-4.x-*`) via the Wazuh API
> (`/agents`), not reconstructed from memory.

---

## Rubric Coverage

| Rubric requirement | Where addressed |
|---|---|
| Implementation of a monitoring **architecture diagram** showing components and data flows | §2 (component diagram §2.2, component inventory §2.3, end-to-end data flow §2.4) |
| **≥3 different data sources integrated** with **evidence of successful data collection** | §3 (DS-1 Windows events, DS-2 Linux auth, DS-3 File integrity + bonus telemetry) |
| Evidence captured (screenshots / query results) | §4 |

---

## 1. Scope & What Was Implemented

A working, **live** monitoring platform was implemented on the lab host — not a mock or a design
on paper. It comprises:

- a **Wazuh 4.14.7** SIEM (manager + indexer + dashboard + REST API) running in Docker;
- **three enrolled endpoint agents** across three operating systems, each **`active`** (verified
  via the API `/agents` endpoint);
- a **network IDS** (Suricata 8.0) deployed alongside it, and
- a downstream **triage engine** that consumes alerts directly from the Wazuh indexer.

| Layer | Component | Version | Status |
|---|---|---|---|
| Collection | Wazuh agent — Kali `002` | 4.14.7 | active / connected |
| Collection | Wazuh agent — Windows `007` | 4.14.7 | active / connected |
| Collection | Wazuh agent — Ubuntu `008` | 4.14.7 | active / connected |
| Analysis | Wazuh Manager | 4.14.7 | running |
| Storage | Wazuh Indexer (OpenSearch 2.x) | — | running |
| Presentation | Wazuh Dashboard | — | running |
| Integration | Wazuh API (JWT) | 4.14.7 | running |
| Network sensor | Suricata + EveBox | 8.0 | running (offline replay) |

---

## 2. Monitoring Architecture — Components & Data Flows

### 2.1 One-line architecture

**Agents** on each endpoint collect local telemetry → stream it **encrypted** to the **Manager**,
which **decodes, normalises and correlates** it against the ruleset → every event/alert is stored
in the **Indexer** → both the **Dashboard** (human) and the **REST API** (machine) read from the
Indexer → the **triage engine** pulls detections from the Indexer and raises **TheHive** cases.

### 2.2 Architecture diagram (components + data flows)

```mermaid
flowchart TB
    subgraph EP["Monitored endpoints — Wazuh agents"]
        K["Kali Linux — agent 002<br/>192.168.64.3<br/>auth.log + FIM + syscollector"]
        W["Windows 10 — agent 007<br/>10.11.1.232<br/>EventChannel + FIM + rootcheck + VD/SCA"]
        U["Ubuntu 22.04 — agent 008<br/>192.168.64.2<br/>auth + FIM"]
    end

    subgraph WZ["Wazuh 4.14.7 — single-node Docker"]
        MGR["Wazuh Manager<br/>decoders + analysisd ruleset<br/>correlate + alert"]
        IDX["Wazuh Indexer — OpenSearch<br/>wazuh-alerts-*  :9200"]
        DASH["Wazuh Dashboard  :443"]
        API["Wazuh API  :55000  JWT"]
        ARE["Active Response<br/>firewall-drop (configured)"]
    end

    ENG["Triage engine<br/>IndexerClient — httpx"]
    TH["TheHive 5.2.16  :9000<br/>case management"]
    SUR["Suricata 8.0 + EveBox  :5636<br/>network IDS — offline replay"]

    K -->|"TCP 1514 — encrypted events"| MGR
    W -->|"TCP 1514 — encrypted events"| MGR
    U -->|"TCP 1514 — encrypted events"| MGR
    K -.->|"TCP 1515 — enrollment"| MGR
    W -.->|"TCP 1515 — enrollment"| MGR
    U -.->|"TCP 1515 — enrollment"| MGR
    MGR -->|"events + alerts"| IDX
    MGR -.->|"level >= threshold"| ARE
    ARE -.->|"block source IP"| K
    IDX --> DASH
    IDX -->|"POST wazuh-alerts-*/_search"| ENG
    API --> IDX
    ENG -->|"high-severity case"| TH
    SUR -.->|"eve.json — PLANNED, not yet wired"| MGR
```

**Legend:** solid arrows = implemented, working flow · dotted arrows = configured/partial or
planned (stated honestly).

### 2.3 Component inventory — functions & relationships

| Component | Where it runs | Core function | Its relationship in the flow |
|---|---|---|---|
| **Wazuh agent** (×3) | Each endpoint | Collects local logs, file-integrity data, rootcheck, vulnerability/SCA/inventory data; streams it to the manager over an encrypted channel | **Source tier** — without it the SIEM is blind to the endpoint |
| **Decoders** | Manager | Parse raw unstructured log lines into structured fields (`srcip`, `dstuser`, `full_log`, `win.eventdata`) | **Transform** — the prerequisite for any rule logic |
| **Ruleset / `analysisd`** | Manager | Apply signature, frequency and composite rules; assign level, groups, MITRE tags; **generate alerts** | **Detection tier** — the raw event becomes a *security alert* only here |
| **Active Response** | Manager → agent | Run a scripted response (e.g. `firewall-drop`) on a matching rule | **Response tier** — present but **currently disabled** (documented) |
| **Wazuh Indexer** | Docker | Store + index all events/alerts in `wazuh-alerts-*` (OpenSearch) | **Storage tier** — the book of record; single source both consumers read |
| **Wazuh Dashboard** | Docker | Human console: security events, agents, rules | **Presentation** — reads the indexer |
| **Wazuh API** | Docker | JWT-authenticated REST access to agents/rules/status | **Integration seam** — consumed by tooling |
| **Triage engine** | Lab host | Pulls detections from the indexer, normalises Wazuh alerts to an internal schema, correlates evidence, produces a report behind a human approval gate | **Consumer** — the project's own agent |
| **TheHive** | Docker | Case management for escalated alerts | **Downstream consumer** |
| **Suricata + EveBox** | Docker | Network IDS; writes `eve.json` alert records | **Network sensor — not yet integrated into Wazuh** |

### 2.4 End-to-end data flow (with ports/protocols)

```
1. COLLECT   Endpoint agent reads local sources
             Linux  : /var/log/auth.log, journald, syscheck(FIM), syscollector
             Windows: Security + Application event channels, syscheck(FIM),
                      rootcheck, vulnerability detector, SCA
                                │
2. SHIP      Wazuh agent ──TCP 1514 (encrypted, libsodium)──► Wazuh Manager
             (enrollment  ──TCP 1515──►  Manager, passwordless in this lab)
                                │
3. DECODE    Manager decoders  raw log line ──► structured fields
             Linux  : sshd decoder  ──► data.srcip / data.dstuser / full_log
             Windows: eventchannel  ──► data.win.system / data.win.eventdata
                                │
4. DETECT    analysisd matches the ruleset in real time
             single-event (signature)  ─► frequency (correlation) ─► composite (state)
             e.g. 5716 ─► 5760 ─► 5763 ;  plus 40111 / 40112
                                │
5. STORE     Manager ──► Wazuh Indexer (OpenSearch :9200)  index wazuh-alerts-*
                                │
6. PRESENT   Indexer ──► Wazuh Dashboard (:443)          [human analyst]
             Indexer ──► Wazuh API (:55000, JWT)          [machine]
                                │
7. CONSUME   Triage engine  POST /wazuh-alerts-*/_search  ──► normalise ──► correlate
             high-severity alert ──► TheHive case (:9000)
                                │
8. RESPOND   (Active Response firewall-drop — configured but currently DISABLED;
              containment in this lab is a human-approved action only)
```

### 2.5 Network / address layout

| Path | Address / port | Protocol | Purpose |
|---|---|---|---|
| Agent `002` → Manager | `192.168.64.3` → `192.168.64.1` | TCP 1514/1515 | Kali events + enrollment |
| Agent `008` → Manager | `192.168.64.2` → `192.168.64.1` | TCP 1514/1515 | Ubuntu events + enrollment |
| Agent `007` → Manager | `10.11.1.232` → `10.11.3.185` | TCP 1514/1515 | Windows events + enrollment |
| Dashboard | `:443` | HTTPS | Analyst console |
| Indexer | `:9200` | HTTPS (self-signed) | Alert storage / queries |
| Wazuh API | `:55000` | HTTPS + JWT | Engine integration |
| Suricata/EveBox | `:5636` | HTTP (no auth) | Network IDS console |

Manager addresses: `192.168.64.1` for the UTM VMs (Kali/Ubuntu) and `10.11.3.185` for the
Windows host. Enrollment is passwordless in this lab; each agent's `ossec.conf` `<address>` was
set explicitly (**never** `0.0.0.0` — that was the original cause of the Windows agent failing to
start).

---

## 3. Integrated Data Sources & Evidence of Successful Collection

**Four data-source classes are integrated into Wazuh**, each with production evidence in the
indexer. The requirement (≥3) is exceeded.

| ID | Data source | Integrated endpoints | Integration mechanism | Telemetry collected |
|---|---|---|---|---|
| **DS-1** | **Windows endpoint event logs** | agent `007` | Wazuh Windows agent v4.14.7 → Manager TCP 1514 | Security + Application event channels, FIM, rootcheck |
| **DS-2** | **Linux endpoint auth / system logs** | agents `002`, `008` | Wazuh Linux agent → Manager TCP 1514 | `sshd`/`pam` authentication, `sudo`, journald |
| **DS-3** | **File-integrity monitoring (FIM)** | agents `002`, `007`, `008` | Wazuh `syscheck` module + `rootcheck` | file add/modify/delete, hashes, attributes, ADS |
| **DS-4** | **Vulnerability detection & SCA** | agent `007` | Wazuh VD + SCA modules | CVE inventory, CIS benchmark checks |

### 3.1 DS-1 — Windows endpoint event logs (agent `007`, `DESKTOP-VCKJCPV`)

| Attribute | Detail |
|---|---|
| Endpoint | Windows 10 Home, build `10.0.19045.6466`, agent `007`, `10.11.1.232` |
| Integration | v4.14.7 agent installed at `C:\Program Files (x86)\ossec-agent`; connected to manager `10.11.3.185` on TCP 1514 |
| Collection | Windows Security + Application **event channels** (forwarded as `data.win.system`/`data.win.eventdata`) |

**Evidence of successful data collection** — `007` has **728 indexed alerts across 3 active
days** (09-23: 437, 09-29: 42, 10-05: 248); **270** are Windows event-channel alerts:

| Rule | Level | Windows event | Observed | Interpretation |
|---|---|---|---|---|
| `60110` | 8 | **4738** "A user account was changed" | 8× on 2026-10-05 (`15:33:12`–`17:31:08`) | Account-change telemetry landing; subject = SYSTEM, target = local user `Kai` |
| `61138` | 5 | **7045** New Windows Service Created | 4× (09-29 `GoogleUpdater`, 10-05 WSL installer) | Service-creation telemetry landing (benign, attributable) |
| `67022` | 3 | **4624** Logon | 16× | Interactive sign-in telemetry landing |
| `61104` | 3 | **7040** Service startup type changed | 31× (27 on 10-05) | Service-config telemetry landing |
| `60132` | 5 | **4616** System time changed | 10× (all `svchost.exe`) | Clock-change telemetry landing (benign resync) |
| `61110` | 10 | **10010** DCOM server time-out | 3× | `level != severity` example — benign noise at level 10 |

> **Verification note:** for Windows event-channel alerts `full_log` is empty; the payload lives
> in `data.win.system` / `data.win.eventdata`. This is a genuine collection characteristic of the
> channel, not missing data.

### 3.2 DS-2 — Linux authentication / system logs (agents `002` Kali, `008` Ubuntu)

| Attribute | Detail |
|---|---|
| Endpoints | Kali `002` (`192.168.64.3`) + Ubuntu `008` (`192.168.64.2`), both aarch64 |
| Integration | Linux agent → manager `192.168.64.1`, TCP 1514/1515; auth sourced from `/var/log/auth.log` + journald |
| Collection | `sshd`/`pam` authentication (success + failure), `sudo` authorisation |

**Evidence of successful data collection** — the authentication chain decoded and correlated the
2026-10-01 SSH brute force on agent `002` end-to-end:

| Rule | Level | `full_log` (verbatim) / metric | When |
|---|---|---|---|
| `5760` | 5 | `Failed password for labtester from 192.168.64.3 port 49024 ssh2` — **61 indexed, `firedtimes` 614** | 17:48:26 → 17:50:07 |
| `5763` | 10 | `sshd: brute force trying to get access to the system` — `firedtimes` 92 | 17:48:31+ |
| `5503` → `5551` | 5 → 10 | `pam_unix(sshd:auth): authentication failure` (PAM branch) | 17:49–17:50 |
| `40111` | 10 | cross-rule failure volume | 17:48:44+ |
| **`40112`** | **12** | `Accepted password for labtester from 192.168.64.3 port 49024 ssh2` | **2026-10-01T17:50:09.931Z** |
| `5501`/`5502` | 3 | `session opened/closed for user labtester(uid=1001)` → **71 ms** session | 17:50:09.931 / :10.002 |
| `5402` | 3 | `sudo … COMMAND=/usr/bin/passwd labtester` | 17:46:11 |

Agent `008` (Ubuntu 22) was enrolled 2026-10-06 and confirmed **`active`** via API `/agents`,
extending auth-log coverage to a second Linux host.

### 3.3 DS-3 — File-integrity monitoring (FIM / syscheck + rootcheck)

| Attribute | Detail |
|---|---|
| Endpoints | agents `002` (Kali), `007` (Windows), `008` (Ubuntu) |
| Integration | Wazuh `syscheck` (baseline + diff) and `rootcheck` (host anomaly) modules |
| Collection | file added/modified/deleted with `md5`/`sha1`/`sha256`, size, mtime, inode; ADS + host anomalies |

**Evidence of successful data collection:**

| Rule | Level | Observed event | Endpoint |
|---|---|---|---|
| `550` | 7 | `File '/etc/shadow' modified … Mode: scheduled` | `002` — 2026-10-02T03:54:17Z |
| `550` | 7 | `File '/etc/shadow-' modified … Size changed from '1385' to '1405'` | `002` — 2026-10-01T03:52:52Z |
| `510` | 7 | `NTFS Alternate data stream found: 'C:\Program Files\Intel…2D Imaging:Win32App_1'` | `007` — 12× across 3 days |

Both `/etc/shadow` FIM alerts were **attributed** to the authorised `5402` `passwd labtester`
command — a demonstration that FIM collection plus an authorisation control resolves a
would-be false positive.

### 3.4 DS-4 (bonus) — Vulnerability detection & SCA (agent `007`)

| Rule | Level | Evidence |
|---|---|---|
| `23504` | 7 | **7 CVEs** detected (all GIMP 3.2.40.0, all Medium, all `Active`) in a single **70 ms** burst at `2026-10-05T15:36:57.109`–`.178Z` — e.g. `CVE-2026-82328` |
| `19005` | 9 | SCA summary: *"CIS Microsoft Windows 10 Enterprise Benchmark v4.0.0: Score less than 30% (27)"* — fired 3× |
| `19007`/`19008`/`19009` | 7/3/3 | 425 SCA checks: **304 failed, 116 passed, 5 n/a** → score **27%** |

### 3.5 Network IDS — deliberately **not** counted as integrated (honest gap)

| Attribute | Detail |
|---|---|
| Sensor | Suricata 8.0 + EveBox, `soc-lab/suricata/` |
| State | Runs **offline pcap replay**; writes `eve.json`; **no Wazuh integration** (`0475-suricata_rules.xml` present but not enabled) |
| Observed | `ET SCAN Potential SSH Scan` (`sid 2001219`, sev 2, `action: allowed`) — 2 alerts from a synthetic pcap (2002 timestamps) |

It corroborates a scenario but is **not** a live, Wazuh-integrated source, so it is excluded from
the "integrated data sources" count above.

### 3.6 Evidence-of-collection summary (the required proof)

| Data source | Integration proof | **Evidence of successful collection** (from the live indexer) |
|---|---|---|
| DS-1 Windows events | agent `007` active, TCP 1514 | **270** event-channel alerts; rule `60110` (event 4738) fired 8× on 2026-10-05 |
| DS-2 Linux auth | agents `002`/`008` active, TCP 1514 | **`40112` L12** at `2026-10-01T17:50:09.931Z`; 61× `5760`; `5763` `firedtimes` 92 |
| DS-3 File integrity | syscheck+rootcheck on `002`/`007`/`008` | rule `550` on `/etc/shadow` `2026-10-02T03:54:17Z`; `510` ADS 12× |
| DS-4 Vuln/SCA (bonus) | VD + SCA modules on `007` | **7 CVEs** (`23504`) at `2026-10-05T15:36:57Z`; **425** SCA checks (`19005`–`19013`) |
| Fleet | 3 OS agents | all reported **`active`** by API `/agents` |

---

## 4. Evidence Captured (screenshots)

> Paths are relative to this document's location (`Security_Monitoring_1/`).

### 4.1 Deployment, connectivity & agent fleet (collection layer)

![Wazuh agent deployment](../DAE-6-Month-Project-Files/ai-agentic-soc/screenshots/agent%20deployment.png)
*Agent enrollment — the endpoint connecting to the manager over the Wazuh agent protocol.*

![Wazuh agents list](../DAE-6-Month-Project-Files/ai-agentic-soc/screenshots/agent%20deployed.png)
*Agent fleet view — the enrolled endpoints shown Active/Connected.*

![Ping to monitored endpoint](../DAE-6-Month-Project-Files/ai-agentic-soc/screenshots/Ping.png)
*ICMP reachability to a monitored endpoint — network configuration verified.*

![SOC test server](../DAE-6-Month-Project-Files/ai-agentic-soc/screenshots/SOC%20Test%20Server.jpg)
*The host running the Wazuh stack (manager/indexer/dashboard).*

![Wazuh admin credential](../DAE-6-Month-Project-Files/ai-agentic-soc/screenshots/wazuh%20password.png)
*Manager/dashboard access configuration.*

### 4.2 Evidence of data collection & rule triggering (DS-1, DS-2, DS-3)

![Wazuh MITRE ATT&CK brute-force detection](../DAE-6-Month-Project-Files/security_operations_center_1/Wazuh%20Mitre%20Att%26ck%20BF%20detection.png)
*Security Events view — brute-force rule matched with MITRE ATT&CK T1110 (DS-2, agent 002).*

![Brute-force threat detection](../DAE-6-Month-Project-Files/security_operations_center_1/Brute%20Force%20Threat%20detection.jpg)
*Brute-force threat detection in the SIEM.*

![Brute-force threat detection 2](../DAE-6-Month-Project-Files/security_operations_center_1/Brute%20Force%20threat%20detection%202.jpg)
*Correlation / multiple failed-authentication events.*

![Successful-access compromise event](../DAE-6-Month-Project-Files/security_operations_center_1/Kali%20Brute%20Force%20Attack%20Access.png)
*The successful-authentication compromise event (`40112`, level 12).*

![Brute-force attack execution](../DAE-6-Month-Project-Files/security_operations_center_1/Kali%20Brute%20Force%20test.jpg)
*Brute-force attack execution against the monitored endpoint.*

![Windows host malware/anomaly scan](../DAE-6-Month-Project-Files/cyber_threats_and_vulnerabilities_1/Malware%20analysis%20sample%20scan.png)
*Host-based file/anomaly scan on the Windows endpoint (agent `007`) — DS-1/DS-3.*

### 4.3 Screenshot reference (paths)

| Evidence | Path (from repo root) |
|---|---|
| Agent deployment | `ai-agentic-soc/screenshots/agent deployment.png` |
| Agent fleet | `ai-agentic-soc/screenshots/agent deployed.png` |
| Connectivity (ping) | `ai-agentic-soc/screenshots/Ping.png` |
| SOC test server | `ai-agentic-soc/screenshots/SOC Test Server.jpg` |
| Wazuh admin credential | `ai-agentic-soc/screenshots/wazuh password.png` |
| MITRE BF detection | `security_operations_center_1/Wazuh Mitre Att&ck BF detection.png` |
| Brute-force detection | `security_operations_center_1/Brute Force Threat detection.jpg` |
| Brute-force detection (2) | `security_operations_center_1/Brute Force threat detection 2.jpg` |
| Successful access (`40112`) | `security_operations_center_1/Kali Brute Force Attack Access.png` |
| Windows host scan | `cyber_threats_and_vulnerabilities_1/Malware analysis sample scan.png` |

> **Placeholders / recommended captures.** `ai-agentic-soc/screenshots/UTM_Docker_Wazuh_Deployment.png`
> is a 0-byte placeholder. Strongest additional captures for submission: the Wazuh **Security
> Events** view filtered per agent (proving each source is live), the **Agents → Summary** page
> showing the 3-OS fleet `active`, and the **Vulnerability Detector / SCA** dashboards for agent
> `007`.

---

## 5. Honest Limitations (documented, not hidden)

| # | Limitation | Impact |
|---|---|---|
| L1 | **Active Response is disabled** (block commented out in `ossec.conf`) | Response is human-approved only; no automatic blocking today |
| L2 | **Email notification is OFF**; the **indexer** is the only working alert-delivery path | Alerts reach consumers via indexer/dashboard, not email |
| L3 | **Suricata is not integrated** into Wazuh (offline pcap replay) | Network source is corroboration, not live coverage — excluded from the integrated count |
| L4 | Endpoint visibility is **auth/journald-sourced** (no process/Sysmon telemetry on Linux) | "No post-access activity" means *no logged* activity |
| L5 | `007` has **no syscollector inventory** (`os.*` empty) | "What was running on the host" is not answerable from this data set |

---

## Companion Documents

| Document | Relevance |
|---|---|
| `Security_Monitoring_1/Monitoring Environment Setup.md` | Platform install, network config, 2 source types, 3 alert scenarios, notification workflow |
| `Security_Monitoring_1/Security Event Analysis.md` | Log-type interpretation, cross-source correlation, incident scenario, triage |
| `DAE-6-Month-Project-Files/security_operations_center_1/SIEM_Implementation.md` | SIEM component architecture + data-flow diagram, correlation rule, log sources |
| `DAE-6-Month-Project-Files/ai-agentic-soc/docs/ARCHITECTURE.md` | Wazuh as real SIEM + alert source; engine integration design |
| `DAE-6-Month-Project-Files/ai-agentic-soc/docs/AGENT_DEPLOYMENT_STATUS.md` | Windows agent `007` deployment & fix |
| `DAE-6-Month-Project-Files/security_operations_center_1/Threat_Detection_Principles.md` | Alert/rule mechanisms and worked investigation |

*Prepared from the live lab evidence in `DAE-6-Month-Project-Files`.*
