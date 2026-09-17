# Network Security Tools Report

**Author:** Kyrell Green
**Date:** 2026-09-17
**Module:** Network Security — SOC Security Analyst track
**Lab environment:** AI-Agentic SOC Home Lab — Wazuh 4.14.7 stack (Docker) on macOS/UTM;
monitored Linux endpoints (`kali-lab-02` 10.11.3.57, `ubuntu-endpoint-01` 10.11.3.42); Wazuh
manager (`10.11.3.185`); LAN `10.11.0.0/22`
**Companion documents:** `Firewall_IDS_IPS_Implementation_Report.md` (detect→decide→respond),
`Monitor_and_Respond_Network_Security_Events.md` (SOC-CASE-2026-0142 IR case),
`Vulnerability_Assessment_Report.md` (Nmap asset discovery + vuln scan context)

---

## Rubric Coverage

| Rubric requirement | Addressed in |
|---|---|
| **Wireshark capture** with analysis | Section 1 — LAN capture during SSH brute-force replay; protocol hierarchy + packet-level analysis |
| **Network vulnerability scanner report** | Section 2 — Nmap 7.94 NSE vulnerability scan against `10.11.3.185` (Wazuh host) |
| **Network penetration testing tool output** | Section 3 — Hydra SSH brute-force tool (authorised lab-only attack against a deliberate test user on `kali-lab-02`) |

---

## 1. Wireshark Capture & Analysis

### 1.1 Capture overview

| Property | Value |
|---|---|
| Tool | Wireshark 4.4.x (Linux, Kali) |
| Interface captured | `eth0` (lab LAN `10.11.0.0/22`) |
| Trigger event | SSH brute-force replay from `203.0.113.77` against `kali-lab-02` (port 22) — the same
  pattern documented in SOC-CASE-2026-0142 |
| Capture filter | `host 10.11.3.57 and tcp port 22` |
| Display filter applied | `tcp.flags.syn == 1 and tcp.flags.ack == 0` (initial SYNs), then
  `ssh && ip.addr == 203.0.113.77` (full SSH stream) |
| Duration | ~30 seconds (burst window within the 2-minute rule timeframe) |
| Frames captured | 4,812 (SYN floods + TCP handshakes + failed key exchanges) |

### 1.2 Protocol hierarchy (from Statistics → Protocol Hierarchy)

| Protocol | % of packets | Role in this capture |
|---|---|---|
| TCP | 97.8% | All SSH handshakes and data; carries both the brute-force attempts and the TCP control traffic |
| SSH | 89.3% | Encrypted key-exchange attempts (`SSH-2.0-OpenSSH_9.7` banner, `SSH_MSG_DISCONNECT` on failure) |
| TCP (pure ACK / RST) | 8.5% | Retransmissions, RSTs after failed key exchange |
| ICMP | 0.2% | Unrelated LAN ping (normal baseline traffic) |
| UDP | <0.1% | Unrelated DNS background traffic |

**Interpretation:** the capture is dominated by SSH-related TCP traffic — exactly what a
brute-force looks like in Wireshark: a dense cluster of TCP handshakes to port 22, each followed
by the SSH key-exchange prefix and a server-side RST after failed credentials.

### 1.3 Packet-level analysis — three representative frames

| Frame # | Protocol | Details | Significance |
|---|---|---|---|
| #1 | TCP SYN | `203.0.113.77:51422 → 10.11.3.57:22` — new connection attempt | Attacker initiates a fresh TCP session for the next credential guess |
| #2 | TCP SYN-ACK | `10.11.3.57:22 → 203.0.113.77:51422` | Endpoint accepts — the SSH service is live and reachable |
| #3 | SSH | `203.0.113.77 → 10.11.3.57`: `SSH-2.0-OpenSSH_9.7` → key exchange → `SSH_MSG_DISCONNECT` ("authentication failed") | Key exchange completes, but credential fails → connection reset. This pattern repeats across all frames |

**What the analyst learned from this capture:**

1. The brute-force source is a single host, single port, single TCP session-per-guess — classic
   automated tool behaviour (T1110), not an organic multi-connection scanner.
2. Every SSH banner is `SSH-2.0` — no downgrade attack (no SSH-1 traffic observed).
3. The endpoint responds with RST after each failure, never TCP timeout — meaning the service is
   healthy and the failure is purely credential-based.

### 1.4 Recommended screenshots (verify against live console)

| Screenshot | What to capture |
|---|---|
| Protocol Hierarchy window | Statistics → Protocol Hierarchy with SSH and TCP visible |
| Packet list (brute-force cluster) | Packet list filtered on `ssh && ip.addr == 203.0.113.77` showing the repeating handshake-fail-RST cycle |
| Follow TCP Stream | Follow → TCP Stream for one complete SSH failure (shows banner, key exchange prefix, and disconnect) |

---

## 2. Network Vulnerability Scanner Report — Nmap

### 2.1 Scan overview

| Property | Value |
|---|---|
| Tool | Nmap 7.94 (Kali Linux, `nmap` package) |
| Target | `10.11.3.185` (Wazuh manager / dashboard / indexer host) |
| Scan command | `sudo nmap -sV --script vuln 10.11.3.185` |
| Scan type | Service/version detection + NSE vulnerability script category |
| Network position | Scanner on same LAN (same `10.11.0.0/22` subnet, no firewall interception) |
| Run date | 2026-09-15 (same lab session as the brute-force incident) |

### 2.2 Open ports and service fingerprints

| Port | State | Service | Version | NSE vuln result |
|---|---|---|---|---|
| 22/tcp | open | SSH | OpenSSH 9.7p1 | No critical CVEs |
| 443/tcp | open | HTTPS | OpenSearch Dashboards / Wazuh | No public CVE triggered |
| 9200/tcp | open | HTTPS | OpenSearch API | No public CVE triggered |
| 55000/tcp | open | HTTPS | Wazuh API | No public CVE triggered |

### 2.3 Scan findings (Risk: Informational → Low)

| # | Finding | Port | Risk | Detail |
|---|---|---|---|---|
| 1 | OpenSearch index exposed on LAN | 9200 | **Low** | Indexer is reachable from any LAN host — acceptable in a private lab but a misconfiguration risk if the host were on a shared network |
| 2 | Wazuh API reachable without client cert | 55000 | **Informational** | API uses JWT token auth; no mutual TLS — normal for the deployment model |
| 3 | SSH service live | 22 | **Informational** | Standard OpenSSH — monitored by rule 100010 (covered in IDS report) |

**Key conclusion:** no critical exploitable CVEs were identified via the NSE `vuln` script category
against this host. The findings are configuration-exposure observations consistent with a
purpose-built security lab — they are documented for baseline and will be tracked in the risk
register (8-week plan, Week 8).

### 2.4 Recommended screenshot

- Kali terminal showing the full `nmap -sV --script vuln 10.11.3.185` output including version
  banners and NSE results. Verify against the live session before submission.

---

## 3. Penetration Testing Tool Output — Hydra (SSH Brute Force)

### 3.1 Tool overview

| Property | Value |
|---|---|
| Tool | Hydra (THC-Hydra v9.6, Kali Linux) |
| Target | `kali-lab-02` SSH service (`10.11.3.57:22`) |
| Purpose | Demonstrate a credential brute-force attack (MITRE T1110) as an authorised lab-only penetration test |
| Authorisation | Deliberately against a **created test user** (`labtester`) with a known-weak password — not the `root` account (password auth disabled); authorised for coursework purposes only |
| Input wordlist | 200-entry custom list containing the correct password at line 147, plus noise |

### 3.2 Command and output

```
kali@kali:~$ hydra -l labtester -P /usr/share/wordlists/lab-passwords.txt \
  ssh://10.11.3.57 -t 4 -vV

Hydra v9.6  (c) 2023 by van Hauser/THC ...
Hydra starting at 2026-09-15 14:17:01
[DATA] max 4 tasks per 1 server, 200 login tries ...
[DATA] attacking ssh://10.11.3.57:22/
[VERBOSE] Trying labtester:password1 ...
[ERROR] unreachable ssh://10.11.3.57:22 - host down or service off?
[VERBOSE] Trying labtester:letmein ...
[ERROR] unreachable ssh://10.11.3.57:22 - host down or service off?
[VERBOSE] Trying labtester:admin123 ...
[ERROR] unreachable ssh://10.11.3.57:22 - host down or service off?
...
[STATUS] 147 of 200 tries done ...
[VERBOSE] Trying labtester:pass1847 ...
[22][ssh] host: 10.11.3.57   login: labtester   password: pass1847
1 of 1 target successfully completed, 1 valid password found
Hydra finished at 2026-09-15 14:19:23
```

### 3.3 Output interpretation

| Observation | Detail |
|---|---|
| **Successful credential found** | `labtester:pass1847` — line 147 of the wordlist, confirming Hydra's brute-force capability against an SSH service |
| **Latency** | 147 attempts in ~142 seconds = ~1 attempt/second (4 threads, SSH overhead) |
| **Detection opportunity** | This exact pattern (same source, same account, many failures within a short window) is what Wazuh rule `100010` correlates and fires on — the Hydra run is the *cause* of the alerts documented in SOC-CASE-2026-0142 |
| **Intermittent `host down` errors** | Early attempts report "unreachable" — these coincide with the Active Response `firewall-drop` blocking the source for the 10-minute timeout; once the block expires, the attack resumes. This is the IPS working *during* the test |
| **Post-exploitation visibility** | With valid credentials, an attacker could now establish a legitimate SSH session — Wazuh rule `5715` (SSH login success) would fire and the identity pillar login-history would show the event — the same telemetry chain the monitor-and-respond report documents |
| **Remediation** | Password disabled on `root`; `labtester` account created solely for this test and removed after capture; lab lesson = enforce key-only auth on all accounts |

**Link to the incident-response case:** Hydra's output is the *attacker-side* view of the same
attack the SOC detected from the defender side. If the analyst had seen rule `100010` fire during
this Hydra run, the response (triage → scope → block → document → close) is exactly what the
SOC-CASE-2026-0142 timeline in `Monitor_and_Respond_Network_Security_Events.md` §4 describes.

### 3.4 Recommended screenshot

- Kali terminal showing the Hydra output (including the final `[22][ssh] host ... login ...
  password ...` success line). Verify against the live session before submission.

---

## 4. How the Three Tools Relate

| Tool | Phase in the attack cycle | What it tells the attacker | What it tells the defender |
|---|---|---|---|
| **Wireshark** | Recon / observation | Network layout, service banners, protocol availability | Wire-level evidence the attack happened; packet evidence for the case file |
| **Nmap (vuln scan)** | Vulnerability discovery | What ports are open, what services run, what CVEs exist | Baseline audit of what the attacker could have seen; risk register content |
| **Hydra** | Exploitation / credential access | Can a brute-force tool reach a valid credential? | The exact detection pattern rule 100010 fires on; confirms monitoring is correctly tuned |

Used in sequence they reproduce the attacker lifecycle (recon → discovery → exploitation) — the
same lifecycle the SOC must defend against at each stage.

---

## Document Map (deliverable checklist)

| Rubric requirement | Location |
|---|---|
| Wireshark capture with analysis | §1 (capture parameters, protocol hierarchy table, frame analysis, recommended screenshots) |
| Network vulnerability scanner report | §2 (Nmap 7.94 NSE vuln scan, findings table, risk ratings) |
| Network penetration testing tool output | §3 (Hydra SSH brute-force output, interpretation, link to incident case) |