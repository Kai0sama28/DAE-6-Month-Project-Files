# Comprehensive Security Policy — SOC Lab

**Author:** Kyrell Green
**Date:** 2026-09-14
**Module:** Cyber Threats & Vulnerabilities / SOC Security Analyst track
**Scope:** Organizational security policy for the SOC lab environment — key security
rules/guidelines, a breach incident-response plan, and the mapping of both to the **CIA Triad**
(Confidentiality, Integrity, Availability).

---

## 1. Purpose & Scope

This policy defines the security rules every user, administrator, and automated system in the
cybersecurity lab must follow. It applies to all systems in scope: the lab Mac (host), the
Wazuh single-node stack (manager/indexer/dashboard Docker containers), the Kali Linux endpoint
(UTM VM, `10.11.0.0/22`), and every credential, dataset, and investigation record they contain.
Compliance is verified through the monitoring controls described in this document; violations
should be reported per Section 4 (Escalation) rather than silenced or fixed silently.

---

## 2. Key Security Rules & Guidelines (Core Rules)

### Rule 1 — Least Privilege & Access Control
- Every user, service, and API account gets **only the rights required to do its job** — no
  exception accounts on the Wazuh manager, no standing root on shared hosts.
- Admin/API access (e.g., Wazuh API `55000`) requires unique accounts and **strong passwords
  or keys**; never shared logins.
- Interactive SSH to lab endpoints must use **key-based authentication**; password auth is
  disabled after the demonstrated brute-force example (Wazuh rule 100010 / MITRE T1110).
- Access is reviewed when a user changes role or leaves; access granted to the privileged set
  is logged.

*Why:* minimizes attack surface and blast radius — an account compromise or insider action can
only touch what that identity legitimately reaches.

### Rule 2 — Credential & Secret Management
- Secrets (**API keys, Wazuh credentials, `.env` files**) are never committed to version
  control or written into code, logs, or documentation. In this repo they live only in the
  gitignored `.env` and never in the public portfolio site.
- Passwords are stored hashed (never plaintext); API credentials are rotated on a schedule
  and immediately on any suspected exposure.
- MFA is required wherever the platform supports it before privileged actions.

*Why:* credential theft is the single most common pathway into a network (T1078 — Valid
Accounts); protecting secrets protects every system that trusts them.

### Rule 3 — Endpoint Security Baseline
- Every managed endpoint (e.g., Kali) must have the **Wazuh agent enrolled**, with
  **File Integrity Monitoring (syscheck)** and log collection active before it joins the
  monitored network.
- Operating system and installed software must be **patched**; critical/security updates are
  applied or justified within a defined window.
- No endpoint may be connected to the lab from an unknown network without going through the
  lab's firewall/IDS/IPS pipeline.

*Why:* a consistent baseline means detection is uniform (no blind spots), FIM protects
Integrity, and patch discipline closes the known-vector root causes.

### Rule 4 — Network Security & Segmentation
- The lab network is segmented: monitored endpoints and the Wazuh stack are separated from
  uncontrolled networks; a **quarantine segment (deny-all default)** exists for compromised
  hosts.
- **No exposed management surface to the internet:** the Wazuh API (`55000`) and indexer
  (`9200`) are never published to the WAN. Remote administration only via VPN/SSH tunnel.
- Firewall/IDS/IPS rules are change-controlled and reviewed; any new listening service must
  be approved and logged.

*Why:* segmentation contains incidents (lateral movement is stopped by design) and keeps the
two most sensitive ports off the internet.

### Rule 5 — Logging, Monitoring & Acceptable Use
- All security-relevant events (auth, FIM changes, process/network telemetry, alerts) are
  collected in Wazuh and retained for the defined retention period to support investigation.
- Monitored systems are for **authorized lab and coursework use only** — no personal data, no
  unauthorized scanning outside the lab scope, no exfiltration out of measures taken for the
  assessment scenarios.

*Why:* you cannot investigate what was never logged; acceptable-use framing keeps the lab
defensible and legal.

### Rule 6 — Incident Reporting Duty
- Every suspected security incident or policy violation must be **reported immediately**, at
  latest within the defined window, through the escalation path in Section 4. Reporting an
  incident is never itself a violation — concealing one is.

*Why:* speed of detection and notification is the single biggest factor in containing a
breach.

---

## 3. Incident Response Plan — Steps in Case of a Security Breach

Applies when any control above is confirmed bypassed and an incident is declared. This is the
situational, breach-response runbook derived from the module's full Incident Response Plan.

### Step 1 — Detect & Declare
- A breach is declared on: a confirmed high-severity alert (e.g., level 10+), a confirmed
  MITRE-mapped hit (T1110 / T1566 / T1486), an IoC match, or a user report.
- The incident is logged with a timestamp, affected systems, and any evidence captured —
  **preserve evidence** (original alert events, logs, and disk state) and avoid unnecessary
  changes to the affected host.

### Step 2 — Assess & Prioritize
- Classify by **scope** (hosts/data at risk), **impact**, and **urgency**. Example: a
  confirmed SSH brute-force on one endpoint with no credential reuse found = Medium; suspected
  ransomware encryption = Critical.
- Assign an owner and notify the affected users/administrators per Rule 6.

### Step 3 — Contain
- **Short-term (minutes):** block attacker/C2 IPs at the firewall/IPS, isolate the affected
  endpoint (disconnect from the network), and suspend any compromised credentials.
- **Longer-term:** move the host to the quarantine segment; rotate credentials for any account
  seen in the incident.
- Containment is a **human-approved** action — never automatically executed by any automated
  or agentic system.

### Step 4 — Eradicate
- Scope the compromise (processes, files, persistence), remove malicious artifacts and
  attacker access, patch the root cause (e.g., disable password SSH → key-only), and re-image
  the host if substantially compromised.
- Verify eradication: rescan with IDS/Wazuh, IoCs no longer present, then reset the FIM
  baseline.

### Step 5 — Recover
- Restore from verified known-good backups, confirm integrity against the FIM baseline
  (no IoCs), reconnect incrementally, and run **elevated monitoring for 30 days** to catch
  recurrence.

### Step 6 — Post-Incident & Lessons Learned
- Document the timeline, root cause, containment/eradication actions, and what worked/failed.
- Update rules and signatures so the incident cannot recur unchanged, and share the review
  with the people who need it — then close the incident record.

---

## 4. Escalation & Notification Path

| Severity | Example | Notify |
|---|---|---|
| Low | Policy violation, no compromise | Security lead, within reporting window |
| Medium | Confirmed single-host compromise, no spread | Security lead + system owner immediately |
| High | Lateral movement / data loss / ransomware | Security lead + full lab team immediately |

Contact channels: in-scope reporting via the lab monitoring platform and direct escalation to
the security lead / program instructor. A breach affecting graded coursework or portfolio
systems is treated as High.

---

## 5. How These Policies Maintain the CIA Triad

The CIA Triad (Confidentiality, Integrity, Availability) is the goal the whole policy is
optimized against. Each part of this document contributes as follows:

### 5.1 Confidentiality (only authorized parties can read/access data)
- **Rule 1 (least privilege)** and **Rule 2 (secrets)** directly limit who and what can read
  data — fewer people with access, and secrets kept out of code and repos.
- **Rule 4 (network)** keeps management interfaces off the internet, so the Wazuh API and
  indexer cannot leak data to the WAN.
- **Breach response:** containment (Step 3) stops ongoing data exfiltration; eradication
  (Step 4) removes the attacker's access to protected data.

### 5.2 Integrity (data is accurate and unaltered by unauthorized parties)
- **Rule 3 (FIM)** is the primary Integrity control — file integrity monitoring alarms on any
  unsanctioned change to system files, which is exactly how malware/ransomware writes are
  caught.
- **Rule 5 (logging)** ensures logs themselves are trusted evidence (they cannot be silently
  edited), and change-controlled firewall/IPS rules keep the enforcing device honest.
- **Breach response:** eradication + post-verification (Steps 4–5) restore data to a
  known-good state verified against the FIM baseline before it is trusted again.

### 5.3 Availability (systems and data are accessible when needed)
- **Rule 3 (patch + baseline)** keeps systems up to date and stable, reducing availability
  outages from known vulnerabilities; monitoring (Rule 5) surfaces DoS/degradation early.
- **Backups + tested restore (Recovery step)** are the Availability safety net — ransomware
  and disk failures are recoverable because a verified restore path exists.
- **Breach response:** recovery (Step 5) and the elevated 30-day monitoring ensure services
  return promptly and stay up.

### 5.4 Summary mapping

| Policy / control | Confidentiality | Integrity | Availability |
|---|---|---|---|
| Least privilege & access control (Rule 1) | ✔ primary | | |
| Credential & secret management (Rule 2) | ✔ primary | ✔ | |
| Endpoint baseline + FIM (Rule 3) | ✔ | ✔ | ✔ |
| Network segmentation / no WAN exposure (Rule 4) | ✔ | | ✔ |
| Logging, monitoring, acceptable use (Rule 5) | ✔ | ✔ | |
| Incident reporting & containment (Rule 6 / §3) | ✔ | ✔ | ✔ |
| Backups + tested restore (§3 Step 5) | | ✔ | ✔ primary |

The CIA Triad is not three separate programs here — the same controls are deliberately
layered so that, for example, **one** breach response simultaneously preserves Confidentiality
(stop exfiltration), restores Integrity (verified clean state), and restores Availability
(prompt recovery).

---

## 6. Rubric Coverage

| Requirement | Addressed in |
|---|---|
| ≥3 key security rules/guidelines | Section 2 — six rules (access, secrets, endpoint baseline, network, logging/use, incident reporting) |
| Incident response plan with steps for a security breach | Section 3 — detect → assess → contain → eradicate → recover → post-incident + escalation path in Section 4 |
| Section explaining how policies maintain the CIA Triad | Section 5 — per-component breakdown (5.1–5.3) + summary mapping (5.4) |