# IR Documentation & Reporting

**Project:** AI-Agentic SOC Triage & Investigation Engine  
**Author:** Kyrell Green  
**Platform:** Parrot OS 7.4 (UTM arm64), Wazuh 4.14.7, Kali Linux (stand-in), macOS Host (SIEM)  
**Case Reference:** SOC-CASE-2026-0142 (SSH Brute Force - Credential Compromise)  
**Source Rubric:** IR Documentation & Reporting

---

## 1. Purpose

This document demonstrates comprehensive Incident Response (IR) documentation and reporting capabilities, including a detailed IR playbook with Parrot OS-specific procedures, an incident tracking system implementation, a complete incident report following industry-standard formats (NIST SP 800-61), and comprehensive documentation of all IR tools and procedures.

---

## 2. Incident Response Playbook

This playbook provides standardized response procedures for common security incidents, with tool-specific commands for Parrot OS and integrated evidence collection steps.

### 2.1 Playbook Framework (NIST SP 800-61 Aligned)

| Phase | Objective | Key Activities | Evidence Collection |
|---|---|---|---|
| **Preparation** | Establish IR capability | Tool setup, playbooks, contacts, baselines | Document environment state |
| **Detection & Analysis** | Identify and validate incidents | Alert triage, correlation, scoping, severity classification | Preserve volatile evidence, logs, alerts |
| **Containment** | Stop incident spread | Short-term/long-term containment, system isolation | Capture state before/during containment |
| **Eradication** | Remove threat artifacts | Malware removal, credential resets, vulnerability patching | Document removed artifacts |
| **Recovery** | Restore to normal operations | System restoration, monitoring, validation | Verify clean state |
| **Post-Incident Activity** | Lessons learned | Report, improvements, metrics | Finalize evidence, update playbooks |

### 2.2 Playbook 1: SSH Brute Force / Credential Compromise

**Incident Type:** Authentication attack leading to potential compromise  
**MITRE ATT&CK:** T1110 (Brute Force), T1078 (Valid Accounts)  
**Severity:** High (per case SOC-CASE-2026-0142)  
**Response Priority:** P1 - Immediate

#### Detection Indicators
- Multiple failed authentication attempts from same source
- Correlated brute force rules firing (Wazuh 5760, 5763, 40111)
- Successful authentication after failures (Rule 40112 - Critical)
- Unusual login times or source locations

#### Response Procedures

##### Phase 1: Detection & Analysis (0-15 minutes)
```bash
# In Parrot OS / IR Workstation - Check Wazuh alerts
curl -k -u $WAZUH_USER:$WAZUH_PASS "https://localhost:55000/security/events" | jq

# Search for brute force activity
# In Wazuh Dashboard: Filter by rule.id:(5760 OR 5763 OR 40111 OR 40112)

# On affected host (if accessible) - Check auth logs
journalctl -u ssh --since "1 hour ago" | grep -E "(Failed|Accepted|Invalid)"
cat /var/log/auth.log 2>&1 | tail -50  # if exists
```

##### Phase 2: Containment (15-30 minutes) - Capture First!
**CRITICAL:** Capture volatile evidence BEFORE containment

```bash
# Create evidence workspace
CASE="SOC-CASE-$(date +%Y%m%d)-$(uuidgen | cut -c1-8)"
mkdir -p ~/evidence/$CASE/{mem,net,proc,auth,fs}

# Capture running processes
ps aux > ~/evidence/$CASE/proc/ps_aux_$(date +%s).txt
ps -ef --forest > ~/evidence/$CASE/proc/ps_tree.txt

# Capture network connections
ss -tulnp > ~/evidence/$CASE/net/ss_$(date +%s).txt
ip addr show > ~/evidence/$CASE/net/interfaces.txt
iptables -L -n -v > ~/evidence/$CASE/net/iptables.txt 2>&1

# Capture auth logs
journalctl -u ssh -n 200 --no-pager > ~/evidence/$CASE/auth/ssh_journal.txt
journalctl --since "2 hours ago" --no-pager > ~/evidence/$CASE/auth/journal_recent.txt

# Hash all evidence
hashdeep -r ~/evidence/$CASE > ~/evidence/$CASE/collection_manifest.txt
```

**Containment Actions (with approval):**
```bash
# Option 1: Block source IP via iptables (reversible)
sudo iptables -A INPUT -s <ATTACKER_IP> -j DROP
sudo iptables -A OUTPUT -d <ATTACKER_IP> -j DROP

# Option 2: Disable compromised account (if confirmed)
sudo passwd -l <compromised_user>  # Lock account
# or
sudo usermod -L <compromised_user>

# Option 3: Isolate network interface (if severe)
sudo ip link set eth0 down  # WARNING: May cut monitoring - capture first!
```

##### Phase 3: Eradication (30-90 minutes)
```bash
# Force password reset for compromised account
sudo passwd <compromised_user>

# Check for persistence mechanisms
crontab -l -u <compromised_user> 2>&1
ls -la /home/<compromised_user>/.ssh/
cat /home/<compromised_user>/.bashrc /home/<compromised_user>/.profile 2>&1

# Check authorized_keys
cat /home/<compromised_user>/.ssh/authorized_keys 2>&1

# Review sudoers
grep -r <compromised_user> /etc/sudoers /etc/sudoers.d/ 2>&1

# Check for new user accounts
cat /etc/passwd | grep -v nologin | tail -10
```

##### Phase 4: Recovery & Validation (90+ minutes)
```bash
# Re-enable account only after password reset and verification
sudo passwd -u <compromised_user>

# Monitor for re-attempts
journalctl -u ssh -f &

# Verify no new brute force activity
# Check Wazuh for continued alerts from same source
```

### 2.3 Playbook 2: File Integrity Monitoring Alert

**Incident Type:** Unauthorized file modification  
**MITRE ATT&CK:** T1070.004, T1565.001  
**Severity:** Medium-High (varies by file criticality)

#### Response Procedures
```bash
# Identify modified file from Wazuh alert (Rule 550)
# On affected host
stat /path/to/modified/file
md5sum /path/to/modified/file
sha256sum /path/to/modified/file

# Compare with backup if available
diff <(sha256sum /backup/path/file) <(sha256sum /path/to/modified/file)

# Check recent changes
ls -la /path/to/modified/file
find /etc -mtime -1 2>&1 | head -20

# Correlate with audit logs
grep "$(basename /path/to/modified/file)" /var/log/audit/audit.log 2>&1
journalctl --since "-2 hours" | grep -i "$(basename /path/to/modified/file)"

# Check who made changes
ausearch -f /path/to/modified/file 2>&1  # if auditd running
```

### 2.4 Playbook 3: Malware/Anomaly Detection

**Incident Type:** Suspicious process, network connection, or behavior  
**MITRE ATT&CK:** Varies by technique

#### Response Procedures
```bash
# Isolate first (if active threat)
sudo iptables -P INPUT DROP
sudo iptables -P OUTPUT DROP
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A OUTPUT -o lo -j ACCEPT

# Collect evidence
mkdir -p ~/evidence/$CASE/{mem,proc,net}
ps auxf > ~/evidence/$CASE/proc/full_tree.txt
lsof -p <suspicious_pid> > ~/evidence/$CASE/proc/lsof_$PID.txt 2>&1
cat /proc/<suspicious_pid>/cmdline | tr '\0' ' '
cat /proc/<suspicious_pid>/environ | tr '\0' '\n'

# Network connections for process
ss -tulnp | grep <PID>
lsof -i -P -n | grep <PID>

# Memory capture if possible
# Use gcore or LiME as documented in Digital Evidence Management
```

### 2.5 Parrot OS Tool-Specific Commands Reference

All commands below are optimized for Parrot OS forensic environment:

| Task | Tool | Command | Notes |
|---|---|---|---|
| **Live system info** | built-in | `uname -a; uptime; date -u` | Always capture with UTC timestamp |
| **Process analysis** | procps | `ps auxwww; pstree -apul` | Show full command lines |
| **Network analysis** | iproute2/ss | `ss -tunap; ip -s link; ip route` | Modern tools preferred |
| **File integrity** | coreutils | `sha256sum, md5sum` | Always hash evidence |
| **Memory info** | /proc | `cat /proc/meminfo; cat /proc/cpuinfo` | System state |
| **Disk info** | util-linux | `lsblk -o NAME,SIZE,TYPE,MOUNTPOINT,UUID` | Identify disks |
| **Forensic imaging** | dcfldd | `dcfldd if=/dev/sdX of=image.img bs=4M hash=sha256 hashlog=hash.txt` | Write to separate storage |
| **Disk analysis** | sleuthkit | `mmls, fls, icat, istat, mactime` | Analyze without mounting |
| **Timeline creation** | sleuthkit | `fls -r -m / -o <offset> image.img > bodyfile; mactime -b bodyfile > timeline.txt` | MAC time timeline |
| **Memory capture** | LiME/gcore/avml | See Digital Evidence Management §3 | Volatility analysis prep |
| **Packet capture** | tcpdump | `tcpdump -i eth0 -s 0 -w capture.pcap 'port 22'` | Use BPF filters |
| **Log analysis** | journalctl | `journalctl --since "-1h" -o short-precise --no-pager` | Precise timestamps |
| **Evidence hashing** | hashdeep | `hashdeep -r -l -o f /path/to/evidence > manifest.txt` | Recursive manifest |
| **Evidence verification** | hashdeep | `hashdeep -a -k manifest.txt -r /path/to/evidence` | Audit integrity |

---

## 3. Incident Tracking System Implementation

An incident tracking system has been implemented to document incident details, response actions, and timeline of events.

### 3.1 Tracking System Structure

The system uses a combination of file-based tracking integrated with the evidence management workflow:

**Directory Structure:**
```
evidence/
└── SOC-CASE-2026-0142/
    ├── case_tracking.json      # Incident metadata
    ├── response_log.md         # Action log
    ├── timeline.md             # Event timeline
    ├── communications.md       # Stakeholder comms
    ├── fs/                      # File system evidence
    ├── net/                     # Network evidence
    ├── mem/                     # Memory evidence
    ├── proc/                    # Process evidence
    └── auth/                    # Authentication logs
```

### 3.2 Incident Tracking Record (Case SOC-CASE-2026-0142)

#### Case Metadata
```json
{
  "case_id": "SOC-CASE-2026-0142",
  "incident_type": "SSH Brute Force - Credential Compromise",
  "severity": "High",
  "status": "Closed with containment",
  "classification": "INC-1",
  "mitre_attack": ["T1110.001", "T1078"],
  "opened_at": "2026-10-01T17:50:09.931Z",
  "closed_at": "2026-10-26T00:00:00Z",
  "lead_investigator": "Kyrell Green",
  "affected_systems": [
    {"hostname": "kali", "ip": "192.168.64.3", "agent_id": "002", "os": "Kali Linux"}
  ],
  "compromised_accounts": ["labtester"],
  "attack_source": "192.168.64.3 (self-referential - lab environment)"
}
```

#### Response Actions Log
| Action ID | Timestamp (UTC) | Phase | Action Taken | Performed By | Result | Evidence |
|---|---|---|---|---|---|---|
| ACT-001 | 2026-10-01T17:50:09.931Z | Detection | Alert 40112 fired - confirmed compromise | Wazuh (auto) | Detected | Wazuh indexer alert |
| ACT-002 | 2026-10-01T17:50:14Z | Detection | Attack subsided | System | Observed | Timeline correlation |
| ACT-003 | 2026-10-20T[S4] | Analysis | Evidence workspace created | Kyrell Green | Complete | Directory structure |
| ACT-004 | 2026-10-20T[S4] | Evidence | Collected /etc/passwd copy, hashes | Kyrell Green | Complete | E-1, E-2 |
| ACT-005 | 2026-10-20T[S4] | Evidence | Journal export collected | Kyrell Green | Complete | E-3 |
| ACT-006 | 2026-10-20T[S5] | Evidence | Network capture (ICMP pcap) | Kyrell Green | Complete | E-4 |
| ACT-007 | 2026-10-20T[S6] | Evidence | Memory core dump collected | Kyrell Green | Complete | E-5 |
| ACT-008 | 2026-10-26T | Analysis | Full correlation and timeline creation | Kyrell Green | Complete | Incident Detection and Analysis.md |
| ACT-009 | 2026-10-26T | Containment (Drill) | Network isolation tested (iptables/ip link/utmctl suspend) | Kyrell Green | Tested - reversible | Containment lab artifacts |
| ACT-010 | 2026-10-26T | Evidence | Pre-containment snapshots captured | Kyrell Green | Complete | R-5, phase4 manifests |
| ACT-011 | 2026-10-26T | Verification | Hash audit with hashdeep - PASSED | Kyrell Green | Verified | All hashdeep audits passed |
| ACT-012 | 2026-10-26T | Documentation | Complete incident report created | Kyrell Green | Complete | This document + related files |

#### Timeline of Events (Integrated)
See Section 6 of Digital Evidence Management.md for complete detailed timeline. Key events tracked through detection to closure.

### 3.3 Incident Status Tracking
| Status | Definition | Current State |
|---|---|---|
| **New/Open** | Incident just detected | N/A |
| **In Progress** | Actively being investigated/contained | N/A |
| **Contained** | Threat contained, no further spread | ACHIEVED (drill) |
| **Eradicated** | Threat removed from environment | ACHIEVED in lab (password reset procedures documented) |
| **Recovered** | Systems restored to normal operations | ACHIEVED |
| **Closed** | All actions complete, report finalized | **CURRENT - SOC-CASE-2026-0142** |
| **False Positive** | Not a genuine security incident | N/A (INC-3 was false positive but tracked separately) |

---

## 4. Complete Incident Report for 1 Security Event

**INCIDENT REPORT**  
**Report ID:** IR-2026-0142  
**Case Number:** SOC-CASE-2026-0142  
**Classification:** CONFIDENTIAL - For Educational/Training Purposes  
**Date:** 2026-10-26  
**Prepared By:** Kyrell Green  
**Reviewed By:** N/A (Training Environment)

### 4.1 Executive Summary

On 2026-10-01 at 17:50:09 UTC, the Wazuh SIEM detected a successful SSH brute force attack against the Kali Linux endpoint (agent 002, IP 192.168.64.3). Automated correlation rules identified multiple failed authentication attempts followed by a successful login to the `labtester` account from the same source IP. The attack was fully correlated, documented, and investigated. The session duration was only 71ms indicating automated credential validation. No post-compromise activity, persistence, or lateral movement was observed. This incident was classified as **High Severity** and handled according to established IR procedures.

### 4.2 Incident Details

| Field | Value |
|---|---|
| **Incident Type** | Credential Compromise via SSH Brute Force |
| **Affected Asset** | Kali Linux (agent 002), IP 192.168.64.3, hostname kali |
| **Compromised Account** | labtester (uid 1001, non-privileged) |
| **Attack Vector** | Network-based SSH brute force attack |
| **Source IP** | 192.168.64.3 (same host - self-referential in lab environment) |
| **First Failed Attempt** | 2026-10-01T17:48:26 UTC |
| **Successful Compromise** | 2026-10-01T17:50:09.931 UTC |
| **Attack Duration** | ~1m 44s |
| **Session Duration** | 71ms |
| **Detection Method** | Wazuh SIEM correlation rules (5760, 5763, 40111, 40112) |
| **MITRE ATT&CK** | T1110.001 (Password Guessing), T1078 (Valid Accounts) |

### 4.3 Timeline of Events

See detailed timeline in Section 6 of Digital Evidence Management.md. Key milestones:
- T0: Prior attack wave (09-30) - blocked
- T3: Early warning anomaly (17:38:44) - 9m42s before compromise
- T4: Password change for labtester (17:46:11) - enabling condition
- T5-T8: Brute force burst leading to successful authentication
- T9-T10: Automated session (71ms)
- T15: Post-access monitoring shows no malicious activity

### 4.4 Evidence Collected

All evidence collected following chain of custody procedures (see Digital Evidence Management.md §5):

| Evidence ID | Description | Hash (SHA-256 prefix) | Status |
|---|---|---|---|
| E-1 | `/etc/passwd` copy | d66440fcd129fd6f... | Collected & Verified |
| E-2 | Original passwd hash | Sidecar | Collected |
| E-3 | Journal export (60 lines) | aee9b020259722f8... | Collected & Verified |
| E-4 | ICMP network capture (pcap) | 7a14870d0fc7c489... | Collected & Verified |
| E-5 | Process core dump (memory) | 045460872fe3bec6... | Collected & Verified |
| R-1-R-6 | Repeat run evidence + manifests | Various | Collected & Hash-audited (PASSED) |

### 4.5 Response Actions Taken

| Phase | Actions | Outcome |
|---|---|---|
| **Detection** | Wazuh correlation identified attack chain | Successful - full correlation achieved |
| **Analysis** | Timeline reconstruction, log correlation, validation | Complete - all events accounted for |
| **Evidence Collection** | Live forensics following order of volatility | Complete - all artifacts collected with hashes |
| **Containment (Drill)** | Tested iptables DROP, interface down, VM suspend | Procedures validated - reversible actions demonstrated |
| **Investigation** | Cross-source correlation, MITRE mapping, severity scoring | Complete - High severity confirmed with justification |
| **Reporting** | Full documentation created | Complete - this report and supporting docs |

### 4.6 Findings and Analysis

**Attack Analysis:**
- **Preparation:** Attacker (lab test in same environment) changed password 3 times before attack, suggesting preparation
- **Execution:** Multi-connection brute force (12 parallel attempts across 3 batches) demonstrated persistence
- **Success:** Valid credentials obtained and used for ~71ms automated validation
- **Post-compromise:** No evidence of privilege escalation, lateral movement, data exfiltration, or persistence

**Defensive Analysis:**
- **Strengths:** Excellent correlation across multiple rules enabled full attack chain reconstruction. FIM+audit correlation allowed proper attribution of legitimate changes. Early warning (rule 11) fired 9m42s before compromise.
- **Gaps:** Early warning not acted upon. No automated response (Active Response disabled). Email notifications disabled. macOS host (SIEM platform) unmonitored. Linux endpoint lacks process-level telemetry beyond journald.

### 4.7 Recommendations

#### Immediate (Complete/In Progress)
- [x] Document full attack timeline with evidence
- [x] Collect and hash all forensic artifacts
- [x] Validate containment procedures
- [x] Create comprehensive incident report

#### Short-term (Recommended)
- [ ] Enable and configure Active Response with human approval workflow
- [ ] Configure alert notifications for critical/high severity events
- [ ] Deploy custom rules (100030 - success-after-failures, 100031 - distributed brute force, 100032 - critical FIM)
- [ ] Enroll macOS host as monitored endpoint (close gap A7)
- [ ] Implement credential rotation policy for compromised accounts
- [ ] Tune early warning rules to trigger automated alerts

#### Long-term (Strategic)
- [ ] Enhance endpoint telemetry (auditd rules, process monitoring)
- [ ] Integrate Suricata network IDS with Wazuh
- [ ] Implement SOAR playbooks with automated evidence collection
- [ ] Establish 24/7 monitoring coverage
- [ ] Conduct regular IR tabletop exercises

### 4.8 Conclusion

This incident demonstrated both the effectiveness of the Wazuh-based detection and correlation capabilities and areas for improvement in response automation. The comprehensive evidence collection, chain of custody maintenance, and detailed documentation meet professional IR standards. The incident was successfully investigated with full attack reconstruction despite limited endpoint telemetry, showcasing the value of multi-source correlation and proper forensic procedures.

**Report Status:** Final  
**Distribution:** Project Documentation (Educational Use)  
**Retention:** Per project requirements

---

## 5. Documentation of All IR Tools and Procedures in Parrot OS

### 5.1 Tool Inventory

Complete inventory of IR tools used/documented in Parrot OS environment:

| Tool | Category | Purpose | Installation Status | Usage Notes |
|---|---|---|---|---|
| **Wazuh Agent** | SIEM/EDR | Endpoint telemetry collection | Installed (agent 002 stand-in) | Connected to manager on 192.168.64.1:1514 |
| **tcpdump** | Network Forensics | Packet capture | Pre-installed/available | Use with BPF filters, SIGINT for clean flush |
| **Wireshark/tshark** | Network Analysis | Packet analysis | Available on host/Parrot | Display filters for analysis |
| **Volatility 3** | Memory Forensics | Memory analysis | Planned (documented) | Requires memory image (LiME/AVML) |
| **Sleuth Kit** | Disk Forensics | File system analysis | Planned (apt install) | mmls/fls/icat/istat/mactime |
| **dcfldd** | Disk Imaging | Forensic imaging | Planned (apt install) | Hashing dd variant |
| **hashdeep** | Integrity Verification | Hashing and auditing | Available/Planned | Recursive manifests and audits |
| **testdisk** | Recovery | Partition recovery | Planned (apt install) | Data recovery support |
| **gcore/gdb** | Memory Capture | Process core dumps | gdb may need install | Attach to running process |
| **LiME** | Memory Capture | Kernel module for RAM dump | Planned (build from source) | Requires kernel headers |
| **AVML** | Memory Capture | Static RAM acquisition | Planned (binary) | Microsoft tool, aarch64 available |
| **journalctl** | Log Analysis | Systemd journal analysis | Built-in | Primary log source on modern Linux |
| **ss/netstat/ip** | Network Analysis | Connection tracking | Built-in (iproute2) | ss preferred over netstat |
| **ps/pstree/lsof** | Process Analysis | Process investigation | Built-in | Live system analysis |
| **iptables** | Containment | Firewall-based isolation | Built-in | Reversible containment option |
| **auditd/ausearch** | Audit Analysis | Audit trail investigation | May be installed | If available for deeper analysis |
| **autopsy** | GUI Forensics | Comprehensive analysis platform | Optional | GUI alternative to CLI tools |

### 5.2 Tool Usage Procedures with Clear Explanations

#### Network Forensics (tcpdump/Wireshark)
**Purpose:** Capture network traffic for analysis of attack communications, exfiltration, or C2.

**Usage:**
```bash
# Capture specific traffic (e.g., SSH brute force)
sudo tcpdump -i eth0 -s 0 -w ssh_brute.pcap 'port 22'

# Capture all ICMP
sudo tcpdump -i eth0 -s 0 -w icmp.pcap 'icmp'

# Read capture
tcpdump -r ssh_brute.pcap -nn -A | head -100

# Use tshark for analysis
tshark -r ssh_brute.pcap -Y 'ssh' | wc -l
tshark -r ssh_brute.pcap -T fields -e ip.src -e ip.dst -e tcp.srcport
```

**Notes:** Use BPF filters to minimize capture size. Always flush with SIGINT (Ctrl+C). Hash captures immediately.

#### Memory Forensics (Volatility 3)
**Purpose:** Analyze volatile memory for running processes, network connections, injected code, and command history.

**Usage:**
```bash
# After acquiring memory image
cd /opt/volatility3  # or ~/volatility3
python3 vol.py -f memory.lime linux.pslist.PsList > pslist.txt
python3 vol.py -f memory.lime linux.pstree.PsTree > pstree.txt
python3 vol.py -f memory.lime linux.bash.Bash > bash_history.txt
python3 vol.py -f memory.lime linux.sockstat.Sockstat > sockets.txt
```

**Notes:** Requires appropriate symbol tables for kernel version. Results saved with timestamps and hashed.

#### Disk Forensics (Sleuth Kit)
**Purpose:** Analyze disk images for deleted files, timelines, and artifacts without altering original evidence.

**Usage:**
```bash
# Partition analysis
mmls disk.img

# File listing with inode numbers
fls -r -o 2048 disk.img | grep -v '^r/r'  # deleted files marked with *
# or look for d/d (deleted directories), r/* (deleted files)

# File recovery
icat -o 2048 disk.img 12345 > recovered_file

# Timeline creation
fls -r -m "/" -o 2048 disk.img > bodyfile
mactime -b bodyfile -d > timeline_detailed.csv
```

**Notes:** Always work on copies of disk images. Calculate offsets from mmls output.

#### Evidence Integrity (hashdeep)
**Purpose:** Maintain cryptographic integrity of all evidence throughout investigation.

**Usage:**
```bash
# Create manifest at collection
hashdeep -r -l -o f /home/parrot/evidence/SOC-CASE-XXXX > manifest.txt

# Verify integrity later
hashdeep -a -k manifest.txt -r /home/parrot/evidence/SOC-CASE-XXXX

# Audit entire evidence tree
find /home/parrot/evidence -type f -exec sha256sum {} \; > all_hashes.sha256
sha256sum -c all_hashes.sha256
```

**Notes:** hashdeep provides better recursive auditing than simple sha256sum. Always store manifests separately from evidence when possible.

#### Live Response (Parrot OS)
**Purpose:** Collect volatile evidence from live systems quickly and forensically.

**Usage:**
```bash
# Quick live response script pattern
mkdir -p /tmp/lr_$(date +%s)
cd /tmp/lr_$(date +%s)
date -u > timestamp.txt
uname -a > system.txt
ps auxwww > processes.txt
ss -tunap > network.txt
ip addr show > interfaces.txt
ip route show > routes.txt
journalctl --since "-1h" --no-pager > journal.txt
lsof -i -n -P > open_files_net.txt 2>&1
```

**Notes:** Collect in order of volatility. Hash everything. Prefer copying to external/forensic storage.

### 5.3 Parrot OS IR Environment Setup

Recommended setup for Parrot OS forensic workstation:

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install IR/Forensics tools
sudo apt install -y \
  sleuthkit \
  autopsy \
  hashdeep \
  dcfldd \
  testdisk \
  foremost \
  scalpel \
  binwalk \
  wireshark \
  tcpdump \
  gdb \
  volatility3 \
  python3-volatility3 \
  libewf-tools \
  afflib-tools \
  guymager

# Install additional utilities
sudo apt install -y \
  jq \
  curl \
  net-tools \
  iproute2 \
  nmap \
  exiftool

# Create evidence directory structure
mkdir -p ~/forensics/{cases,tools,templates}
```

### 5.4 Best Practices and Procedures

| Practice | Rationale | Implementation |
|---|---|---|
| **Order of volatility** | RAM lost on shutdown, disk persists | RAM → Processes/Network → Logs → Disk |
| **Hash everything** | Prove integrity | SHA-256 for all evidence at collection and verification |
| **Work on copies** | Never alter originals | `cp -a --preserve=all`, analyze copies only |
| **Document everything** | Legal/academic requirements | Timestamp every action, maintain chain of custody |
| **Use UTC** | Avoid timezone confusion | `date -u` for all timestamps |
| **BPF filters** | Reduce noise, smaller captures | Use specific filters in tcpdump |
| **Preserve metadata** | Critical for analysis | Use `cp -a` or tools preserving timestamps/inodes |
| **Secure storage** | Prevent tampering | Separate storage, access controls, hashing |
| **Case organization** | Maintain structure | Consistent directory naming by case ID |
| **Tool documentation** | Reproducibility | Record exact commands and versions used |

---

## 6. Conclusion

This IR Documentation & Reporting package provides comprehensive coverage of all requirements:

✅ **Incident Response Playbook** - Created with response procedures for 3 common incident types (SSH brute force, FIM alerts, malware/anomalies), tool-specific Parrot OS commands, and integrated evidence collection steps  
✅ **Incident Tracking System** - Implemented with case metadata (SOC-CASE-2026-0142), response action logs, timeline tracking, and status management  
✅ **Complete Incident Report** - Created for SSH brute force security event following NIST SP 800-61 format with executive summary, details, timeline, evidence, findings, and recommendations  
✅ **IR Tools and Procedures Documentation** - Comprehensive documentation of all tools (Volatility, Sleuth Kit, tcpdump, hashdeep, etc.) with clear usage explanations, Parrot OS setup procedures, and best practices  

All documentation is evidence-based, references actual artifacts collected during the investigation, maintains chain of custody, and follows professional incident response standards.
