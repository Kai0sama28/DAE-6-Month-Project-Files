# Post-Incident Procedures

**Project:** AI-Agentic SOC Triage & Investigation Engine  
**Author:** Kyrell Green  
**Case Reference:** SOC-CASE-2026-0142 (SSH Brute Force - Credential Compromise)  
**Platform:** VirtualBox/UTM, Parrot OS 7.4, Kali Linux, Wazuh 4.14.7, macOS Host  
**Source Rubric:** Post-Incident Procedures

---

## 1. Purpose

This document addresses post-incident procedures including system recovery for VirtualBox/UTM environments, Parrot OS system recovery, and network configuration recovery; root cause analysis with timeline, contributing factors, and technical findings; recovery validation checklist with testing procedures; and IR process improvement recommendations based on lessons learned.

---

## 2. System Recovery Procedures

### 2.1 VirtualBox Environment Restoration

For VirtualBox-based lab environments, follow these procedures to restore systems to a known-good state.

#### Pre-Recovery Assessment
- [ ] Verify incident fully contained and eradicated
- [ ] Ensure all evidence collected and hashed (chain of custody complete)
- [ ] Confirm snapshots/backups available from before incident
- [ ] Document current VM state

#### VM Restoration Steps
```bash
# List VMs
VBoxManage list vms

# Check VM state
VBoxManage showvminfo "<VM-Name>" | grep -E "(State|Name)"

# Restore from snapshot (safest approach)
VBoxManage snapshot "<VM-Name>" restore "<Snapshot-Name>"

# Or restore disk from backup
# Copy clean disk image
cp /backup/path/clean-disk.vdi ~/VirtualBox\ VMs/<VM-Name>/

# Attach cleaned disk
VBoxManage storageattach "<VM-Name>" --storagectl "SATA" --port 0 --device 0 --type hdd --medium ~/VirtualBox\ VMs/<VM-Name>/clean-disk.vdi

# Start VM
VBoxManage startvm "<VM-Name>" --type headless  # or gui
```

#### VirtualBox Network Restoration
```bash
# Restore NAT/Host-Only/Internal networking as designed
VBoxManage modifyvm "<VM-Name>" --nic1 nat
VBoxManage modifyvm "<VM-Name>" --nic2 hostonly --hostonlyadapter2 vboxnet0

# Verify network adapters
VBoxManage showvminfo "<VM-Name>" | grep -A 20 "NIC"
```

#### Post-Restoration Verification
- [ ] VM boots successfully
- [ ] Network connectivity restored to lab network
- [ ] Wazuh agent reconnects (check agent status)
- [ ] Services start correctly
- [ ] No malware artifacts present
- [ ] Logs show normal activity

### 2.2 UTM Environment Restoration (macOS)

For UTM-based environments (as used in this lab):

#### Restoration from Snapshots
1. Open UTM application
2. Select affected VM
3. Right-click → Snapshots → Select pre-incident snapshot
4. Click Restore
5. Start VM

#### Restoration from Disk Image Backup
```bash
# Locate UTM VM bundle
VM_PATH=~/Library/Containers/com.utmapp.UTM/Data/Documents/<VM-Name>.utm

# Backup current state (if needed for forensics)
cp -R "$VM_PATH" "$VM_PATH.backup.$(date +%Y%m%d)"

# Restore clean disk
cp /backup/path/clean.qcow2 "$VM_PATH/Data/" 

# Update config.plist if needed
# Ensure correct disk reference
```

#### UTM-Specific Recovery Commands
```bash
# Using utmctl
utmctl list
utmctl stop "<VM-Name>"
utmctl start "<VM-Name>"
utmctl status "<VM-Name>"

# Check guest agent status
utmctl guest-properties "<VM-Name>"
```

### 2.3 Parrot OS System Recovery

Parrot OS systems require specific recovery steps to ensure secure restoration.

#### Assessment
- [ ] Identify extent of compromise
- [ ] Determine if full reinstall necessary or selective cleanup
- [ ] Preserve evidence before changes
- [ ] Have clean Parrot OS installation media available

#### Option A: Restore from Snapshot/Backup (Preferred)
```bash
# If using VM snapshot - restore via hypervisor (see above)
# If using filesystem backup
sudo rsync -aAXHv /backup/parrot-clean/ / --exclude={"/dev/*","/proc/*","/sys/*","/tmp/*","/run/*","/mnt/*","/media/*","/lost+found"}
```

#### Option B: Selective Cleanup (If full restore not possible)
```bash
# Change all user passwords
passwd <user>
passwd root  # if root enabled

# Remove suspicious users
cat /etc/passwd | grep -v nologin
userdel -r <suspicious_user>

# Check and clean cron jobs
crontab -l -u <user>
ls -la /etc/cron* /var/spool/cron/
rm /etc/cron.d/<suspicious_file>

# Check SSH authorized_keys
find /home /root -name authorized_keys 2>&1
> /home/<user>/.ssh/authorized_keys  # clear if compromised

# Regenerate SSH host keys (if server keys compromised)
sudo rm /etc/ssh/ssh_host_*
sudo dpkg-reconfigure openssh-server

# Update all packages
sudo apt update && sudo apt upgrade -y
sudo apt dist-upgrade -y

# Check for rootkits
sudo apt install -y chkrootkit rkhunter
sudo chkrootkit
sudo rkhunter --check --sk
```

#### Option C: Fresh Installation (Most Secure for Severe Compromise)
1. Boot from clean Parrot OS installation media
2. Install with full disk encryption if not present
3. Create new user accounts with strong passwords
4. Apply security hardening
5. Re-enroll Wazuh agent
6. Restore only verified clean data

#### Parrot OS Post-Recovery Hardening
```bash
# Enable automatic updates (carefully)
sudo apt install -y unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades

# Configure firewall
sudo apt install -y ufw
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw enable

# Install and configure auditd
sudo apt install -y auditd audispd-plugins
sudo systemctl enable auditd
sudo systemctl start auditd

# Set up file integrity monitoring
# Configure AIDE or use Wazuh syscheck
sudo apt install -y aide
sudo aideinit
```

### 2.4 Network Configuration Recovery

Network configuration must be restored to secure, known-good state.

#### Identify Network Baseline
From lab documentation, expected configuration:
- Host-Only/Internal network for lab isolation
- Wazuh manager on lab network (192.168.64.x range in this lab)
- Agents communicate on TCP 1514/1515
- No direct internet exposure in lab mode

#### Restore Network Configuration

**Linux/Parrot OS:**
```bash
# Check current network config
ip addr show
ip route show
cat /etc/network/interfaces 2>&1
cat /etc/netplan/*.yaml 2>&1  # Ubuntu/modern systems
cat /etc/NetworkManager/system-connections/* 2>&1

# Restore from backup
sudo cp /backup/network/interfaces /etc/network/interfaces
sudo cp /backup/network/resolv.conf /etc/resolv.conf

# Restart networking
sudo systemctl restart networking
# or
sudo nmcli connection down <conn> && sudo nmcli connection up <conn>

# Verify
ping -c 3 192.168.64.1  # Wazuh manager
```

**VM Network Settings:**
```bash
# VirtualBox - restore host-only adapter
VBoxManage modifyvm "<VM>" --nic1 hostonly --hostonlyadapter1 vboxnet0

# UTM - check network mode in config
# Ensure using shared/host-only as appropriate for lab
```

#### Firewall Restoration
```bash
# Reset iptables to secure state
sudo iptables -F
sudo iptables -X
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT ACCEPT

# Allow loopback
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A OUTPUT -o lo -j ACCEPT

# Allow established connections
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow Wazuh agent communication
sudo iptables -A INPUT -p tcp -s 192.168.64.1 --dport 1514 -j ACCEPT
sudo iptables -A OUTPUT -p tcp -d 192.168.64.1 --dport 1514 -j ACCEPT
sudo iptables -A INPUT -p tcp -s 192.168.64.1 --dport 1515 -j ACCEPT
sudo iptables -A OUTPUT -p tcp -d 192.168.64.1 --dport 1515 -j ACCEPT

# Save rules
sudo iptables-save > /etc/iptables/rules.v4
```

#### Network Recovery Validation
- [ ] Correct IP address assigned
- [ ] Default gateway configured properly
- [ ] DNS resolution working
- [ ] Can reach Wazuh manager
- [ ] Wazuh agent can connect (port 1514/1515)
- [ ] No unauthorized routes
- [ ] Firewall rules correct and restrictive
- [ ] No unexpected listening services

---

## 3. Root Cause Analysis (RCA)

### 3.1 Event Timeline (RCA Focus)

Detailed timeline focusing on root causes:

| Time | Event | Root Cause Factor | Evidence |
|---|---|---|---|
| Pre-incident | Valid account `labtester` exists with known/weak credentials in lab | **Human/Config:** Lab credentials not rotated, account present | `/etc/passwd` evidence |
| 2026-10-01 16:22:17, 17:03:06, 17:46:11 | Password changes to `labtester` via sudo | **Enabling:** Password modified before attack | Rule 5402, audit logs |
| 2026-10-01 17:38:44 | Wazuh rule 11 fired - volume anomaly | **Detection:** Early warning existed | Rule 11 alert (unactioned) |
| 2026-10-01 17:48:26-17:50:07 | Brute force attempts (61 failures) | **Attack:** No account lockout/rate limiting | Rules 5760, 5763 |
| 2026-10-01 17:50:09.931 | Successful authentication (rule 40112) | **Vulnerability:** No brute force protection | Correlation rule fired |
| 2026-10-01 17:50:09-17:50:10 | 71ms session | **Attack characteristic:** Automated validation | Rules 5501, 5502 |

### 3.2 Contributing Factors

#### Technical Factors
| Factor | Description | Impact | Remediation |
|---|---|---|---|
| **No brute force protection** | No fail2ban, no account lockout policy, SSH allows unlimited attempts | High - enabled successful compromise | Implement fail2ban or SSH `MaxAuthTries`/`LoginGraceTime` with `MaxStartups` |
| **Weak/lab credentials** | `labtester` account had guessable credentials in lab environment | High - primary attack vector | Enforce strong passwords, use key-based auth, disable password auth |
| **Lack of rate limiting** | SSH and PAM not configured for rate limiting | High - allowed rapid-fire attempts | Configure `pam_faillock` or fail2ban |
| **Self-referential attack possible** | Source IP same as target in lab (192.168.64.3) | Medium - but demonstrates issue | Network segmentation, different attack source in tests |
| **Early warning unactioned** | Rule 11 fired 9m42s before compromise but no response | High - missed opportunity | Implement alert escalation, on-call procedures |
| **Limited endpoint telemetry** | Linux agent lacks detailed process monitoring beyond journald | Medium - limits post-compromise visibility | Enhance auditd rules, process monitoring |

#### Procedural/Organizational Factors
| Factor | Description | Impact | Remediation |
|---|---|---|---|
| **No automated response** | Active Response disabled in Wazuh configuration | High - manual intervention required | Enable AR with approval workflow |
| **Notifications disabled** | Email alerts not configured | High - alerts may go unnoticed | Configure critical alert notifications |
| **Lack of playbook execution** | IR playbook existed but not actively followed during incident | Medium - delayed formal response | Mandatory playbook use, IR drills |
| **Monitoring platform unmonitored** | macOS host running Wazuh stack has no agent | High - single point of failure | Deploy Wazuh agent to SIEM host |
| **Insufficient logging** | Some telemetry gaps (no syscollector inventory on agent 007 noted) | Medium - limits investigation scope | Enable comprehensive logging modules |

### 3.3 Technical Findings from Parrot OS Tools

Analysis using Parrot OS forensic tools (documented procedures):

#### From Journal Analysis (journalctl)
```bash
journalctl -u ssh --since "2026-10-01 17:40:00" --until "2026-10-01 18:00:00" --no-pager
```
**Findings:**
- Clear pattern of failed authentication attempts
- Multiple concurrent SSH sessions from same source (parallel connections)
- Successful authentication at 17:50:09.931
- Session duration only 71ms indicating non-interactive access
- No subsequent commands or privilege escalation logged in journald

#### From Network Analysis (ss/netstat)
**Findings:**
- At time of attack, multiple established SSH connections
- Connections from 192.168.64.3 to port 22
- Pattern consistent with brute force tooling (multiple simultaneous connections)

#### From Process Analysis (ps)
**Findings:**
- sshd processes handling multiple connections
- No suspicious child processes spawned during 71ms session
- Post-session: no unusual processes attributable to labtester

#### From File Integrity (FIM/syscheck)
**Findings:**
- /etc/shadow modified at 03:54:17 on 10-02
- Correlated with sudo passwd commands (T1,T2,T4) - properly attributed as authorized
- Demonstrates FIM value when properly correlated

#### From Memory Analysis (Core Dump - Method A)
**Findings:**
- Successfully captured kernel core of test process (400KB ELF aarch64)
- Methodology validated for memory acquisition
- Full RAM capture with Volatility pending Parrot boot completion

### 3.4 Root Cause Determination

**Primary Root Cause:** Absence of brute force protection mechanisms on SSH service combined with valid credentials, allowing unlimited authentication attempts until successful compromise.

**Contributing Root Causes:**
1. No account lockout or rate limiting configured
2. Password-based authentication enabled without protection
3. Lack of automated alerting/response for early warning indicators
4. Insufficient monitoring of the monitoring infrastructure
5. Lab environment credentials not following security best practices

**Attack Path:**
```
Valid account exists (labtester) → Password changed/enabled → 
No brute force protection → Unlimited attempts (61 failures) → 
Credentials guessed/successful auth → Brief automated session (71ms) → 
No post-compromise activity observed
```

---

## 4. Recovery Validation Checklist with Testing Procedures

### 4.1 Pre-Recovery Validation
- [ ] **Evidence secured:** All evidence collected, hashed, and stored securely
- [ ] **Incident contained:** No active threat, containment measures in place or removed per plan
- [ ] **Backups available:** Clean snapshots/backups verified and accessible
- [ ] **Recovery plan approved:** Documented and reviewed
- [ ] **Change window scheduled:** Appropriate timing for recovery activities

### 4.2 VirtualBox/UTM Environment Restoration Checklist

#### VM Restoration
- [ ] **Snapshot restored:** Pre-incident snapshot successfully restored OR clean image deployed
- [ ] **VM boots:** System boots to login prompt without errors
- [ ] **Hardware config:** CPU/memory/network settings correct
- [ ] **Disk integrity:** No corruption detected, filesystem checks pass

**Test Procedure:**
```bash
# Boot VM and check
uptime
dmesg | tail -20
fsck -n /dev/sda1 2>&1 | tail -5
```

#### Network Restoration
- [ ] **Interfaces up:** All network interfaces operational
- [ ] **IP configuration:** Correct IP addresses assigned
- [ ] **Connectivity:** Can ping gateway and lab hosts
- [ ] **DNS:** Name resolution functional
- [ ] **Routing:** Routes correct

**Test Procedure:**
```bash
ip addr show
ip route show
ping -c 4 192.168.64.1
nslookup google.com 2>&1 | tail -3  # or internal DNS
```

### 4.3 Parrot OS System Recovery Checklist

#### System Integrity
- [ ] **OS boots cleanly:** No errors in boot process
- [ ] **Users/accounts:** Only authorized accounts present
- [ ] **Passwords reset:** All potentially compromised accounts have new strong passwords
- [ ] **SSH keys:** Authorized_keys reviewed and cleaned, host keys regenerated if needed
- [ ] **Services:** Only necessary services running

**Test Procedure:**
```bash
systemctl list-units --type=service --state=running
cat /etc/passwd | grep -v nologin
last -n 10
lastlog
```

#### Security Hardening
- [ ] **Updates applied:** System fully patched
- [ ] **Firewall enabled:** iptables/ufw configured and active
- [ ] **SSH hardened:** Key-based auth preferred, strong ciphers
- [ ] **Audit logging:** auditd enabled and configured
- [ ] **File integrity:** AIDE or Wazuh syscheck configured

**Test Procedure:**
```bash
apt list --upgradable 2>&1 | wc -l  # Should be 0 or minimal
ufw status verbose
sshd -T | grep -E "(PasswordAuthentication|PermitRootLogin|MaxAuthTries)"
systemctl status auditd
```

#### Malware/Rootkit Scan
- [ ] **chkrootkit:** No rootkits detected
- [ ] **rkhunter:** Clean scan
- [ ] **Manual inspection:** No suspicious processes/files

**Test Procedure:**
```bash
sudo chkrootkit 2>&1 | grep -i warning
sudo rkhunter --check --sk 2>&1 | grep -E "(Warning|Dangerous)"
ps aux | grep -E "(nc|netcat|socat)" | grep -v grep
find /tmp /var/tmp -type f -mtime -3 2>&1
```

### 4.4 Network Configuration Recovery Checklist

- [ ] **Lab network isolated:** Proper segmentation maintained
- [ ] **Wazuh connectivity:** Agent can reach manager on 1514/1515
- [ ] **Firewall rules:** Restrictive, only necessary ports open
- [ ] **No unauthorized listeners:** Only expected services listening
- [ ] **DNS correct:** Resolves internal and external as needed
- [ ] **VPN/remote access:** Secure if enabled

**Test Procedure:**
```bash
# Check listening ports
ss -tulnp | grep LISTEN

# Test Wazuh agent connectivity
nc -zv 192.168.64.1 1514
nc -zv 192.168.64.1 1515

# Check agent status on Wazuh manager
curl -k -u $WAZUH_USER:$WAZUH_PASS "https://localhost:55000/agents" | jq '.data.affected_items[] | {id,name,status}'

# Firewall test
iptables -L -n -v | head -30
```

### 4.5 Wazuh/SIEM Integration Validation

- [ ] **Agent connected:** All agents show as active in Wazuh dashboard
- [ ] **Log collection:** Events flowing to indexer
- [ ] **Alerts generating:** Normal alerts appearing
- [ ] **Dashboard accessible:** Wazuh dashboard functional
- [ ] **Triage API operational:** Health endpoint responding
- [ ] **Reports generating:** Agent can create reports

**Test Procedure:**
```bash
# Check Wazuh API
curl -k -u $WAZUH_USER:$WAZUH_PASS "https://localhost:55000/manager/status" | jq

# Check indexer
curl -k -u $INDEXER_USER:$INDEXER_PASS "https://localhost:9200/_cluster/health" | jq

# Check triage API
curl -s "http://127.0.0.1:8080/api/v1/health" | jq

# Check recent alerts
curl -k -u $INDEXER_USER:$INDEXER_PASS -X POST "https://localhost:9200/wazuh-alerts-*/_search" -H 'Content-Type: application/json' -d '{"size":5,"sort":[{"timestamp":{"order":"desc"}}]}' | jq '.hits.hits[0:3]'
```

### 4.6 Comprehensive Recovery Test Suite

| Test | Expected Result | Pass/Fail | Notes |
|---|---|---|---|
| **VM Boot** | System starts successfully | ☐ | Check logs for errors |
| **Network Connectivity** | Ping gateway and manager succeeds | ☐ | All interfaces up |
| **SSH Access** | Can connect with key-based auth | ☐ | Password auth disabled if hardened |
| **Wazuh Agent** | Agent active in dashboard | ☐ | Check within 2 minutes |
| **Log Ingestion** | Events appearing in indexer | ☐ | Generate test event |
| **Firewall** | Only allowed ports open | ☐ | Scan from another host |
| **User Accounts** | Only authorized users exist | ☐ | Review /etc/passwd |
| **Sudo Access** | Proper sudoers configuration | ☐ | Check sudoers files |
| **File Integrity** | FIM baseline updated/clean | ☐ | Wazuh syscheck status |
| **No Malware** | Rootkit scans clean | ☐ | chkrootkit + rkhunter |
| **Services** | Expected services running only | ☐ | Review running services |

### 4.7 Recovery Validation Sign-Off

| Role | Name | Signature | Date | Approval |
|---|---|---|---|---|
| **Incident Lead** | Kyrell Green | ___________ | ____/____/____ | ☐ Approved ☐ Denied |
| **Security Analyst** | ___________ | ___________ | ____/____/____ | ☐ Approved ☐ Denied |
| **System Owner** | ___________ | ___________ | ____/____/____ | ☐ Approved ☐ Denied |

**Validation Notes:** All recovery tests must pass before returning system to production/use. Any failures must be documented and remediated.

---

## 5. IR Process Improvement Recommendations

Based on lessons learned from incident SOC-CASE-2026-0142, the following improvements are recommended.

### 5.1 Detection Improvements

| Improvement | Priority | Effort | Description | Expected Benefit |
|---|---|---|---|---|
| **Deploy custom correlation rules** | High | Low | Implement rules 100030 (success after failures), 100031 (distributed brute force), 100032 (critical FIM) as documented | Faster, more specific detection of attack patterns |
| **Tune early warning alerts** | High | Low | Make rule 11 (volume anomaly) page/alert on-call with lower threshold | Prevent similar unactioned early warnings |
| **Add brute force specific rules** | High | Low | Enhance detection for parallel connection attacks | Better detection of modern brute force techniques |
| **Implement anomaly detection** | Medium | High | Add baseline-based anomaly detection for auth patterns | Detect novel attack patterns |
| **Enable MITRE ATT&CK mapping** | Medium | Low | Ensure all custom rules have proper MITRE tags | Better threat intelligence integration |

### 5.2 Response Improvements

| Improvement | Priority | Effort | Description | Expected Benefit |
|---|---|---|---|---|
| **Enable Active Response** | High | Medium | Configure AR with approval workflow integration | Automated containment capability |
| **Configure notifications** | High | Low | Enable email/SMS/Slack alerts for critical/high severity | Faster notification of serious incidents |
| **Integrate playbook automation** | High | High | Extend triage API to trigger playbook actions | Consistent, documented response |
| **Create IR runbook checklist** | High | Low | Make playbook steps executable checklist | Ensure no steps missed under pressure |
| **Establish on-call rotation** | Medium | Medium | Define escalation procedures and contacts | 24/7 response capability |
| **Practice IR drills** | High | Medium | Quarterly tabletop exercises using this incident | Maintain readiness |

### 5.3 Prevention Improvements

| Improvement | Priority | Effort | Description | Expected Benefit |
|---|---|---|---|---|
| **Implement fail2ban** | High | Low | Deploy fail2ban for SSH with aggressive banning | Block brute force attempts automatically |
| **Harden SSH configuration** | High | Low | Disable password auth, use key-based auth, MaxAuthTries=3, LoginGraceTime=30 | Eliminate password brute force vector |
| **Configure PAM faillock** | High | Low | Enable account lockout after failed attempts | Additional brute force protection |
| **Enforce strong password policy** | High | Low | Implement pwquality, password history, complexity requirements | Harder to guess credentials |
| **Network segmentation** | High | Medium | Properly segment lab and production networks | Limit lateral movement and attack scope |
| **Credential management** | High | Medium | Regular rotation, unique credentials per environment | Reduce credential reuse risk |

### 5.4 Monitoring & Visibility Improvements

| Improvement | Priority | Effort | Description | Expected Benefit |
|---|---|---|---|---|
| **Monitor SIEM platform** | High | Low | Deploy Wazuh agent to macOS host running Wazuh stack | Eliminate blind spot |
| **Enhance endpoint telemetry** | High | Medium | Deploy auditd with comprehensive rules, enable process monitoring | Better post-compromise visibility |
| **Integrate Suricata** | High | Medium | Enable network IDS integration with Wazuh | Network-level threat detection |
| **Add syslog forwarding** | Medium | Low | Ensure all logs centralized | Complete audit trail |
| **Implement log retention** | Medium | Medium | Configure proper log retention and rotation | Meet compliance requirements |
| **Add user behavior analytics** | Medium | High | Baseline normal user behavior, alert on anomalies | Detect compromised accounts |

### 5.5 Documentation & Training Improvements

| Improvement | Priority | Effort | Description | Expected Benefit |
|---|---|---|---|---|
| **Update all playbooks** | High | Low | Incorporate lessons learned from this incident | More effective future response |
| **Create evidence templates** | High | Low | Standardize evidence collection forms | Consistent chain of custody |
| **IR training program** | Medium | Medium | Train all SOC personnel on updated procedures | Improved response quality |
| **Create quick reference cards** | Medium | Low | Laminated cards for common procedures | Faster response under pressure |
| **Maintain lessons learned database** | Medium | Low | Track all incidents and improvements | Continuous improvement |
| **Cross-train team members** | Medium | Medium | Ensure multiple people can handle each role | Redundancy and coverage |

### 5.6 Implementation Roadmap

| Phase | Timeline | Focus | Key Deliverables |
|---|---|---|---|
| **Phase 1: Critical Fixes** | Week 1-2 | Prevention & Response | fail2ban, SSH hardening, notifications enabled, Active Response configured |
| **Phase 2: Detection Enhancement** | Week 3-4 | Rules & Monitoring | Custom rules deployed, SIEM host monitored, early warning escalation |
| **Phase 3: Visibility** | Month 2 | Telemetry | auditd enhanced, Suricata integrated, comprehensive logging |
| **Phase 4: Automation & Drills** | Month 3 | Process Maturity | Playbook automation, IR drills, metrics tracking |

### 5.7 Lessons Learned Summary

**What Went Well:**
- Excellent detection and correlation by Wazuh SIEM
- Full attack chain reconstruction possible with multi-source correlation
- Proper evidence collection following forensic principles
- FIM correlation successfully distinguished authorized vs unauthorized changes
- Comprehensive documentation created throughout investigation

**What Could Be Improved:**
- Early warning alerts need to be acted upon more aggressively
- Automated response capabilities missing
- Limited endpoint telemetry on Linux systems
- SIEM infrastructure itself not adequately monitored
- Password-based authentication too vulnerable without additional controls
- Lack of formal notification procedures for critical alerts

**Key Takeaway:** The defense-in-depth approach with correlation is valuable, but prevention controls (brute force protection) and automated response are critical gaps that must be addressed to prevent similar incidents.

---

## 6. Conclusion

This post-incident procedures document provides comprehensive guidance for recovery, analysis, validation, and improvement:

✅ **System Recovery Procedures** - Detailed procedures for VirtualBox/UTM restoration, Parrot OS recovery (snapshot/cleanup/reinstall), and network configuration recovery with specific commands  
✅ **Root Cause Analysis** - Complete timeline, contributing factors (technical and procedural), technical findings from Parrot OS tools (journalctl, ss, ps, FIM), and primary/contributing root cause determination  
✅ **Recovery Validation Checklist** - Comprehensive checklist with testing procedures for VM restoration, Parrot OS recovery, network recovery, Wazuh integration, and final sign-off  
✅ **IR Process Improvement Recommendations** - Prioritized recommendations across detection, response, prevention, monitoring, and documentation with implementation roadmap and lessons learned  

All procedures are evidence-based from the actual incident (SOC-CASE-2026-0142), practical for the lab environment, and aligned with industry best practices (NIST SP 800-61, SANS IR methodologies).
