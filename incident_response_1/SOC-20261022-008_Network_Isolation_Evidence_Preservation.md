# Incident Review & Response: SOC-20261022-008
**Report Reviewed:** `/Users/Adult/Desktop/Kai-DAE 6Month Project Files/ai-agentic-soc/reports/SOC-20261022-008.html`  
**Incident Type:** SSH Brute Force (Self-Generated)  
**Affected Host:** Kali Linux (agent 002, 192.168.64.3)  
**Target:** labtester account  
**Severity:** Medium (per report)  
**MITRE:** T1110 (Brute Force)

## Incident Review Summary
- Verified SSH brute force from localhost (192.168.64.3) targeting user 'labtester'
- 33 failed attempts in ~16 seconds, rule 100002 triggered 3 times
- No successful authentication observed
- Source equals agent IP (self-generated in lab environment)
- Related: legitimate root logins/sudo occurred earlier, unrelated


## 1. Network Isolation Procedures in Kali Linux

### 1.1 Network Interface Configuration for Isolation

Identify interfaces:
```bash
ip addr show
ip link show
nmcli device status
```

Isolation strategies:
```bash
# Option A: Bring down non-essential interfaces (keep loopback)
sudo ip link set eth0 down  # if not needed

# Option B: Assign static IP with no gateway (isolate from network)
sudo ip addr flush dev eth0
sudo ip addr add 192.168.100.10/24 dev eth0
# Do NOT add default gateway
sudo ip link set eth0 up

# Option C: Use host-only-like isolation
# Verify no default route
ip route show
```

Verification:
```bash
ping -c 3 8.8.8.8  # Should fail if isolated
ping -c 3 192.168.64.1  # Test host connectivity as needed
```

### 1.2 Basic Firewall Rules Implementation (iptables/nftables)

#### Using iptables
```bash
# Flush existing rules
sudo iptables -F
sudo iptables -X
sudo iptables -t nat -F
sudo iptables -t mangle -F

# Set default policies to DROP
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT DROP

# Allow loopback
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A OUTPUT -o lo -j ACCEPT

# Allow established/related connections
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow SSH only from host (if needed for management)
sudo iptables -A INPUT -p tcp -s 192.168.64.1 --dport 22 -j ACCEPT
sudo iptables -A OUTPUT -p tcp --sport 22 -d 192.168.64.1 -j ACCEPT

# Allow DNS only if needed (generally block during isolation)
# sudo iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
# sudo iptables -A INPUT -p udp --sport 53 -j ACCEPT

# Log dropped packets (optional)
sudo iptables -A INPUT -j LOG --log-prefix "IPTABLES-DROP-INPUT: "
sudo iptables -A OUTPUT -j LOG --log-prefix "IPTABLES-DROP-OUTPUT: "

# Save rules
sudo iptables-save | sudo tee /etc/iptables/rules.v4
```

#### Using nftables (modern alternative)
```bash
sudo nft flush ruleset
sudo nft add table inet filter
sudo nft add chain inet filter input { type filter hook input priority 0 \; policy drop \; }
sudo nft add chain inet filter forward { type filter hook forward priority 0 \; policy drop \; }
sudo nft add chain inet filter output { type filter hook output priority 0 \; policy drop \; }
sudo nft add rule inet filter input iif lo accept
sudo nft add rule inet filter output oif lo accept
sudo nft add rule inet filter input ct state established,related accept
sudo nft add rule inet filter output ct state established,related accept
sudo nft list ruleset | sudo tee /etc/nftables.conf.d/isolation.nft
```

Verification:
```bash
sudo iptables -L -v -n
sudo nft list ruleset
```

### 1.3 Network Segmentation using VirtualBox Networking

For VirtualBox VMs (or UTM equivalent), segmentation options:

| Network Mode | Use Case | Isolation Level |
|--------------|----------|-----------------|
| NAT | Internet access through host | Low isolation, host can reach VM |
| NAT Network | Isolated network with NAT | Moderate, VMs can talk to each other |
| Bridged | VM on same LAN as host | Low isolation |
| Internal Network | VM-to-VM only, no host/internet | High isolation |
| Host-Only | VM-to-host only | High isolation from external network |

Recommended for compromised host:
1. **Immediate isolation:** Switch to Internal Network or Host-Only
2. **Forensics mode:** Host-Only with dedicated forensics workstation
3. **Disable all network adapters** if not needed for evidence transfer

In VirtualBox:
- VM Settings → Network → Adapter 1 → Attached to: "Internal Network" or "Host-only Adapter"
- Disable unused adapters
- Ensure no promiscuous mode unless needed for capture

## 2. Evidence Preservation using Kali Linux Forensic Tools

### 2.1 File System Artifacts

Create evidence directory:
```bash
sudo mkdir -p /home/kali/evidence/SOC-20261022-008/{fs,net,mem,logs}
cd /home/kali/evidence/SOC-20261022-008
```

Capture critical files with preservation:
```bash
# Auth logs
sudo cp -a /var/log/auth.log fs/ 2>/dev/null || sudo cp -a /var/log/auth.log.* fs/
sudo cp -a /var/log/secure fs/ 2>/dev/null

# System logs
sudo cp -a /var/log/syslog fs/ 2>/dev/null
sudo journalctl --since -24h > logs/journalctl_24h.log

# User/session info
last > logs/last.txt
lastlog > logs/lastlog.txt
w > logs/who.txt
who > logs/who_simple.txt
cat /etc/passwd > fs/passwd
cat /etc/shadow > fs/shadow  # handle carefully
cat /etc/group > fs/group

# SSH artifacts
sudo cp -a /etc/ssh fs/ 2>/dev/null
sudo cp -a /root/.bash_history fs/root_bash_history 2>/dev/null
cp ~/.bash_history fs/user_bash_history 2>/dev/null
```

Generate hashes:
```bash
find fs/ logs/ -type f -exec sha256sum {} \; > evidence_fs.sha256
sha256sum fs/* logs/* > manifest.sha256
```

Timeline (optional):
```bash
which fls mactime 2>&1 | head -2
# If available: fls -r /dev/sda1 > timeline.body && mactime -b timeline.body > timeline.csv
```

### 2.2 Network Traffic Captures

```bash
# Identify interface
ip link show

# Capture all traffic
sudo tcpdump -i eth0 -s 0 -w net/full_capture_$(date +%Y%m%d_%H%M%S).pcap &
TCPDUMP_PID=$!
sleep 60  # capture window
sudo kill $TCPDUMP_PID

# Targeted capture for SSH
sudo tcpdump -i eth0 port 22 -s 0 -w net/ssh_capture.pcap

# Verify capture
tcpdump -r net/full_capture_*.pcap | wc -l
capinfos net/*.pcap 2>&1 | head -20
```

### 2.3 Basic Memory Dumps

Options for memory acquisition on Kali:
```bash
# Check available tools
which avml lime-4* insmod gcore 2>&1 | head -10

# Using AVML (Microsoft) if installed
# sudo avml net/memory.avml

# Using /proc/kcore (limited)
# sudo dd if=/proc/kcore of=mem/kcore.dump bs=1M count=1024

# Dump running processes
mkdir -p mem/procs
for pid in $(ps -e -o pid=); do
  gcore -o mem/procs/core $pid 2>/dev/null
done 2>&1 | tail -5

# Hash memory artifacts
sha256sum mem/* net/*.pcap fs/* 2>&1 | tee evidence_all.sha256
```

**Note:** Full memory acquisition may require kernel modules (LiME) or specific tools. Document what is available and attempted.

## 3. Verification & Checklist

- [ ] Interfaces identified and isolation applied
- [ ] Firewall rules implemented and tested (default DROP)
- [ ] Network segmentation configured per VirtualBox/UTM settings
- [ ] External connectivity blocked (ping 8.8.8.8 fails)
- [ ] Host management access controlled
- [ ] File system artifacts copied with preservation
- [ ] Hashes generated for all evidence
- [ ] Network capture completed and verified
- [ ] Memory dump attempted/documented
- [ ] Evidence stored in isolated location
- [ ] All actions logged with timestamps

## 4. Restoration Notes
- Document original interface configuration before changes
- Save original iptables rules: `iptables-save > /root/iptables.backup.$(date +%s)`
- Test restoration in isolated environment
- Remove isolation only after investigation complete and approval received

## References
- SOC-20261022-008 report (AI-Agentic SOC Triage Engine)
- Kali Linux documentation
- NIST SP 800-61 (Incident Handling Guide)
- Wazuh FIM documentation
