# Incident Response and Containment Playbook (Parrot OS / VirtualBox)

**Case reference:** `SOC-CASE-2026-0142`  
**Case prefix:** `IR-CONTAIN-YYYYMMDDTHHMMSSZ`  
**Evidence root:** `incident_response_1/containment_lab/evidence/<CASE_ID>/`  
**Automation:** `incident_response_1/containment_lab/scripts/`  
**Status:** procedures and automation statically validated 2026-10-25; live Parrot execution pending.

## 1. Scope

This playbook covers four containment capabilities:

1. **Host isolation** by moving a VirtualBox NIC to `IR-LAB-QUARANTINE` or disconnecting its link.
2. **Traffic blocking** with nftables/iptables against a confirmed malicious IP/CIDR.
3. **Network quarantine posture** for the forwarding path.
4. **Service shutdown** for an affected service, while preserving logging and forensic services.

It also defines the evidence-preservation gates that must happen before destructive containment.

## 2. Actual Topology

| Network | VirtualBox type | CIDR | Parrot address | Purpose |
|---|---|---|---|---|
| Management | Host-only | `192.168.56.0/24` | `192.168.56.10` | Analyst access |
| Core | Internal `IR-LAB-CORE` | `192.168.64.0/24` | `192.168.64.10` | Kali/affected hosts |
| Protected | Internal `IR-LAB-PROTECTED` | `10.20.20.0/24` | `10.20.20.10` | Sensitive assets |
| Quarantine | Internal `IR-LAB-QUARANTINE` | `10.20.99.0/24` | `10.20.99.20` if used | Isolated hosts |
| NAT | NAT | DHCP | `enp0s3` | Tool/package access |

Existing project endpoints used for context:

| Agent | Host | Address |
|---|---|---|
| `002` | Kali | `192.168.64.3` |
| `008` | Ubuntu | `192.168.64.2` |
| `007` | Windows `DESKTOP-VCKJCPV` | `10.11.1.232` |
| manager | Wazuh manager | `192.168.64.1` |

The VirtualBox internal network is isolated from the Windows host by design. The existing Wazuh
manager is not automatically reachable from `IR-LAB-CORE`; validate telemetry separately or place a
manager/collector on the core segment.

## 3. Roles

| VM | Role | Actual state |
|---|---|---|
| `PARROT-IR` | Parrot OS IR/forensic host | **Planned**; not present in current VirtualBox |
| `Kali` | Affected/test victim; also existing Wazuh agent `002` | Registered, powered off, `nic1=nat`, `nic2=none` |
| `PROTECTED-01` | Protected test asset | Planned |
| `ATTACKER-01` | Simulated adversary | Optional; known documentation IP `203.0.113.77` |

## 4. Phase 0: Preparation

- [ ] Confirm case ID and scope; record the current UTC time.
- [ ] Capture preflight state: `sudo ./scripts/00-preflight.sh`.
- [ ] Confirm Parrot NIC layout: `ip -br link`, `ip -br addr`, `ip route`.
- [ ] Confirm VirtualBox host-only adapter exists: `VBoxManage list hostonlyifs`.
- [ ] Confirm `Kali` is powered off before NIC network changes: `VBoxManage list runningvms`.
- [ ] Decide whether volatile evidence acquisition must precede isolation.

Evidence: `preflight.txt`, `preflight.meta`, `vbox-network-isolation.txt`.

## 5. Phase 1: Network Isolation

### 5.1 Configure Parrot segmented interfaces

```bash
sudo ./scripts/10-configure-network.sh --router --apply
ip -br addr
ip route
sysctl net.ipv4.ip_forward
```

Expected Parrot addresses: `192.168.56.10/24`, `192.168.64.10/24`, `10.20.20.10/24`. The NAT
interface remains the default route; the lab interfaces use `ipv4.never-default yes`.

### 5.2 Attach VMs to VirtualBox segments

Host-only setup on Windows:

```powershell
powershell -ExecutionPolicy Bypass -File configs\virtualbox\lab-network.ps1 -Apply
```

Attach Kali NIC2 to the core network while the VM is powered off:

```powershell
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" modifyvm "Kali" --nic2=intnet --intnet2=IR-LAB-CORE --nic-type2=82540EM --nic-promisc2=deny
```

Check: `VBoxManage showvminfo "Kali" --machinereadable`.

### 5.3 Isolate an affected VM

Dry run:

```bash
./scripts/30-network-isolation-vbox.sh --move-quarantine --vm Kali --nic 2
```

Powered-off isolation:

```bash
./scripts/30-network-isolation-vbox.sh --move-quarantine --vm Kali --nic 2 --apply
```

Running-VM link cut:

```bash
./scripts/30-network-isolation-vbox.sh --live-disconnect --vm Kali --nic 2 --apply
```

Approval: the script prompts unless `IR_ASSUME_YES=1` is set. The VirtualBox `modifyvm` path refuses
to act on a running VM; use `controlvm setlinkstateN off` first.

Evidence: `vbox-network-isolation.txt` with the planned/applied command and `showvminfo`.

## 6. Phase 2: Firewall Baseline

```bash
sudo ./scripts/20-firewall-baseline.sh
sudo ./scripts/20-firewall-baseline.sh --apply --persist --yes
sudo nft list table inet ir_filter
```

Baseline behavior in `configs/nftables/ir-baseline.nft`:

- default drop on input and forward; output accepts except blocked destinations
- loopback, established/related, invalid drop, DHCP, limited ICMP
- management SSH/DNS from `192.168.56.0/24`
- block `192.168.64.0/24 -> 10.20.20.0/24`
- block `192.168.64.0/24 -> 10.11.1.232`
- log and drop unauthorized input/forward traffic

Rollback:

```bash
sudo ./scripts/20-firewall-baseline.sh --rollback --yes
```

Evidence: `firewall-baseline.txt`, `nft-ruleset-before.txt`, `ir-firewall.service` status.

## 7. Phase 3: Evidence Preservation

Preserve volatile evidence before aggressive blocking or shutdown when feasible:

```bash
sudo ./scripts/40-evidence-preserve.sh --snapshot-fs --pcap-iface enp0s9 --mem
```

Artifacts:

- `snapshots/` — compressed `/var/log`, `/var/ossec/logs`, `/var/log/audit` where present
- `pcaps/` — 10-second tcpdump capture per requested interface
- `memdump/` — AVML, LiME, or `/proc/kcore` attempt with the method recorded
- system state — interfaces, routes, neighbours, sockets, processes, mounts, open files
- `chain-of-custody.txt` — operator, host, start/end, SHA-256 per artifact
- `manifest.sha256` — hashes of all case files

If a tool is unavailable, the report records the limitation. Do not describe a skipped collection as
a successful acquisition.

## 8. Phase 4: Traffic Blocking and Quarantine

Block a confirmed attacker IP/CIDR:

```bash
sudo ./scripts/50-containment-playbook.sh --block-ip 203.0.113.77 --confirm
sudo nft list table inet ir_contain
```

Tighten the forward path:

```bash
sudo ./scripts/50-containment-playbook.sh --isolate-network --confirm
```

The `ir_contain` set uses a four-hour timeout for blocked entries. The quarantine posture flushes the
forward chain, accepts established/related traffic, drops invalid traffic, logs, then drops.

Evidence: `containment-playbook.txt`, `containment-actions.log`.

## 9. Phase 5: Service Shutdown

Enumerate before acting:

```bash
ss -tulpn
systemctl list-units --type=service --state=running
systemctl list-dependencies <service>
journalctl --since "-15 min" --no-pager
```

Stop and disable only the affected service:

```bash
sudo ./scripts/50-containment-playbook.sh --shutdown-services --service apache2 --confirm
systemctl status apache2 --no-pager
ss -tulpn | grep ':80 '
```

Do not stop the Wazuh agent, logging stack, or forensic collection service unless the incident
commander approves the loss of telemetry.

## 10. Phase 6: Verification

```bash
sudo ./scripts/60-verify.sh --strict
```

Verify:

- interface addresses and routes match the design
- `nft list table inet ir_filter` shows the expected policy and counters
- blocked destination is unreachable from the core segment
- quarantined VM has no core/protected connectivity
- service is stopped, disabled, and no longer listening
- all evidence files are present and hashed

## 11. Evidence and Rubric Mapping

| Requirement | Implementation | Evidence |
|---|---|---|
| Network interface configuration | `10-configure-network.sh`, netplan reference | `network-configuration.txt`, `ip -br addr` |
| Basic firewall rules | `20-firewall-baseline.sh`, nftables/iptables configs | `firewall-baseline.txt`, `nft list ruleset` |
| VirtualBox segmentation | host-only script, `30-network-isolation-vbox.sh` | `vbox-network-isolation.txt`, `showvminfo` |
| Filesystem evidence | log snapshots and system state | `snapshots/`, `evidence-preservation.txt` |
| Network evidence | tcpdump captures | `pcaps/`, `capinfos`, hashes |
| Memory evidence | AVML/LiME/kcore attempt | `memdump/`, chain of custody |
| Host isolation | `--block-host-vbox` / `--move-quarantine` | containment log and VM state |
| Traffic blocking | `--block-ip`, `--isolate-network` | nft table, counters, log |
| Service shutdown | `--shutdown-services` | systemctl status and socket check |
| Documentation/functionality | main document, README, validation report | `evidence/validation/` |

## 12. Stop Conditions and Escalation

- Stop and escalate if containment would destroy the only copy of volatile evidence.
- Stop if the action could cut the management path used by the incident commander.
- Stop if the target cannot be confirmed; do not block a documentation IP as if it were a live
  attacker.
- Record the decision, approver, timestamp, and reason for every destructive action.
- Preserve the original evidence; work from copies for analysis.

## 13. Live Status

| Item | Status |
|---|---|
| Kit files, scripts, configs, static checks | Complete; 36 pass / 1 warning / 0 failures |
| PowerShell host-only detection | Complete and parsed with Windows PowerShell |
| VirtualBox host-only adapter | Present: `192.168.56.1/24` |
| Kali VM | Registered and powered off; NIC2 not yet attached |
| Parrot VM | Not present in VirtualBox; live steps pending |
| nftables apply and counters | Pending Parrot |
| pcap, memory dump, chain of custody | Pending Parrot |
| Live host isolation and blocked-connectivity proof | Pending Parrot and segmented VMs |
