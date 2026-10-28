# Incident Response and Containment Lab Kit (Parrot OS / VirtualBox)

**Status:** kit authored and statically validated 2026-10-25. Live Parrot OS execution and
live firewall/capture/memory evidence are **pending** until the Parrot VM is built in VirtualBox.

This kit supports the `incident_response_1/Incident Response and Containment.md` deliverable:

- network interface configuration on a segmented Parrot OS forensic host
- basic nftables/iptables firewall rules with default-deny and scoped allows
- VirtualBox host-only and internal-network segmentation
- evidence preservation for filesystem artifacts, network traffic, and basic memory dumps
- a containment playbook for host isolation, traffic blocking, and service shutdown
- repeatable evidence collection with hashes and a chain of custody

## Actual Project Context

The existing 6-month project lab uses case `SOC-CASE-2026-0142` and these real Wazuh endpoints:

| Agent | Host | Address |
|---|---|---|
| `002` | Kali | `192.168.64.3` |
| `008` | Ubuntu | `192.168.64.2` |
| `007` | Windows `DESKTOP-VCKJCPV` | `10.11.1.232` |
| manager | Wazuh manager | `192.168.64.1` |

The current containment host is Windows with VirtualBox `7.2.16r174877`. VirtualBox currently has
one registered VM, `Kali`, powered off. It has `nic1=nat` and `nic2..8=none`. Parrot is not
registered in this VirtualBox installation. The earlier project work staged a Parrot 7.4 arm64 UTM
bundle on a macOS host; that is not a VirtualBox image.

The kit therefore uses the project's real core network `192.168.64.0/24` so the Kali victim address
stays continuous, and adds isolated VirtualBox segments for management, protected assets, and
quarantine. A VirtualBox internal network has no host routing by design, so Wazuh telemetry needs an
additional NAT/host-only path or a manager on the core segment. Do not assume the existing manager
is reachable inside `IR-LAB-CORE` until it is tested.

## Topology

| Segment | VirtualBox network | CIDR | Parrot address | Purpose |
|---|---|---|---|---|
| Management | Host-only `VirtualBox Host-Only Ethernet Adapter` | `192.168.56.0/24` | `192.168.56.10` | Analyst access |
| Core | Internal `IR-LAB-CORE` | `192.168.64.0/24` | `192.168.64.10` | Kali/affected hosts |
| Protected | Internal `IR-LAB-PROTECTED` | `10.20.20.0/24` | `10.20.20.10` | Sensitive test assets |
| Quarantine | Internal `IR-LAB-QUARANTINE` | `10.20.99.0/24` | `10.20.99.20` (if used) | Isolated compromised hosts |
| NAT | VirtualBox NAT | DHCP | `enp0s3` | Tool/package access |

`Parrot` uses `enp0s3` NAT, `enp0s8` management, `enp0s9` core, and `enp0s10` protected.
The configuration in `configs/netplan/50-ir-lab.yaml` is the declarative reference; the applied path
is `scripts/10-configure-network.sh`, which uses NetworkManager because Parrot ships with it.

## Layout

```text
containment_lab/
├── lab.env
├── configs/
│   ├── iptables/ir-baseline.rules
│   ├── netplan/50-ir-lab.yaml
│   ├── nftables/ir-baseline.nft
│   └── virtualbox/lab-network.ps1
├── scripts/
│   ├── lib/common.sh
│   ├── 00-preflight.sh
│   ├── 10-configure-network.sh
│   ├── 20-firewall-baseline.sh
│   ├── 30-network-isolation-vbox.sh
│   ├── 40-evidence-preserve.sh
│   ├── 50-containment-playbook.sh
│   ├── 60-verify.sh
│   └── 99-validate-kit.sh
├── playbooks/containment-playbook.md
├── evidence/
└── README.md
```

## Quick Start on Parrot OS

Prerequisites: Parrot VM with four NICs attached, `nftables`, `tcpdump`, `iproute2`,
`NetworkManager`, and optional `avml`/Volatility for memory work. Run from the kit directory.

```bash
cd incident_response_1/containment_lab
source lab.env
sudo ./scripts/00-preflight.sh
sudo ./scripts/10-configure-network.sh --router --apply
sudo ./scripts/20-firewall-baseline.sh --apply --persist --yes
sudo ./scripts/40-evidence-preserve.sh --snapshot-fs --pcap-iface enp0s9 --mem
sudo ./scripts/50-containment-playbook.sh --plan
sudo ./scripts/60-verify.sh --strict
```

`10-configure-network.sh --router` enables IPv4 forwarding. Keep the NAT default route; the three
lab interfaces are configured with `ipv4.never-default yes`.

## Host-Side VirtualBox Setup (Windows)

Run PowerShell as Administrator:

```powershell
powershell -ExecutionPolicy Bypass -File configs\virtualbox\lab-network.ps1
powershell -ExecutionPolicy Bypass -File configs\virtualbox\lab-network.ps1 -Apply
```

The script detects the existing host-only adapter by name and falls back to its address
`192.168.56.1/24`. It does not create internal networks directly; VirtualBox creates
`IR-LAB-CORE`, `IR-LAB-PROTECTED`, and `IR-LAB-QUARANTINE` when a VM adapter is attached.

Attach the Kali NIC2 to the core segment while the VM is powered off:

```powershell
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" modifyvm "Kali" --nic2=intnet --intnet2=IR-LAB-CORE --nic-type2=82540EM --nic-promisc2=deny
```

The containment script performs the equivalent change and records before/after VM state.

## Containment Actions

```bash
sudo ./scripts/50-containment-playbook.sh --block-ip 203.0.113.77 --confirm
sudo ./scripts/50-containment-playbook.sh --block-host-vbox --vm Kali --nic 2 --confirm
sudo ./scripts/50-containment-playbook.sh --isolate-network --confirm
sudo ./scripts/50-containment-playbook.sh --shutdown-services --service apache2 --confirm
```

For live isolation of a running VM:

```bash
sudo ./scripts/30-network-isolation-vbox.sh --live-disconnect --vm Kali --nic 2 --apply
```

`modifyvm` requires the VM to be powered off; `controlvm setlinkstateN off` cuts the link while it
is running. Preserve volatile evidence before either action where possible.

## Evidence

Each case is written to `evidence/<CASE_ID>/` and contains, as applicable:

- `preflight.txt`, `preflight.meta`
- `network-configuration.txt`, `network-configuration.plan`
- `firewall-baseline.txt`, `nft-ruleset-before.txt`
- `vbox-network-isolation.txt`
- `evidence-preservation.txt`, `chain-of-custody.txt`
- `containment-playbook.txt`, `containment-actions.log`
- `verification.txt`
- `snapshots/`, `pcaps/`, `memdump/`
- `manifest.sha256`

`00-preflight.sh` and `30-network-isolation-vbox.sh --plan` can run without root. Firewall,
network, capture, memory, and containment actions require root.

## Validation Status

`scripts/99-validate-kit.sh` checks required files, shell syntax, executable bits, CRLF endings,
nftables policy content, actual lab addresses, VBoxManage visibility, host-only presence, netplan
YAML, and PowerShell parsing.

Latest static run: **36 pass, 1 warning, 0 failures**. The warning is expected: `nft` is not
installed on the WSL authoring host, so the nftables syntax check is deferred to the Parrot VM.
Static evidence is in `evidence/validation/` and case plan evidence is in
`evidence/IR-CONTAIN-STATIC-20261025/`.

Live checks still required on Parrot: apply the firewall and show counters, capture a pcap, hash
artifacts, produce a memory dump, isolate `Kali`, and verify blocked connectivity.
