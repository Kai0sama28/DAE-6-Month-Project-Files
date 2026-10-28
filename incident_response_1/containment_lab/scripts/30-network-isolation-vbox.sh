#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/lib/common.sh"

ACTION="plan"
VM=""
IFACE_NUMBER=2
NETWORK_NAME=""
MAC_ADDRESS=""
ADAPTER_TYPE="82540EM"
PROMISC="deny"
APPLY=0
VBOX="$(find_vboxmanage || true)"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --plan) ACTION="plan" ;;
        --isolate|--host-isolate) ACTION="isolate-host" ;;
        --quarantine|--move-quarantine) ACTION="move-quarantine" ;;
        --restore|--host-restore) ACTION="restore-host" ;;
        --live-disconnect|--disconnect) ACTION="live-disconnect" ;;
        --apply) APPLY=1 ;;
        --vm) VM="${2:?missing value}"; shift ;;
        --nic) IFACE_NUMBER="${2:?missing value}"; shift ;;
        --network) NETWORK_NAME="${2:?missing value}"; shift ;;
        --mac) MAC_ADDRESS="${2:?missing value}"; shift ;;
        --promisc) PROMISC="${2:?missing value}"; shift ;;
        --help|-h)
            cat <<'EOF'
Usage:
  30-network-isolation-vbox.sh --plan
  30-network-isolation-vbox.sh --isolate --vm <VM> [--nic <N>] --apply
  30-network-isolation-vbox.sh --move-quarantine --vm <VM> [--network IR-LAB-QUARANTINE] [--nic <N>] --apply
  30-network-isolation-vbox.sh --restore --vm <VM> [--network IR-LAB-CORE] [--nic <N>] --apply
  30-network-isolation-vbox.sh --live-disconnect --vm <VM> [--nic <N>] --apply
EOF
            exit 0
            ;;
        *) die "unknown argument: $1" ;;
    esac
    shift
done

if [[ "$ACTION" == "restore-host" && -z "$NETWORK_NAME" ]]; then
    NETWORK_NAME="$VBOX_NET_CORE"
fi
if [[ "$ACTION" == "move-quarantine" && -z "$NETWORK_NAME" ]]; then
    NETWORK_NAME="$VBOX_NET_QUARANTINE"
fi

ensure_case_dir
OUT="$(evidence_path vbox-network-isolation.txt)"
: >"$OUT"

{
    printf '=== VirtualBox networking plan ===\n'
    printf 'action=%s vm=%s nic=%d network=%s promisc=%s\n' "$ACTION" "$VM" "$IFACE_NUMBER" "$NETWORK_NAME" "$PROMISC"
    printf 'VBoxManage=%s\n' "$VBOX"
    printf '\n=== host-only ===\n'
} >>"$OUT"

if [[ -n "$VBOX" ]]; then
    "$VBOX" list hostonlyifs >>"$OUT" 2>&1 || true
    printf '\n=== internal networks present ===\n' >>"$OUT"
    "$VBOX" list intnets >>"$OUT" 2>&1 || true
    printf '\n=== running VMs ===\n' >>"$OUT"
    "$VBOX" list runningvms >>"$OUT" 2>&1 || true
    printf '\n=== all VMs ===\n' >>"$OUT"
    "$VBOX" list vms >>"$OUT" 2>&1 || true
fi

if [[ "$ACTION" == "plan" ]]; then
    printf '\nDry run. Use --isolate/--move-quarantine/--restore/--live-disconnect with --vm --apply to change a VM.\n' | tee -a "$OUT"
    sha256sum "$OUT" >>"$(evidence_path manifest.sha256)"
    exit 0
fi

[[ -n "$VM" ]] || die "missing --vm"
[[ -n "$VBOX" ]] || die "VBoxManage not found"

if [[ "$APPLY" -eq 0 ]]; then
    printf '\n=== planned action (%s) ===\n' "$ACTION" >>"$OUT"
    {
        case "$ACTION" in
            isolate-host)
                printf '$ %s modifyvm "%s" --nic%d=intnet --intnet%d=%s\n' "$VBOX" "$VM" "$IFACE_NUMBER" "$IFACE_NUMBER" "$VBOX_NET_QUARANTINE"
                printf '$ %s modifyvm "%s" --nic-type%d=%s\n' "$VBOX" "$VM" "$IFACE_NUMBER" "$ADAPTER_TYPE"
                printf '$ %s modifyvm "%s" --nic-promisc%d=%s\n' "$VBOX" "$VM" "$IFACE_NUMBER" "$PROMISC"
                ;;
            move-quarantine)
                printf '$ %s modifyvm "%s" --nic%d=intnet --intnet%d=%s\n' "$VBOX" "$VM" "$IFACE_NUMBER" "$IFACE_NUMBER" "$NETWORK_NAME"
                printf '$ %s modifyvm "%s" --nic-promisc%d=%s\n' "$VBOX" "$VM" "$IFACE_NUMBER" "$PROMISC"
                ;;
            restore-host)
                printf '$ %s modifyvm "%s" --nic%d=intnet --intnet%d=%s\n' "$VBOX" "$VM" "$IFACE_NUMBER" "$IFACE_NUMBER" "$NETWORK_NAME"
                printf '$ %s modifyvm "%s" --nic-promisc%d=allow-all\n' "$VBOX" "$VM" "$IFACE_NUMBER"
                ;;
            live-disconnect)
                printf '$ %s controlvm "%s" setlinkstate%d off\n' "$VBOX" "$VM" "$IFACE_NUMBER"
                ;;
        esac
        if [[ -n "$MAC_ADDRESS" ]]; then
            printf '$ %s modifyvm "%s" --mac-address%d=%s\n' "$VBOX" "$VM" "$IFACE_NUMBER" "$MAC_ADDRESS"
        fi
    } >>"$OUT"
    printf '\nDry run only. Re-run with --apply and confirm when prompted.\n' | tee -a "$OUT"
    sha256sum "$OUT" >>"$(evidence_path manifest.sha256)"
    exit 0
fi

if [[ "$ACTION" == "live-disconnect" ]]; then
    if ! "$VBOX" list runningvms | grep -Fq "\"$VM\""; then
        die "VM is not running: $VM"
    fi
    confirm_apply "Disconnect NIC$IFACE_NUMBER on running VM $VM?" || die "not applied"
    "$VBOX" controlvm "$VM" setlinkstate"$IFACE_NUMBER" off
else
    if "$VBOX" list runningvms | grep -Fq "\"$VM\""; then
        die "VM is running; use --live-disconnect first or power off before changing NIC networks"
    fi
    confirm_apply "Apply VirtualBox network isolation for $VM?" || die "not applied"
    case "$ACTION" in
        isolate-host)
            "$VBOX" modifyvm "$VM" --nic"$IFACE_NUMBER"=intnet --intnet"$IFACE_NUMBER"="$VBOX_NET_QUARANTINE"
            "$VBOX" modifyvm "$VM" --nic-type"$IFACE_NUMBER"="$ADAPTER_TYPE"
            "$VBOX" modifyvm "$VM" --nic-promisc"$IFACE_NUMBER"="$PROMISC"
            ;;
        move-quarantine)
            "$VBOX" modifyvm "$VM" --nic"$IFACE_NUMBER"=intnet --intnet"$IFACE_NUMBER"="$NETWORK_NAME"
            "$VBOX" modifyvm "$VM" --nic-promisc"$IFACE_NUMBER"="$PROMISC"
            ;;
        restore-host)
            "$VBOX" modifyvm "$VM" --nic"$IFACE_NUMBER"=intnet --intnet"$IFACE_NUMBER"="$NETWORK_NAME"
            "$VBOX" modifyvm "$VM" --nic-promisc"$IFACE_NUMBER"=allow-all
            ;;
        *)
            die "unknown action: $ACTION"
            ;;
    esac
    [[ -n "$MAC_ADDRESS" ]] && "$VBOX" modifyvm "$VM" --mac-address"$IFACE_NUMBER"="$MAC_ADDRESS"
fi

"$VBOX" showvminfo "$VM" >>"$OUT" 2>&1 || true
sha256sum "$OUT" >>"$(evidence_path manifest.sha256)"
log "VirtualBox isolation evidence written to $OUT"
