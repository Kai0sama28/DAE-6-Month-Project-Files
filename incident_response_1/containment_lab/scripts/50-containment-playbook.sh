#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/lib/common.sh"

ACTION="plan"
BLOCK_IP=""
BLOCK_HOST=""
VM=""
SERVICE_NAME=""
NIC=2

while [[ $# -gt 0 ]]; do
    case "$1" in
        --plan) ACTION="plan" ;;
        --isolate-network) ACTION="isolate-network" ;;
        --block-ip) ACTION="block-ip"; BLOCK_IP="${2:?missing value}"; shift ;;
        --block-host-vbox) ACTION="block-host-vbox"; VM="${2:?missing value}"; shift ;;
        --shutdown-services) ACTION="shutdown-services" ;;
        --service) SERVICE_NAME="${2:?missing value}"; shift ;;
        --confirm) IR_ASSUME_YES=1 ;;
        --help|-h)
            cat <<'EOF'
Usage:
  50-containment-playbook.sh --plan
  50-containment-playbook.sh --block-ip <IP/CIDR> [--confirm]
  50-containment-playbook.sh --block-host-vbox --vm <VM> [--nic <N>] [--confirm]
  50-containment-playbook.sh --isolate-network [--confirm]
  50-containment-playbook.sh --shutdown-services --service <name> [--confirm]
EOF
            exit 0
            ;;
        *) die "unknown argument: $1" ;;
    esac
    shift
done

ensure_case_dir
OUT="$(evidence_path containment-playbook.txt)"
LOG="$(evidence_path containment-actions.log)"
: >"$OUT"
: >"$LOG"

{
    printf '=== containment playbook ===\n'
    printf 'case_id=%s\n' "$CASE_ID"
    printf 'action=%s\n' "$ACTION"
    printf 'timestamp_utc=%s\n' "$(now_utc)"
    printf 'operator=%s\n' "${SUDO_USER:-${USER:-unknown}}"
} >>"$OUT"

run_action() {
    local description="$1"
    shift
    printf '[%s] ACTION: %s\n' "$(now_utc)" "$description" >>"$LOG"
    printf '$ %s\n' "$*" >>"$LOG"
    if [[ "${IR_ASSUME_YES:-0}" -eq 1 ]]; then
        local rc=0
        "$@" >>"$LOG" 2>&1
        rc=$?
        printf '[exit=%s]\n\n' "$rc" >>"$LOG"
        return 0
    else
        printf '[SKIPPED - confirmation required]\n\n' >>"$LOG"
        return 0
    fi
}

if [[ "$ACTION" == "plan" ]]; then
    cat >>"$OUT" <<'EOF'
## Host isolation (VirtualBox)
1. Snapshot/cordon the affected VM (power off only if no volatile evidence loss is acceptable and acquisition already done)
2. Move NIC to IR-LAB-QUARANTINE (internal network) or disconnect entirely
3. Disable promiscuous mode; block cross-network routes
4. Record VM UUID, MAC, adapter, network before/after

## Network traffic blocking
1. Add nftables/iptables DROP for attacker IP/CIDR in input/forward/output
2. Rate-limit only if DoS; prefer DROP for confirmed compromise
3. Push to persistence unit if the node remains in service
4. Log blocks (prefix IR-*)

## Service shutdown
1. Enumerate dependent services (ss -tulpn, systemctl list-units)
2. Stop/disable only affected services (avoid taking down the logger/forensics stack)
3. Mask if necessary; avoid deleting binaries until eradication approved
4. Capture journalctl around shutdown time

## Evidence-preservation gates
- Acquire network capture BEFORE applying aggressive blocks if feasible
- Hash artifacts and update chain-of-custody
- Do not reboot the compromised host before memory/disk snapshots as required
EOF
    sha256sum "$OUT" >>"$(evidence_path manifest.sha256)"
    exit 0
fi

need_root

case "$ACTION" in
    block-ip)
        [[ -n "$BLOCK_IP" ]] || die "missing IP/CIDR"
        need_cmd nft
        if [[ "${IR_ASSUME_YES:-0}" -eq 1 ]]; then
            {
                printf '[%s] ACTION: Block IP %s\n' "$(now_utc)" "$BLOCK_IP"
                printf '$ nft add element inet ir_contain blocked { %s timeout 4h }\n' "$BLOCK_IP"
                printf '$ nft insert rule inet ir_contain input ip saddr @blocked drop\n'
                printf '$ nft insert rule inet ir_contain forward ip saddr @blocked drop\n'
                printf '$ nft insert rule inet ir_contain output ip daddr @blocked drop\n'
            } >>"$LOG"
            nft add table inet ir_contain 2>/dev/null || true
            nft add chain inet ir_contain input '{ type filter hook input priority 10; policy accept; }' 2>/dev/null || true
            nft add chain inet ir_contain forward '{ type filter hook forward priority 10; policy accept; }' 2>/dev/null || true
            nft add chain inet ir_contain output '{ type filter hook output priority 10; policy accept; }' 2>/dev/null || true
            nft add set inet ir_contain blocked '{ type ipv4_addr; flags interval,timeout; }' 2>/dev/null || true
            nft add element inet ir_contain blocked "{ $BLOCK_IP timeout 4h }"
            nft insert rule inet ir_contain input ip saddr @blocked drop 2>/dev/null || true
            nft insert rule inet ir_contain forward ip saddr @blocked drop 2>/dev/null || true
            nft insert rule inet ir_contain forward ip daddr @blocked drop 2>/dev/null || true
            nft insert rule inet ir_contain output ip daddr @blocked drop 2>/dev/null || true
        fi
        run_action "Block IP $BLOCK_IP via nftables (ir_contain)" nft list table inet ir_contain
        ;;
    block-host-vbox)
        [[ -n "$VM" ]] || die "missing VM"
        VBOX="$(find_vboxmanage || true)"
        [[ -n "$VBOX" ]] || die "VBoxManage not found"
        if [[ "${IR_ASSUME_YES:-0}" -eq 1 ]]; then
            IR_ASSUME_YES=1 "$SCRIPT_DIR/30-network-isolation-vbox.sh" --move-quarantine --vm "$VM" --nic "$NIC" --network "$VBOX_NET_QUARANTINE" --apply
        else
            printf '[SKIPPED - confirmation required]\n\n' >>"$LOG"
        fi
        ;;
    isolate-network)
        need_cmd nft
        if [[ "${IR_ASSUME_YES:-0}" -eq 1 ]]; then
            {
                printf '[%s] ACTION: Tighten forward policy to quarantine posture\n' "$(now_utc)"
                printf '$ nft flush chain inet ir_filter forward\n'
                printf '$ nft add rule inet ir_filter forward ct state established,related accept\n'
                printf '$ nft add rule inet ir_filter forward ct state invalid drop\n'
                printf '$ nft add rule inet ir_filter forward log prefix \"IR-QUARANTINE-FORWARD: \" level info\n'
                printf '$ nft add rule inet ir_filter forward drop\n'
            } >>"$LOG"
            if ! nft list table inet ir_filter >/dev/null 2>&1; then
                nft -f "$LAB_CONFIGS/nftables/ir-baseline.nft"
            fi
            nft flush chain inet ir_filter forward
            nft add rule inet ir_filter forward ct state established,related accept
            nft add rule inet ir_filter forward ct state invalid drop
            nft add rule inet ir_filter forward log prefix '"IR-QUARANTINE-FORWARD: "' level info
            nft add rule inet ir_filter forward drop
        fi
        run_action "Tighten forward policy (quarantine posture)" nft list chain inet ir_filter forward
        ;;
    shutdown-services)
        [[ -n "$SERVICE_NAME" ]] || die "missing --service"
        need_cmd systemctl
        if [[ "${IR_ASSUME_YES:-0}" -eq 1 ]]; then
            systemctl stop "$SERVICE_NAME" || true
            systemctl disable "$SERVICE_NAME" || true
        fi
        run_action "Stop and disable service $SERVICE_NAME" systemctl status "$SERVICE_NAME" --no-pager
        ;;
    *)
        die "unknown action: $ACTION"
    esac

{
    printf '\n=== containment evidence ===\n'
    printf 'completed_utc=%s\n' "$(now_utc)"
    ss -tulpn 2>/dev/null || true
    nft list ruleset 2>/dev/null || true
} >>"$OUT"

sha256sum "$OUT" "$LOG" >>"$(evidence_path manifest.sha256)"
log "containment playbook evidence written to $OUT"
log "containment actions log: $LOG"
