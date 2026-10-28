#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/lib/common.sh"

APPLY=0
ROUTER=0
MGMT_IF="$IF_MGMT"
CORE_IF="$IF_CORE"
PROTECTED_IF="$IF_PROTECTED"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --apply) APPLY=1 ;;
        --router) ROUTER=1 ;;
        --mgmt-if) MGMT_IF="${2:?missing value}"; shift ;;
        --core-if) CORE_IF="${2:?missing value}"; shift ;;
        --protected-if) PROTECTED_IF="${2:?missing value}"; shift ;;
        --help|-h)
            printf 'Usage: %s [--apply] [--router] [--mgmt-if IF] [--core-if IF] [--protected-if IF]\n' "$0"
            exit 0
            ;;
        *) die "unknown argument: $1" ;;
    esac
    shift
done

ensure_case_dir
OUT="$(evidence_path network-configuration.txt)"
PLAN="$(evidence_path network-configuration.plan)"
: >"$OUT"

cat >"$PLAN" <<EOF
nmcli connection add type ethernet ifname "$MGMT_IF" con-name ir-mgmt
nmcli connection modify ir-mgmt ipv4.method manual ipv4.addresses "$IR_MGMT_IP/24" ipv4.never-default yes ipv6.method disabled connection.autoconnect yes
nmcli connection up ir-mgmt

nmcli connection add type ethernet ifname "$CORE_IF" con-name ir-core
nmcli connection modify ir-core ipv4.method manual ipv4.addresses "$IR_CORE_IP/24" ipv4.never-default yes ipv6.method disabled connection.autoconnect yes
nmcli connection up ir-core

nmcli connection add type ethernet ifname "$PROTECTED_IF" con-name ir-protected
nmcli connection modify ir-protected ipv4.method manual ipv4.addresses "$IR_PROTECTED_IP/24" ipv4.never-default yes ipv6.method disabled connection.autoconnect yes
nmcli connection up ir-protected
EOF

{
    printf '=== planned interface configuration ===\n'
    cat "$PLAN"
    printf '\n=== interface inventory before changes ===\n'
    ip -br link
    printf '\n'
    ip -br addr
    printf '\n=== routes before changes ===\n'
    ip route
} >>"$OUT"

if [[ "$APPLY" -eq 0 ]]; then
    printf '\nDry run only. Re-run with --apply to apply the plan.\n' | tee -a "$OUT"
    sha256sum "$OUT" >>"$(evidence_path manifest.sha256)"
    exit 0
fi

need_root
need_cmd nmcli
need_cmd ip

for iface in "$MGMT_IF" "$CORE_IF" "$PROTECTED_IF"; do
    ip link show "$iface" >/dev/null 2>&1 || die "interface does not exist: $iface"
done

if ! systemctl is-active --quiet NetworkManager; then
    die "NetworkManager is not active"
fi

configure_connection() {
    local name="$1"
    local iface="$2"
    local address="$3"
    if ! nmcli -t -f NAME connection show | grep -Fxq "$name"; then
        nmcli connection add type ethernet ifname "$iface" con-name "$name"
    fi
    nmcli connection modify "$name" \
        ipv4.method manual \
        ipv4.addresses "$address/24" \
        ipv4.never-default yes \
        ipv6.method disabled \
        connection.autoconnect yes
    nmcli connection up "$name"
}

configure_connection ir-mgmt "$MGMT_IF" "$IR_MGMT_IP"
configure_connection ir-core "$CORE_IF" "$IR_CORE_IP"
configure_connection ir-protected "$PROTECTED_IF" "$IR_PROTECTED_IP"

if [[ "$ROUTER" -eq 1 ]]; then
    printf 'net.ipv4.ip_forward=1\n' >/etc/sysctl.d/99-ir-lab.conf
    sysctl --system >/dev/null
fi

{
    printf '\n=== interface inventory after changes ===\n'
    ip -br addr
    printf '\n=== routes after changes ===\n'
    ip route
    printf '\n=== NetworkManager connections ===\n'
    nmcli connection show
    printf '\n=== address validation ===\n'
} >>"$OUT"

for pair in "mgmt:$IR_MGMT_IP" "core:$IR_CORE_IP" "protected:$IR_PROTECTED_IP"; do
    label="${pair%%:*}"
    addr="${pair#*:}"
    if ip -o -4 addr show | awk -v target="$addr" '$4 ~ ("^" target "/") {found=1} END {exit !found}'; then
        printf 'PASS %s %s\n' "$label" "$addr" >>"$OUT"
    else
        printf 'FAIL %s %s\n' "$label" "$addr" >>"$OUT"
    fi
done

if [[ "$ROUTER" -eq 1 ]]; then
    printf '\n=== forwarding ===\n' >>"$OUT"
    sysctl net.ipv4.ip_forward >>"$OUT"
fi

sha256sum "$OUT" >>"$(evidence_path manifest.sha256)"
log "network configuration evidence written to $OUT"
