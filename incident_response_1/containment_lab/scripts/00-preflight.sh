#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/lib/common.sh"

STRICT=0
if [[ "${1:-}" == "--strict" ]]; then
    STRICT=1
fi

ensure_case_dir
OUT="$(evidence_path preflight.txt)"
: >"$OUT"
write_metadata "$(evidence_path preflight.meta)"

log "writing preflight evidence to $OUT"

{
    printf '=== identity ===\n'
    id
    printf '\n=== date ===\n'
    date -u
    printf '\n=== os ===\n'
    cat /etc/os-release 2>/dev/null || true
    printf '\n=== kernel ===\n'
    uname -a
    printf '\n=== lab config ===\n'
    cat "$LAB_ENV"
} >>"$OUT"

if have ip; then
    capture_cmd "ip addresses" "$OUT" ip -br addr
    capture_cmd "ip routes" "$OUT" ip route
    capture_cmd "ip rules" "$OUT" ip rule
    capture_cmd "ip neighbours" "$OUT" ip neigh
else
    printf 'CRITICAL: ip command missing\n' >>"$OUT"
fi

if have nft; then
    capture_cmd "nftables ruleset" "$OUT" nft list ruleset
else
    printf 'MISSING: nft\n' >>"$OUT"
fi

TOOLS=(ip nft tcpdump tshark capinfos sha256sum systemctl journalctl ss ps tar find awk sed grep curl avml insmod vol vol.py VBoxManage VBoxManage.exe)
{
    printf '\n=== tool inventory ===\n'
    for tool in "${TOOLS[@]}"; do
        if have "$tool"; then
            printf 'present  %s  %s\n' "$tool" "$(command -v "$tool")"
        else
            printf 'missing  %s\n' "$tool"
        fi
    done
} >>"$OUT"

resolve_iface IF_MGMT "$IR_MGMT_IP"
resolve_iface IF_CORE "$IR_CORE_IP"
resolve_iface IF_PROTECTED "$IR_PROTECTED_IP"

{
    printf '\n=== resolved interfaces ===\n'
    printf 'IF_NAT=%s\n' "$IF_NAT"
    printf 'IF_MGMT=%s\n' "$IF_MGMT"
    printf 'IF_CORE=%s\n' "$IF_CORE"
    printf 'IF_PROTECTED=%s\n' "$IF_PROTECTED"
} >>"$OUT"

for pair in "IF_NAT:$IF_NAT" "IF_MGMT:$IF_MGMT" "IF_CORE:$IF_CORE" "IF_PROTECTED:$IF_PROTECTED"; do
    name="${pair%%:*}"
    iface="${pair#*:}"
    if [[ -z "$iface" ]]; then
        printf 'WARN: %s is not set or was not detected\n' "$name" >>"$OUT"
    elif ! ip link show "$iface" >/dev/null 2>&1; then
        printf 'WARN: %s=%s does not exist\n' "$name" "$iface" >>"$OUT"
    else
        printf 'OK: %s=%s exists\n' "$name" "$iface" >>"$OUT"
    fi
done

for pair in "MGMT:$IR_MGMT_IP" "CORE:$IR_CORE_IP" "PROTECTED:$IR_PROTECTED_IP"; do
    label="${pair%%:*}"
    addr="${pair#*:}"
    if ip -o -4 addr show 2>/dev/null | awk -v target="$addr" '$4 ~ ("^" target "/") {found=1} END {exit !found}'; then
        printf 'OK: %s address %s is configured\n' "$label" "$addr" >>"$OUT"
    else
        printf 'WARN: %s address %s is not configured\n' "$label" "$addr" >>"$OUT"
    fi
done

if have VBoxManage || have VBoxManage.exe || [[ -x "/mnt/c/Program Files/Oracle/VirtualBox/VBoxManage.exe" ]]; then
    VBOX="$(find_vboxmanage || true)"
    if [[ -n "$VBOX" ]]; then
        capture_cmd "VirtualBox version" "$OUT" "$VBOX" --version
        capture_cmd "VirtualBox host-only interfaces" "$OUT" "$VBOX" list hostonlyifs
        capture_cmd "VirtualBox running VMs" "$OUT" "$VBOX" list runningvms
    fi
else
    printf 'INFO: VirtualBox CLI not available from this shell\n' >>"$OUT"
fi

printf '\n=== result ===\n' >>"$OUT"
if grep -q '^CRITICAL:' "$OUT"; then
    printf 'FAIL\n' >>"$OUT"
    if [[ "$STRICT" -eq 1 ]]; then
        sha256sum "$OUT" >>"$(evidence_path manifest.sha256)"
        die "preflight failed in strict mode"
    fi
else
    printf 'PASS\n' >>"$OUT"
fi

sha256sum "$OUT" >>"$(evidence_path manifest.sha256)"
log "preflight complete"
