#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/lib/common.sh"

STRICT=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --strict) STRICT=1 ;;
        --help|-h)
            printf 'Usage: %s [--strict]\n' "$0"
            exit 0
            ;;
        *) die "unknown argument: $1" ;;
    esac
    shift
done

ensure_case_dir
OUT="$(evidence_path verification.txt)"
: >"$OUT"
VBOX="$(find_vboxmanage || true)"

{
    printf '=== verification ===\n'
    printf 'case_id=%s\n' "$CASE_ID"
    printf 'generated_utc=%s\n' "$(now_utc)"
    printf '\n=== firewall ===\n'
    nft list ruleset 2>/dev/null || printf 'nft not available\n'
    printf '\n=== addresses ===\n'
    ip -br addr
    printf '\n=== routes ===\n'
    ip route
    printf '\n=== listening ===\n'
    ss -tulpn
    printf '\n=== connections ===\n'
    ss -tunap | head -80
    printf '\n=== interfaces ===\n'
    for iface in "$IF_MGMT" "$IF_CORE" "$IF_PROTECTED" "$IF_NAT"; do
        [[ -z "$iface" ]] && continue
        ip link show "$iface" 2>&1 | head -2
    done
} >>"$OUT"

check() {
    local desc="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        printf 'PASS %s\n' "$desc" >>"$OUT"
    else
        printf 'FAIL %s\n' "$desc" >>"$OUT"
        return 1
    fi
}

FAILED=0
{
    printf '\n=== checks ===\n'
} >>"$OUT"

have nft && check "nft installed" true || FAILED=$((FAILED+1))
have ip && check "iproute2 installed" true || FAILED=$((FAILED+1))
have tcpdump && check "tcpdump available" true || FAILED=$((FAILED+1))

if have nft; then
    if nft list table inet ir_filter >/dev/null 2>&1; then
        printf 'PASS nft table inet ir_filter present\n' >>"$OUT"
    else
        printf 'INFO nft table inet ir_filter not loaded\n' >>"$OUT"
    fi
fi

if [[ -n "$VBOX" ]]; then
    if "$VBOX" list hostonlyifs | grep -q "$VBOX_MGMT_IF"; then
        printf 'PASS VirtualBox host-only %s exists\n' "$VBOX_MGMT_IF" >>"$OUT"
    else
        printf 'INFO VirtualBox host-only %s not found\n' "$VBOX_MGMT_IF" >>"$OUT"
    fi
    printf '\n=== VirtualBox inventory ===\n' >>"$OUT"
    "$VBOX" list vms >>"$OUT" 2>&1 | head -40
    "$VBOX" list runningvms >>"$OUT" 2>&1
fi

{
    printf '\n=== summary ===\n'
    printf 'failed_checks=%s\n' "$FAILED"
    printf 'case_dir=%s\n' "$CASE_DIR"
} >>"$OUT"

if [[ "$FAILED" -gt 0 ]]; then
    printf 'OVERALL=FAIL\n' >>"$OUT"
    [[ "$STRICT" -eq 1 ]] && die "verification failed in strict mode"
else
    printf 'OVERALL=PASS\n' >>"$OUT"
fi

find "$CASE_DIR" -type f -print0 | xargs -0 sha256sum >>"$(evidence_path manifest.sha256)" 2>&1 || true
log "verification complete: $OUT"
cat "$OUT"
