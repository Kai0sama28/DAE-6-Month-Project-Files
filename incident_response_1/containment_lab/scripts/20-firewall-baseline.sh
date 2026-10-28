#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/lib/common.sh"

APPLY=0
PERSIST=0
ROLLBACK=0
ASSUME_YES=0
CONFIG="$LAB_CONFIGS/nftables/ir-baseline.nft"
SERVICE=/etc/systemd/system/ir-firewall.service
PERSIST_DIR=/etc/ir-lab
PERSIST_FILE="$PERSIST_DIR/ir-baseline.nft"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --apply) APPLY=1 ;;
        --persist) PERSIST=1 ;;
        --rollback) ROLLBACK=1 ;;
        --yes) ASSUME_YES=1 ;;
        --config) CONFIG="${2:?missing value}"; shift ;;
        --help|-h)
            printf 'Usage: %s [--apply] [--persist] [--rollback] [--yes] [--config FILE]\n' "$0"
            exit 0
            ;;
        *) die "unknown argument: $1" ;;
    esac
    shift
done

ensure_case_dir
OUT="$(evidence_path firewall-baseline.txt)"
: >"$OUT"

if [[ "$ROLLBACK" -eq 1 ]]; then
    need_root
    need_cmd nft
    {
        printf '=== rollback ===\n'
        printf 'Removing table inet ir_filter and ir-firewall.service\n'
    } >>"$OUT"
    if systemctl list-unit-files ir-firewall.service >/dev/null 2>&1; then
        systemctl disable --now ir-firewall.service 2>/dev/null || true
        systemctl daemon-reload || true
    fi
    rm -f "$SERVICE" "$PERSIST_FILE"
    nft delete table inet ir_filter 2>/dev/null || true
    nft list ruleset >>"$OUT" 2>&1 || true
    sha256sum "$OUT" >>"$(evidence_path manifest.sha256)"
    log "firewall rollback complete"
    exit 0
fi

[[ -f "$CONFIG" ]] || die "config not found: $CONFIG"
need_cmd nft

{
    printf '=== firewall plan ===\n'
    printf 'config=%s\n' "$CONFIG"
    printf 'apply=%s persist=%s\n' "$APPLY" "$PERSIST"
    printf '\n=== config ===\n'
    cat "$CONFIG"
    printf '\n=== nft syntax check ===\n'
} >>"$OUT"

if ! nft -c -f "$CONFIG" >>"$OUT" 2>&1; then
    die "nft syntax check failed; see $OUT"
fi
printf 'PASS\n' >>"$OUT"

if [[ "$APPLY" -eq 0 && "$PERSIST" -eq 0 ]]; then
    printf '\nDry run only. Re-run with --apply and optionally --persist.\n' | tee -a "$OUT"
    sha256sum "$OUT" >>"$(evidence_path manifest.sha256)"
    exit 0
fi

need_root

if [[ "$APPLY" -eq 1 ]]; then
    if [[ "$ASSUME_YES" -ne 1 ]]; then
        confirm_apply "Apply the default-deny IR firewall now?" || die "not applied"
    fi
    nft list ruleset >"$(evidence_path nft-ruleset-before.txt)" 2>&1 || true
    nft delete table inet ir_filter 2>/dev/null || true
    nft -f "$CONFIG"
    printf '\n=== applied ruleset ===\n' >>"$OUT"
    nft list table inet ir_filter >>"$OUT" 2>&1
fi

if [[ "$PERSIST" -eq 1 ]]; then
    if [[ "$ASSUME_YES" -ne 1 && "$APPLY" -ne 1 ]]; then
        confirm_apply "Persist the IR firewall as a systemd unit?" || die "not persisted"
    fi
    install -d -m 0750 "$PERSIST_DIR"
    install -m 0640 "$CONFIG" "$PERSIST_FILE"
    cat >"$SERVICE" <<'EOF'
[Unit]
Description=Incident Response Lab Firewall
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStartPre=-/usr/sbin/nft delete table inet ir_filter
ExecStart=/usr/sbin/nft -f /etc/ir-lab/ir-baseline.nft
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    chmod 0644 "$SERVICE"
    systemctl daemon-reload
    systemctl enable --now ir-firewall.service
    systemctl status ir-firewall.service --no-pager >>"$OUT" 2>&1 || true
fi

{
    printf '\n=== verification ===\n'
    nft list ruleset
    printf '\n=== listening sockets ===\n'
    ss -tulpn 2>/dev/null || true
    printf '\n=== table counters ===\n'
    nft list table inet ir_filter 2>/dev/null || true
} >>"$OUT"

sha256sum "$OUT" >>"$(evidence_path manifest.sha256)"
log "firewall evidence written to $OUT"
