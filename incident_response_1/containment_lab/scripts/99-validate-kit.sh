#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/lib/common.sh"

OUT_DIR="$LAB_EVIDENCE/validation"
OUT="$OUT_DIR/validation-report.txt"
mkdir -p "$OUT_DIR"
: >"$OUT"

PASS=0
FAIL=0
WARN=0

ok() {
    PASS=$((PASS + 1))
    printf 'PASS  %s\n' "$*" | tee -a "$OUT"
}

bad() {
    FAIL=$((FAIL + 1))
    printf 'FAIL  %s\n' "$*" | tee -a "$OUT"
}

warn() {
    WARN=$((WARN + 1))
    printf 'WARN  %s\n' "$*" | tee -a "$OUT"
}

{
    printf '=== containment lab validation ===\n'
    printf 'generated_utc=%s\n' "$(now_utc)"
    printf 'lab_home=%s\n' "$LAB_HOME"
    printf 'host=%s\n' "$(hostname 2>/dev/null || true)"
    printf 'user=%s\n' "${USER:-unknown}"
    printf '\n'
} >>"$OUT"

for required in "$LAB_HOME/lab.env" "$LAB_HOME/README.md" "$LAB_HOME/playbooks/containment-playbook.md" "$LAB_HOME/configs/nftables/ir-baseline.nft" "$LAB_HOME/configs/iptables/ir-baseline.rules" "$LAB_HOME/configs/netplan/50-ir-lab.yaml"; do
    if [[ -f "$required" ]]; then
        ok "file exists: ${required#$LAB_HOME/}"
    else
        bad "file missing: ${required#$LAB_HOME/}"
    fi
done

while IFS= read -r -d '' script; do
    if bash -n "$script" 2>>"$OUT"; then
        ok "bash syntax: ${script#$LAB_HOME/}"
    else
        bad "bash syntax: ${script#$LAB_HOME/}"
    fi
    if [[ -x "$script" ]]; then
        ok "executable: ${script#$LAB_HOME/}"
    else
        warn "not executable: ${script#$LAB_HOME/}"
    fi
    if grep -q $'\r' "$script"; then
        bad "CRLF line endings: ${script#$LAB_HOME/}"
    fi
done < <(find "$LAB_HOME/scripts" -type f -name '*.sh' -print0 | sort -z)

if grep -q 'policy drop;' "$LAB_HOME/configs/nftables/ir-baseline.nft"; then
    ok "nft baseline has default-drop policy"
else
    bad "nft baseline missing default-drop policy"
fi
if grep -q '192.168.56.0/24 tcp dport 22 accept' "$LAB_HOME/configs/nftables/ir-baseline.nft"; then
    ok "nft baseline scopes management SSH"
else
    bad "nft baseline missing scoped SSH allow"
fi
if grep -q '192.168.64.0/24 ip daddr 10.20.20.0/24 drop' "$LAB_HOME/configs/nftables/ir-baseline.nft"; then
    ok "nft baseline blocks core-to-protected segment"
else
    bad "nft baseline missing segment block"
fi
if grep -q '192.168.64.3' "$LAB_HOME/lab.env"; then
    ok "lab.env references actual Kali agent address 192.168.64.3"
else
    warn "lab.env does not reference 192.168.64.3"
fi
if grep -q 'SOC-CASE-2026-0142' "$LAB_HOME/lab.env"; then
    ok "lab.env references actual case SOC-CASE-2026-0142"
else
    warn "lab.env does not reference actual case"
fi

if have nft; then
    if nft -c -f "$LAB_HOME/configs/nftables/ir-baseline.nft" >>"$OUT" 2>&1; then
        ok "nft syntax check passed"
    else
        bad "nft syntax check failed"
    fi
else
    warn "nft not installed; syntax check skipped"
fi

if have ip; then
    ok "iproute2 available: $(ip -V 2>/dev/null || true)"
else
    bad "iproute2 not available"
fi

VBOX="$(find_vboxmanage || true)"
if [[ -n "$VBOX" ]]; then
    ok "VBoxManage available: $VBOX"
    "$VBOX" --version >>"$OUT" 2>&1 || true
    if "$VBOX" list hostonlyifs 2>/dev/null | grep -qE 'Name:|192\.168\.56\.1'; then
        ok "VirtualBox host-only interface exists"
    else
        warn "VirtualBox host-only interface not found (run lab-network.ps1 -Apply)"
    fi
    if "$VBOX" list vms 2>/dev/null | grep -q '"Kali"'; then
        ok "actual Kali VM is registered in VirtualBox"
    else
        warn "Kali VM not found in VirtualBox"
    fi
else
    warn "VBoxManage not available; host-side checks skipped"
fi

if grep -q '192.168.64.10/24' "$LAB_HOME/configs/netplan/50-ir-lab.yaml"; then
    ok "netplan core address matches actual core network"
else
    bad "netplan core address does not match 192.168.64.0/24"
fi

if have python3; then
    if python3 -c 'import yaml' >/dev/null 2>&1; then
        if python3 -c 'import sys,yaml; yaml.safe_load(open(sys.argv[1]))' "$LAB_HOME/configs/netplan/50-ir-lab.yaml" >>"$OUT" 2>&1; then
            ok "netplan YAML parses"
        else
            bad "netplan YAML parse failed"
        fi
    else
        warn "PyYAML not installed; YAML parse skipped"
    fi
else
    warn "python3 not available; YAML parse skipped"
fi

PS_BIN=""
for candidate in pwsh powershell.exe; do
    if have "$candidate"; then
        PS_BIN="$candidate"
        break
    fi
done
if [[ -n "$PS_BIN" ]]; then
    PS_SCRIPT="$LAB_HOME/configs/virtualbox/lab-network.ps1"
    if [[ "$PS_BIN" == *.exe ]] && have wslpath; then
        PS_SCRIPT="$(wslpath -w "$PS_SCRIPT")"
    fi
    if "$PS_BIN" -NoProfile -Command "\$errors=\$null; [void][System.Management.Automation.Language.Parser]::ParseFile('$PS_SCRIPT',[ref]\$null,[ref]\$errors); if (\$errors.Count -gt 0) { exit 1 }" >>"$OUT" 2>&1; then
        ok "PowerShell network script parses ($PS_BIN)"
    else
        bad "PowerShell parse check failed"
    fi
else
    warn "PowerShell not installed; parse check skipped"
fi

{
    printf '\n=== summary ===\n'
    printf 'pass=%d warn=%d fail=%d\n' "$PASS" "$WARN" "$FAIL"
} >>"$OUT"

printf 'pass=%d warn=%d fail=%d\n' "$PASS" "$WARN" "$FAIL"
printf 'report=%s\n' "$OUT"
[[ "$FAIL" -eq 0 ]]
