#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/lib/common.sh"

IFACES=()
PCAP_IFACES=()
DUMP_COUNT=10
SNAPSHOT_FS=0
LOG_SOURCES=(/var/log /var/ossec/logs /var/log/audit)
MEM=0
MEM_TOOL=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --iface) IFACES+=("${2:?missing value}"); shift ;;
        --pcap-iface) PCAP_IFACES+=("${2:?missing value}"); shift ;;
        --dump-count) DUMP_COUNT="${2:?missing value}"; shift ;;
        --log-source) LOG_SOURCES+=("${2:?missing value}"); shift ;;
        --snapshot-fs) SNAPSHOT_FS=1 ;;
        --mem) MEM=1 ;;
        --mem-tool) MEM_TOOL="${2:?missing value}"; shift ;;
        --help|-h)
            cat <<'EOF'
Usage:
  40-evidence-preserve.sh [--iface IF] [--pcap-iface IF] [--dump-count N] [--log-source DIR] [--snapshot-fs] [--mem] [--mem-tool auto|avml|lime|proc]
EOF
            exit 0
            ;;
        *) die "unknown argument: $1" ;;
    esac
    shift
done

ensure_case_dir
OUT="$(evidence_path evidence-preservation.txt)"
: >"$OUT"
CHAIN="$(evidence_path chain-of-custody.txt)"

{
    printf 'chain_of_custody_case_id=%s\n' "$CASE_ID"
    printf 'operator=%s\n' "${SUDO_USER:-${USER:-unknown}}"
    printf 'host=%s\n' "$(hostname 2>/dev/null || true)"
    printf 'started_utc=%s\n' "$(now_utc)"
    printf 'action=evidence_preservation\n'
} >"$CHAIN"

if [[ ${#IFACES[@]} -eq 0 ]] && have ip; then
    IFACES=($(ip -o link show up 2>/dev/null | awk -F': ' '{print $2}' | grep -v lo || true))
fi

{
    printf '=== evidence preservation plan ===\n'
    printf 'case_dir=%s\n' "$CASE_DIR"
    printf 'interfaces_for_snapshot=%s\n' "${IFACES[*]:-none}"
    printf 'pcap_ifaces=%s\n' "${PCAP_IFACES[*]:-none}"
    printf 'log_sources=%s\n' "${LOG_SOURCES[*]}"
    printf 'snapshot_fs=%s mem=%s mem_tool=%s\n' "$SNAPSHOT_FS" "$MEM" "$MEM_TOOL"
} >>"$OUT"

run_snapshot() {
    local dir="$1"
    local base
    base="$(basename "$dir")"
    if [[ ! -d "$dir" ]]; then
        printf 'SKIP (missing): %s\n' "$dir" >>"$OUT"
        return 0
    fi
    local arch="$CASE_DIR/snapshots/${base}-$(date -u +%Y%m%dT%H%M%SZ).tar.zst"
    mkdir -p "$(dirname "$arch")"
    if have tar; then
        if have zstd; then
            tar --warning=no-file-changed -C "$(dirname "$dir")" -cf - "$(basename "$dir")" 2>>"$OUT" | zstd -q -o "$arch" || true
        else
            tar --warning=no-file-changed -C "$(dirname "$dir")" -czf "${arch%.zst}.tgz" "$(basename "$dir")" 2>>"$OUT" || true
            arch="${arch%.zst}.tgz"
        fi
        printf 'SNAPSHOT %s -> %s\n' "$dir" "$arch" >>"$OUT"
        if [[ -f "$arch" ]]; then
            printf 'sha256 %s %s\n' "$(sha256_of "$arch")" "$arch" >>"$CHAIN"
        fi
    fi
}

if [[ "$SNAPSHOT_FS" -eq 1 ]]; then
    printf '\n=== filesystem snapshots ===\n' >>"$OUT"
    for src in "${LOG_SOURCES[@]}"; do
        run_snapshot "$src"
    done
fi

if [[ ${#PCAP_IFACES[@]} -gt 0 ]] && have tcpdump; then
    need_root
    printf '\n=== packet capture (short window) ===\n' >>"$OUT"
    mkdir -p "$CASE_DIR/pcaps"
    for iface in "${PCAP_IFACES[@]}"; do
        pcap="$CASE_DIR/pcaps/${iface}-$(date -u +%Y%m%dT%H%M%SZ).pcapng"
        printf 'capturing %s -> %s\n' "$iface" "$pcap" >>"$OUT"
        timeout --signal=INT 10 tcpdump -i "$iface" -nn -s 0 -w "$pcap" 2>>"$OUT" || true
        if [[ -f "$pcap" ]]; then
            printf 'sha256 %s %s\n' "$(sha256_of "$pcap")" "$pcap" >>"$CHAIN"
            if have capinfos; then
                capture_cmd "capinfos $iface" "$OUT" capinfos "$pcap"
            fi
        fi
    done
elif [[ ${#PCAP_IFACES[@]} -gt 0 ]]; then
    printf '\n=== packet capture ===\nSKIP: tcpdump not installed\n' >>"$OUT"
fi

if [[ "$MEM" -eq 1 ]]; then
    need_root
    printf '\n=== memory dump attempt ===\n' >>"$OUT"
    mkdir -p "$CASE_DIR/memdump"
    if [[ -z "$MEM_TOOL" || "$MEM_TOOL" == "auto" ]]; then
        MEM_TOOL=""
        for tool in avml /opt/avml/avml /usr/local/bin/avml; do
            if [[ -x "$tool" ]] || have "$tool"; then
                MEM_TOOL="$tool"
                break
            fi
        done
        if [[ -z "$MEM_TOOL" ]] && have insmod; then
            MEM_TOOL="lime"
        fi
        if [[ -z "$MEM_TOOL" && -r /proc/kcore ]]; then
            MEM_TOOL="proc"
        fi
    fi
    case "$MEM_TOOL" in
        avml|*/avml)
            if have "$MEM_TOOL"; then
                out="$CASE_DIR/memdump/memory-$(date -u +%Y%m%dT%H%M%SZ).mem"
                "$MEM_TOOL" "$out" >>"$OUT" 2>&1 || true
                [[ -f "$out" ]] && printf 'sha256 %s %s\n' "$(sha256_of "$out")" "$out" >>"$CHAIN"
            fi
            ;;
        proc)
            if [[ -r /proc/kcore ]]; then
                out="$CASE_DIR/memdump/kcore-$(date -u +%Y%m%dT%H%M%SZ).raw"
                dd if=/proc/kcore of="$out" bs=4M status=progress >>"$OUT" 2>&1 || true
                [[ -f "$out" ]] && printf 'sha256 %s %s\n' "$(sha256_of "$out")" "$out" >>"$CHAIN"
            fi
            ;;
        lime)
            printf 'LiME kernel module required (insmod lime.ko path="...") — record path and command in chain-of-custody\n' >>"$OUT"
            ;;
        *)
            printf 'No suitable memory acquisition tool found; document method and justification\n' >>"$OUT"
            ;;
    esac
fi

printf '\n=== interface snapshots ===\n' >>"$OUT"
for iface in "${IFACES[@]}"; do
    capture_cmd "ip addr show $iface" "$OUT" ip addr show "$iface"
    capture_cmd "ethtool $iface" "$OUT" ethtool "$iface"
done

capture_cmd "routing table" "$OUT" ip route
capture_cmd "arp table" "$OUT" ip neigh
capture_cmd "active connections" "$OUT" ss -tunap
capture_cmd "process snapshot" "$OUT" ps auxww
capture_cmd "mounted filesystems" "$OUT" mount
capture_cmd "open files" "$OUT" lsof -nP 2>&1 | head -200

{
    printf '\nended_utc=%s\n' "$(now_utc)"
    printf 'manifest=%s\n' "$(evidence_path manifest.sha256)"
} >>"$CHAIN"

find "$CASE_DIR" -type f -print0 | xargs -0 sha256sum >"$(evidence_path manifest.sha256)" 2>&1 || true
log "evidence preservation complete in $CASE_DIR"
cat "$CHAIN"
