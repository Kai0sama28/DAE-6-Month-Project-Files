#!/usr/bin/env bash
set -Eeuo pipefail

LAB_HOME="${LAB_HOME:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
LAB_ENV="${LAB_ENV:-$LAB_HOME/lab.env}"
LAB_CONFIGS="${LAB_CONFIGS:-$LAB_HOME/configs}"
LAB_EVIDENCE="${LAB_EVIDENCE:-$LAB_HOME/evidence}"
CASE_PREFIX="${CASE_PREFIX:-IR-CONTAIN}"
CASE_ID="${CASE_ID:-${CASE_PREFIX}-$(date -u +%Y%m%dT%H%M%SZ)}"
CASE_DIR="${CASE_DIR:-$LAB_EVIDENCE/$CASE_ID}"
VBOX_BIN="${VBOX_BIN:-}"

if [[ -f "$LAB_ENV" ]]; then
    set -a
    . "$LAB_ENV"
    set +a
fi

now_utc() {
    date -u +%Y-%m-%dT%H:%M:%SZ
}

log() {
    printf '[%s] %s\n' "$(now_utc)" "$*"
}

warn() {
    printf '[%s] WARN: %s\n' "$(now_utc)" "$*" >&2
}

die() {
    printf '[%s] ERROR: %s\n' "$(now_utc)" "$*" >&2
    exit 1
}

have() {
    command -v "$1" >/dev/null 2>&1
}

need_root() {
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        die "root is required for this action"
    fi
}

need_cmd() {
    local cmd="$1"
    have "$cmd" || die "required command not found: $cmd"
}

ensure_case_dir() {
    mkdir -p "$CASE_DIR"
    chmod 700 "$CASE_DIR"
}

sha256_of() {
    sha256sum "$1" | awk '{print $1}'
}

record_cmd() {
    local out="$1"
    shift
    local rc=0
    {
        printf '$ %s\n' "$*"
        set +e
        "$@" 2>&1
        rc=$?
        set -e
        printf '[exit=%s]\n\n' "$rc"
    } >>"$out"
    return 0
}

capture_cmd() {
    local title="$1"
    local out="$2"
    shift 2
    local rc=0
    {
        printf '=== %s ===\n' "$title"
        printf '$ %s\n' "$*"
        set +e
        "$@" 2>&1
        rc=$?
        set -e
        printf '[exit=%s]\n\n' "$rc"
    } >>"$out"
    return 0
}

detect_iface_for_ip() {
    local ip="$1"
    ip -o -4 addr show 2>/dev/null | awk -v target="$ip" '$4 ~ ("^" target "/") {print $2; exit}'
}

detect_iface_for_network() {
    local net="$1"
    local base
    base="$(printf '%s' "$net" | cut -d/ -f1 | awk -F. '{print $1"."$2"."$3"."}')"
    ip -o -4 addr show 2>/dev/null | awk -v prefix="$base" '$4 ~ ("^" prefix) {print $2; exit}'
}

resolve_iface() {
    local var_name="$1"
    local ip="$2"
    local current="${!var_name:-}"
    if [[ -n "$current" ]] && have ip && ! ip link show "$current" >/dev/null 2>&1; then
        current=""
    fi
    if [[ -z "$current" ]] && have ip; then
        current="$(detect_iface_for_ip "$ip")"
    fi
    printf -v "$var_name" '%s' "$current"
    export "$var_name"
}

find_vboxmanage() {
    if [[ -n "$VBOX_BIN" ]] && { have "$VBOX_BIN" || [[ -x "$VBOX_BIN" ]]; }; then
        printf '%s' "$VBOX_BIN"
        return 0
    fi
    local candidate
    for candidate in VBoxManage VBoxManage.exe "/mnt/c/Program Files/Oracle/VirtualBox/VBoxManage.exe"; do
        if have "$candidate"; then
            printf '%s' "$candidate"
            return 0
        fi
        if [[ -x "$candidate" ]]; then
            printf '%s' "$candidate"
            return 0
        fi
    done
    return 1
}

confirm_apply() {
    local prompt="$1"
    if [[ "${IR_ASSUME_YES:-0}" == "1" ]]; then
        return 0
    fi
    local answer
    read -r -p "$prompt [y/N] " answer
    [[ "$answer" == "y" || "$answer" == "Y" ]]
}

write_metadata() {
    local out="$1"
    {
        printf 'case_id=%s\n' "$CASE_ID"
        printf 'generated_utc=%s\n' "$(now_utc)"
        printf 'hostname=%s\n' "$(hostname 2>/dev/null || true)"
        printf 'operator=%s\n' "${SUDO_USER:-${USER:-unknown}}"
        printf 'lab_home=%s\n' "$LAB_HOME"
        printf 'case_dir=%s\n' "$CASE_DIR"
        printf 'lab_profile=%s\n' "${LAB_PROFILE:-unknown}"
    } >"$out"
}

evidence_path() {
    local name="$1"
    printf '%s/%s' "$CASE_DIR" "$name"
}
