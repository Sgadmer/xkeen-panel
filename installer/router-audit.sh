#!/bin/sh
# Read-only inventory. Do not run XKeen itself: some dispatcher versions mutate
# their scratch/install files even for informational arguments.
set -eu
ROOT=${1:-}
case "$ROOT" in ''|/*) ;; *) printf 'invalid_root\n' >&2; exit 2;; esac
OPT=$ROOT/opt
emit() { printf '%s=%s\n' "$1" "$(printf '%s' "$2" | tr -cd 'A-Za-z0-9._+,:/ ()=-' | cut -c1-240)"; }
emit schema 1
emit platform "$(uname -s)"
emit kernel "$(uname -r)"
emit machine "$(uname -m)"
emit uid "$(id -u)"
emit entware "$([ -d "$OPT/etc" ] && command -v opkg >/dev/null 2>&1 && echo found || echo missing)"
if command -v opkg >/dev/null 2>&1; then
    emit entware_arch "$(opkg print-architecture 2>/dev/null | awk '$2!="all" && $2!="noarch" {a=$2} END {print a}')"
fi
emit mem_total_kib "$(awk '/^MemTotal:/ {print $2}' "$ROOT/proc/meminfo" 2>/dev/null || true)"
emit mem_available_kib "$(awk '/^MemAvailable:/ {print $2}' "$ROOT/proc/meminfo" 2>/dev/null || true)"
emit swap_total_kib "$(awk '/^SwapTotal:/ {print $2}' "$ROOT/proc/meminfo" 2>/dev/null || true)"
for location in "$OPT" "$ROOT/tmp"; do
    [ -d "$location" ] || continue
    emit filesystem "$(df -PT "$location" 2>/dev/null | awk 'NR==2 {print $2}')"
    emit free_kib "$(df -Pk "$location" 2>/dev/null | awk 'NR==2 {print $4}')"
    emit free_inodes "$(df -Pi "$location" 2>/dev/null | awk 'NR==2 {print $4}')"
done
for tool in ndmc opkg curl tar unzip jq sha256sum timeout ip iptables ipset; do
    command -v "$tool" >/dev/null 2>&1 && emit command "$tool:found" || emit command "$tool:missing"
done
if command -v curl >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then
    version=$(curl -fsS --max-time 4 http://127.0.0.1:79/rci/show/version 2>/dev/null || true)
    if printf '%s' "$version" | jq -e 'type=="object"' >/dev/null 2>&1; then
        emit model "$(printf '%s' "$version" | jq -r '.model // .system.model // "unknown" | if type=="string" then . else "unknown" end')"
        emit firmware "$(printf '%s' "$version" | jq -r '.release // .system.release // "unknown" | if type=="string" then . else "unknown" end')"
        emit netfilter_component "$(printf '%s' "$version" | jq -r '(.components // "") | if type=="string" then contains("opkg-kmod-netfilter") else false end')"
    else
        emit native_api 'unavailable-use-authenticated-web-interface'
    fi
fi
for process in xray mihomo xkeen-panel xkeen-ui xkeen-go nginx; do
    emit running "$process:$([ -n "$(pidof "$process" 2>/dev/null || true)" ] && echo yes || echo no)"
done
if [ -d "$OPT/etc/init.d" ]; then
    for entry in "$OPT/etc/init.d/"*xkeen* "$OPT/etc/init.d/"*xray* "$OPT/etc/init.d/"*mihomo*; do
        [ -f "$entry" ] || continue
        emit init_script "$(basename "$entry")"
    done
fi
for directory in "$OPT/etc/xray/configs" "$OPT/etc/xkeen-panel/data" "$OPT/etc/mihomo" "$OPT/etc/xkeen"; do
    [ -d "$directory" ] || continue
    emit config_directory "${directory#"$ROOT"}"
    emit config_files "$(find "$directory" -type f | wc -l | tr -d ' ')"
done
if [ -d "$OPT/etc/xray/dat" ]; then
    for file in "$OPT/etc/xray/dat/"*.dat; do [ ! -f "$file" ] || emit geodata "$(basename "$file") size:$(wc -c < "$file" | tr -d ' ')"; done
fi
emit conclusion 'agent-must-review-model-firmware-rcitoken-netfilter-resource-budget-and-existing-rules'
