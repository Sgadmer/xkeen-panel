#!/bin/sh
# Run this opt-in companion from the vetted installer directory on the router.
# Only published Claude API/Console destination prefixes are enabled by default.
set -eu
umask 077
[ "$#" -eq 1 ] || { echo 'usage: install-claude-guard.sh check|install' >&2; exit 2; }
case "$1" in
    check) exec /opt/sbin/xkeen-panel-guard check-api ;;
    install) ;;
    *) exit 2 ;;
esac
[ "$(id -u)" = 0 ] || { echo 'root is required' >&2; exit 1; }
source_dir=$(CDPATH='' cd -P "$(dirname "$0")" && pwd)
guard=/opt/sbin/xkeen-panel-guard
init=/opt/etc/init.d/S01xkeen-panel-guard
hook=/opt/etc/ndm/netfilter.d/99-xkeen-panel-guard.sh

check_file() {
    [ -f "$1" ] && [ ! -L "$1" ] && sh -n "$1" || return 1
    if [ -e "$2" ] || [ -L "$2" ]; then
        [ -f "$2" ] && [ ! -L "$2" ] && cmp -s "$1" "$2" || {
            printf 'existing companion differs: %s\n' "$2" >&2
            return 1
        }
    fi
    [ -d "${2%/*}" ] && [ -w "${2%/*}" ]
}
check_file "$source_dir/strict-guard.sh" "$guard"
check_file "$source_dir/S01xkeen-panel-guard" "$init"
check_file "$source_dir/99-xkeen-panel-guard.sh" "$hook"
for command in iptables ip6tables iptables-restore ip6tables-restore; do
    command -v "$command" >/dev/null || { echo "missing $command" >&2; exit 1; }
done

# Publish each complete executable in its own directory. If an interrupted
# install is retried, existing identical files are accepted. Nothing flushes or
# removes a firewall during an installation or a partial failure.
temp=''
trap '[ -z "$temp" ] || rm -f "$temp"' EXIT
trap 'exit 1' HUP INT TERM
publish() {
    if [ -e "$2" ]; then
        check_file "$1" "$2" || return 1
        [ -x "$2" ] || chmod 0755 "$2"
        return
    fi
    temp=$(mktemp "${2%/*}/.xkp-guard.XXXXXX")
    cat "$1" > "$temp"
    chmod 0755 "$temp"
    # A hard link creates the final name atomically and never replaces an
    # independently installed companion. Both paths share the same filesystem.
    if ! ln "$temp" "$2"; then check_file "$1" "$2" && [ -x "$2" ] || return 1; fi
    rm -f "$temp"
    temp=''
}
publish "$source_dir/strict-guard.sh" "$guard"
publish "$source_dir/S01xkeen-panel-guard" "$init"
publish "$source_dir/99-xkeen-panel-guard.sh" "$hook"
"$guard" apply-api
"$guard" check-api
