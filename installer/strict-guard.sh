#!/bin/sh
# Protect Xray FakeDNS pools and Anthropic's published API/Console ingress
# networks if the interceptor disappears. Never change ordinary traffic or DNS.
set -eu
LC_ALL=C
export LC_ALL

[ "$#" = 1 ] || exit 2
case "$1" in check|apply|check-api|apply-api|check-policy) mode=$1 ;; *) exit 2 ;; esac

if [ "$mode" = check-policy ]; then
    # Candidate selectors arrive on stdin. A native exclusive route and a
    # conditional FakeDNS use different classifiers and packet paths. A FakeDNS
    # adapter must also call `check` for its pools. An absent verifier fails.
    verifier=/opt/sbin/xkeen-panel-policy-check
    if [ ! -x "$verifier" ]; then
        printf 'strict guard: router policy verifier is unavailable\n' >&2
        exit 1
    fi
    exec "$verifier"
fi

at_head() {
    # A matching rule below a broad ACCEPT or ESTABLISHED would be ineffective.
    printf '%s\n' "$snapshot" | awk -v prefixes="$prefixes" '
        BEGIN { count = split(prefixes, pool, " ") }
        $1 == "-A" && ($2 == "FORWARD" || $2 == "OUTPUT") && seen[$2] < count {
            if ($0 != "-A " $2 " -d " pool[++seen[$2]] " -j DROP") bad = 1
        }
        END { exit (bad || seen["FORWARD"] != count || seen["OUTPUT"] != count) }
    '
}

reconcile() {
    family=$1 prefixes=$2
    # Keenetic ships xtables 1.4.21, whose -w takes no timeout. Without -w a
    # contended lock fails promptly, allowing the caller to retry safely.
    snapshot=$("$family" -t filter -S) || return 1
    at_head && return 0
    case "$mode" in apply|apply-api) ;; *) return 1 ;; esac

    # Delete matching copies and put both replacements first in ONE kernel
    # table transaction. A stale snapshot may make the commit fail, leaving
    # the old table intact. No other host, chain, or rule is changed.
    batch=$(printf '%s\n' "$snapshot" | awk -v prefixes="$prefixes" '
        BEGIN {
            print "*filter"
            count = split(prefixes, pool, " ")
            for (i=1; i<=count; i++) {
                ours["-A FORWARD -d " pool[i] " -j DROP"] = 1
                ours["-A OUTPUT -d " pool[i] " -j DROP"] = 1
            }
        }
        $0 in ours {
            sub(/^-A /, "-D "); print
        }
        END {
            for (i=count; i>=1; i--) {
                print "-I FORWARD -d " pool[i] " -j DROP"
                print "-I OUTPUT -d " pool[i] " -j DROP"
            }
            print "COMMIT"
        }
    ') || return 1
    printf '%s\n' "$batch" | "$family-restore" --noflush || return 1
    snapshot=$("$family" -t filter -S) || return 1
    at_head
}

failed=0
# Source for real destination ranges: https://platform.claude.com/docs/en/api/ip-addresses
# Use the inbound prefixes only. Outbound/MCP and retired addresses serve a different purpose.
v4='160.79.104.0/23 153.61.224.0/22'
v6='2607:6bc0::/48'
case "$mode" in
    check|apply) v4="$v4 198.18.0.0/15"; v6="$v6 2001:2::/48" ;;
esac
if ! reconcile iptables "$v4"; then
    printf 'strict guard: IPv4 filter not ready\n' >&2
    failed=1
fi
if ! reconcile ip6tables "$v6"; then
    printf 'strict guard: IPv6 filter not ready\n' >&2
    failed=1
fi
[ "$failed" = 0 ] || exit 1
case "$mode" in
    check-api|apply-api) printf 'anthropic-api-firewall-ready\n' ;;
    *) printf 'selective-firewall-ready\n' ;;
esac
