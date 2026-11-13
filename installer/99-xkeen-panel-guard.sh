#!/bin/sh
# Install in /opt/etc/ndm/netfilter.d/. NDM may run this after rewriting a table.
[ "${table:-}" = filter ] || exit 0
case "${type:-}" in iptables|ip6tables) ;; *) exit 0 ;; esac
exec /opt/sbin/xkeen-panel-guard apply-api
