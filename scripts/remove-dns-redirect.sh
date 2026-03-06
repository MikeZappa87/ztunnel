#!/bin/bash
# remove-dns-redirect.sh — Remove all DNS (port 53) redirect rules from ztunnel chains
#
# Usage:
#   remove-dns-redirect.sh <netns_path>
#
# Example:
#   remove-dns-redirect.sh /proc/388256/ns/net

set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <netns_path>"
    exit 1
fi

NETNS_ARG="$1"

# Build nsenter prefix
if [[ "$NETNS_ARG" == /proc/*/ns/net ]] || [[ "$NETNS_ARG" == /var/run/netns/* ]]; then
    NSENTER="nsenter --net=$NETNS_ARG"
elif ip netns list 2>/dev/null | grep -q "^${NETNS_ARG} "; then
    NSENTER="ip netns exec $NETNS_ARG"
else
    NSENTER="nsenter --net=$NETNS_ARG"
fi

echo "Netns: $NETNS_ARG"
echo ""
echo "=== BEFORE ==="
$NSENTER iptables -t nat -L ZTUNNEL_OUTPUT -n -v --line-numbers 2>/dev/null || true
$NSENTER iptables -t nat -L ZTUNNEL_PRERT -n -v --line-numbers 2>/dev/null || true
echo ""

# Remove DNS rules from ZTUNNEL_OUTPUT (iterate in reverse to preserve line numbers)
echo "Removing DNS rules from ZTUNNEL_OUTPUT..."
while true; do
    LINE=$($NSENTER iptables -t nat -L ZTUNNEL_OUTPUT -n --line-numbers 2>/dev/null \
        | grep -E 'dpt:53|redir ports 15053' | tail -1 | awk '{print $1}')
    if [[ -z "$LINE" ]]; then
        break
    fi
    echo "  Deleting ZTUNNEL_OUTPUT rule $LINE"
    $NSENTER iptables -t nat -D ZTUNNEL_OUTPUT "$LINE"
done

# Remove DNS rules from ZTUNNEL_PRERT (iterate in reverse to preserve line numbers)
echo "Removing DNS rules from ZTUNNEL_PRERT..."
while true; do
    LINE=$($NSENTER iptables -t nat -L ZTUNNEL_PRERT -n --line-numbers 2>/dev/null \
        | grep -E 'dpt:53|redir ports 15053' | tail -1 | awk '{print $1}')
    if [[ -z "$LINE" ]]; then
        break
    fi
    echo "  Deleting ZTUNNEL_PRERT rule $LINE"
    $NSENTER iptables -t nat -D ZTUNNEL_PRERT "$LINE"
done

echo ""
echo "=== AFTER ==="
$NSENTER iptables -t nat -L ZTUNNEL_OUTPUT -n -v --line-numbers 2>/dev/null || true
$NSENTER iptables -t nat -L ZTUNNEL_PRERT -n -v --line-numbers 2>/dev/null || true
echo ""
echo "Done. All DNS redirect rules removed."
