#!/bin/bash
# fix-vm-redirect.sh — Patch existing ztunnel iptables rules in a VM workload's netns
# to correctly route VM outbound traffic to port 15001 instead of 15006.
#
# Usage:
#   fix-vm-redirect.sh <netns_path> [vm_internal_ip]
#
# Examples:
#   fix-vm-redirect.sh /var/run/netns/simwl-abc123
#   fix-vm-redirect.sh /proc/12345/ns/net 169.254.0.2
#
# Default vm_internal_ip is 169.254.0.2

set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <netns_path> [vm_internal_ip]"
    exit 1
fi

NETNS_ARG="$1"
VM_IP="${2:-169.254.0.2}"

CHAIN="ZTUNNEL_PRERT"
OUTBOUND_PORT=15001
DNS_PORT=15053
MARK_ZTUNNEL="0x539/0xfff"

# Build nsenter prefix
if [[ "$NETNS_ARG" == /proc/*/ns/net ]] || [[ "$NETNS_ARG" == /var/run/netns/* ]]; then
    NSENTER="nsenter --net=$NETNS_ARG"
elif ip netns list 2>/dev/null | grep -q "^${NETNS_ARG} "; then
    NSENTER="ip netns exec $NETNS_ARG"
else
    NSENTER="nsenter --net=$NETNS_ARG"
fi

echo "Netns:  $NETNS_ARG"
echo "VM IP:  $VM_IP"
echo ""

# Show current rules
echo "=== BEFORE ==="
$NSENTER iptables -t nat -L $CHAIN -n -v --line-numbers 2>/dev/null || {
    echo "ERROR: $CHAIN chain not found — redirect rules not installed yet"
    exit 1
}
echo ""

# Check if VM rules already exist
if $NSENTER iptables -t nat -C $CHAIN -s "$VM_IP/32" -p tcp -m mark ! --mark $MARK_ZTUNNEL -j REDIRECT --to-ports $OUTBOUND_PORT 2>/dev/null; then
    echo "VM outbound rules already present, nothing to do."
    exit 0
fi

# Find the line number of the inbound catch-all rule (REDIRECT to 15006).
# We insert VM rules BEFORE it.
INBOUND_LINE=$($NSENTER iptables -t nat -L $CHAIN -n --line-numbers | grep "redir ports 15006" | head -1 | awk '{print $1}')

if [[ -z "$INBOUND_LINE" ]]; then
    echo "ERROR: Could not find the inbound redirect rule (port 15006) in $CHAIN"
    echo "Cannot determine where to insert VM rules."
    exit 1
fi

echo "Inserting VM outbound rules at line $INBOUND_LINE (before inbound catch-all)..."

# Insert TCP outbound rule first (it will become line $INBOUND_LINE)
$NSENTER iptables -t nat -I $CHAIN $INBOUND_LINE \
    -s "$VM_IP/32" -p tcp -m mark ! --mark $MARK_ZTUNNEL \
    -j REDIRECT --to-ports $OUTBOUND_PORT

echo ""
echo "=== AFTER ==="
$NSENTER iptables -t nat -L $CHAIN -n -v --line-numbers

echo ""
echo "Done. VM outbound traffic from $VM_IP will now route to port $OUTBOUND_PORT (outbound)."
