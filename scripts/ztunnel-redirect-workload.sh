#!/bin/bash
# ztunnel-redirect-workload.sh — Install/remove iptables redirect rules in a workload's network namespace
#
# This sets up traffic interception so ztunnel can proxy workload traffic:
#   - Outbound TCP → redirected to ztunnel outbound port (15001)
#   - Outbound DNS → redirected to ztunnel DNS (15053)
#   - Inbound TCP (non-15008) → redirected to ztunnel inbound passthrough (15006)
#   - CONNMARK-based original source preservation
#
# Usage:
#   ztunnel-redirect-workload.sh install <netns_path>
#   ztunnel-redirect-workload.sh remove  <netns_path>
#
# Where netns_path is either:
#   - /proc/<pid>/ns/net
#   - /var/run/netns/<name>
#   - A named netns (simwl-xxx)

set -euo pipefail

CHAIN_PREFIX="ZTUNNEL"
OUTBOUND_PORT=15001
INBOUND_PORT=15006
INBOUND_TLS_PORT=15008
DNS_PORT=15053
MARK_ZTUNNEL="0x539/0xfff"     # mark set by ztunnel on its own traffic
MARK_CONNMARK="0x111/0xfff"    # connmark for original src preservation

usage() {
    echo "Usage: $0 {install|remove} <netns_path>"
    echo ""
    echo "  install  - Install iptables redirect rules in the netns"
    echo "  remove   - Remove iptables redirect rules from the netns"
    echo ""
    echo "  netns_path: /proc/<pid>/ns/net, /var/run/netns/<name>, or a named netns"
    exit 1
}

if [[ $# -lt 2 ]]; then
    usage
fi

ACTION="$1"
NETNS_ARG="$2"

# Build the nsenter prefix based on the netns argument type
if [[ "$NETNS_ARG" == /proc/*/ns/net ]] || [[ "$NETNS_ARG" == /var/run/netns/* ]]; then
    # Path-based: use nsenter --net=<path>
    NSENTER="nsenter --net=$NETNS_ARG"
elif ip netns list 2>/dev/null | grep -q "^${NETNS_ARG} "; then
    # Named netns
    NSENTER="ip netns exec $NETNS_ARG"
else
    # Try as a path anyway
    NSENTER="nsenter --net=$NETNS_ARG"
fi

install_rules() {
    echo "Installing ztunnel redirect rules in $NETNS_ARG..."

    # Check if rules already installed
    if $NSENTER iptables -t mangle -L ${CHAIN_PREFIX}_PRERT -n &>/dev/null; then
        echo "  Rules already installed, skipping"
        return 0
    fi

    $NSENTER iptables-restore --wait 10 --noflush <<EOF
*mangle
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:${CHAIN_PREFIX}_OUTPUT - [0:0]
:${CHAIN_PREFIX}_PRERT - [0:0]
-A PREROUTING -j ${CHAIN_PREFIX}_PRERT
-A OUTPUT -j ${CHAIN_PREFIX}_OUTPUT
-A ${CHAIN_PREFIX}_OUTPUT -m connmark --mark ${MARK_CONNMARK} -j CONNMARK --restore-mark --nfmask 0xffffffff --ctmask 0xffffffff
-A ${CHAIN_PREFIX}_PRERT -m mark --mark ${MARK_ZTUNNEL} -j CONNMARK --set-xmark ${MARK_CONNMARK}
COMMIT
*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:${CHAIN_PREFIX}_OUTPUT - [0:0]
:${CHAIN_PREFIX}_PRERT - [0:0]
-A OUTPUT -j ${CHAIN_PREFIX}_OUTPUT
-A PREROUTING -j ${CHAIN_PREFIX}_PRERT
-A ${CHAIN_PREFIX}_OUTPUT -d 169.254.7.127/32 -p tcp -m tcp -j ACCEPT
-A ${CHAIN_PREFIX}_OUTPUT ! -o lo -p udp -m mark ! --mark ${MARK_ZTUNNEL} -m udp --dport 53 -j REDIRECT --to-ports ${DNS_PORT}
-A ${CHAIN_PREFIX}_OUTPUT ! -d 127.0.0.1/32 -p tcp -m tcp --dport 53 -m mark ! --mark ${MARK_ZTUNNEL} -j REDIRECT --to-ports ${DNS_PORT}
-A ${CHAIN_PREFIX}_OUTPUT -p tcp -m mark --mark ${MARK_CONNMARK} -j ACCEPT
-A ${CHAIN_PREFIX}_OUTPUT ! -d 127.0.0.1/32 -o lo -j ACCEPT
-A ${CHAIN_PREFIX}_OUTPUT ! -d 127.0.0.1/32 -p tcp -m mark ! --mark ${MARK_ZTUNNEL} -j REDIRECT --to-ports ${OUTBOUND_PORT}
-A ${CHAIN_PREFIX}_PRERT -s 169.254.7.127/32 -p tcp -m tcp -j ACCEPT
-A ${CHAIN_PREFIX}_PRERT ! -d 127.0.0.1/32 -p tcp ! --dport ${INBOUND_TLS_PORT} -m mark ! --mark ${MARK_ZTUNNEL} -j REDIRECT --to-ports ${INBOUND_PORT}
COMMIT
EOF

    # Route table for tproxy / original source preservation
    $NSENTER ip route add local 0.0.0.0/0 dev lo table 100 2>/dev/null || true
    $NSENTER ip rule add fwmark ${MARK_CONNMARK} pref 32764 lookup 100 2>/dev/null || true

    echo "  Redirect rules installed"
}

remove_rules() {
    echo "Removing ztunnel redirect rules from $NETNS_ARG..."

    # Remove jump rules from built-in chains
    $NSENTER iptables -t mangle -D PREROUTING -j ${CHAIN_PREFIX}_PRERT 2>/dev/null || true
    $NSENTER iptables -t mangle -D OUTPUT -j ${CHAIN_PREFIX}_OUTPUT 2>/dev/null || true
    $NSENTER iptables -t nat -D OUTPUT -j ${CHAIN_PREFIX}_OUTPUT 2>/dev/null || true
    $NSENTER iptables -t nat -D PREROUTING -j ${CHAIN_PREFIX}_PRERT 2>/dev/null || true

    # Flush and delete custom chains
    $NSENTER iptables -t mangle -F ${CHAIN_PREFIX}_OUTPUT 2>/dev/null || true
    $NSENTER iptables -t mangle -X ${CHAIN_PREFIX}_OUTPUT 2>/dev/null || true
    $NSENTER iptables -t mangle -F ${CHAIN_PREFIX}_PRERT 2>/dev/null || true
    $NSENTER iptables -t mangle -X ${CHAIN_PREFIX}_PRERT 2>/dev/null || true
    $NSENTER iptables -t nat -F ${CHAIN_PREFIX}_OUTPUT 2>/dev/null || true
    $NSENTER iptables -t nat -X ${CHAIN_PREFIX}_OUTPUT 2>/dev/null || true
    $NSENTER iptables -t nat -F ${CHAIN_PREFIX}_PRERT 2>/dev/null || true
    $NSENTER iptables -t nat -X ${CHAIN_PREFIX}_PRERT 2>/dev/null || true

    # Remove routing rule and route
    $NSENTER ip rule del fwmark ${MARK_CONNMARK} pref 32764 lookup 100 2>/dev/null || true
    $NSENTER ip route del local 0.0.0.0/0 dev lo table 100 2>/dev/null || true

    echo "  Redirect rules removed"
}

case "$ACTION" in
    install)
        install_rules
        ;;
    remove)
        remove_rules
        ;;
    *)
        usage
        ;;
esac
