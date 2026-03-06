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
MARK_ZTUNNEL="0x539/0xfff"     # mark set by ztunnel on its own traffic
MARK_CONNMARK="0x111/0xfff"    # connmark for original src preservation

VM_INTERNAL_IP=""
TRANSPARENT_PROXY=false
VM_IFACE_MODE=false

usage() {
    echo "Usage: $0 {install|remove} <netns_path> [--vm-internal-ip <ip>] [--transparent-proxy]"
    echo ""
    echo "  install  - Install iptables redirect rules in the netns"
    echo "  remove   - Remove iptables redirect rules from the netns"
    echo ""
    echo "  netns_path: /proc/<pid>/ns/net, /var/run/netns/<name>, or a named netns"
    echo ""
    echo "  --vm-internal-ip <ip>  VM's internal IP (e.g. 169.254.0.2)."
    echo "      When set, VM outbound traffic (from this IP) arriving via"
    echo "      PREROUTING is redirected to the outbound port (15001) instead"
    echo "      of the inbound port (15006)."
    echo ""
    echo "  --transparent-proxy    Redirect ALL traffic in PREROUTING to"
    echo "      the HBONE inbound port (15008). No port-based inbound/outbound"
    echo "      split. Use when a transparent proxy sits in front of ztunnel."
    echo ""
    echo "  --vm-iface-mode        Use interface-based routing in PREROUTING:"
    echo "      tap0 traffic (VM outbound) → 15001, veth+ traffic (mesh inbound) → 15008."
    echo "      Mutually exclusive with --transparent-proxy and --vm-internal-ip."
    exit 1
}

if [[ $# -lt 2 ]]; then
    usage
fi

ACTION="$1"
NETNS_ARG="$2"
shift 2

# Parse optional flags
while [[ $# -gt 0 ]]; do
    case "$1" in
        --vm-internal-ip)
            VM_INTERNAL_IP="$2"
            shift 2
            ;;
        --transparent-proxy)
            TRANSPARENT_PROXY=true
            shift
            ;;
        --vm-iface-mode)
            VM_IFACE_MODE=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

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

    # Build VM-specific PREROUTING rules if --vm-internal-ip was provided.
    # In VM workloads, outbound traffic from the VM arrives via the tap/veth
    # interface and hits PREROUTING (not OUTPUT). Without these rules, VM
    # outbound gets misclassified as inbound and redirected to port 15006.
    VM_PRERT_RULES=""
    if [[ -n "$VM_INTERNAL_IP" ]] && [[ "$TRANSPARENT_PROXY" == false ]] && [[ "$VM_IFACE_MODE" == false ]]; then
        echo "  VM mode: internal IP=$VM_INTERNAL_IP — adding outbound rules in PREROUTING"
        VM_PRERT_RULES=$(cat <<-VMEOF
-A ${CHAIN_PREFIX}_PRERT -s ${VM_INTERNAL_IP}/32 -p tcp -m mark ! --mark ${MARK_ZTUNNEL} -j REDIRECT --to-ports ${OUTBOUND_PORT}
VMEOF
        )
    fi

    # Determine the PREROUTING catch-all rule(s) based on mode:
    #   --vm-iface-mode: interface-based — tap0 → 15001 (outbound), veth+ → 15008 (inbound)
    #   --transparent-proxy: redirect ALL traffic to 15008 (HBONE)
    #   default: redirect non-15008 traffic to 15006 (inbound passthrough)
    if [[ "$VM_IFACE_MODE" == true ]]; then
        echo "  VM interface mode: tap0 → ${OUTBOUND_PORT}, veth+ → ${INBOUND_TLS_PORT}"
        PRERT_CATCHALL=$(cat <<-IFEOF
-A ${CHAIN_PREFIX}_PRERT -i tap0 -p tcp -m mark ! --mark ${MARK_ZTUNNEL} -j REDIRECT --to-ports ${OUTBOUND_PORT}
-A ${CHAIN_PREFIX}_PRERT -i veth+ -p tcp -m mark ! --mark ${MARK_ZTUNNEL} -j REDIRECT --to-ports ${INBOUND_TLS_PORT}
IFEOF
        )
    elif [[ "$TRANSPARENT_PROXY" == true ]]; then
        echo "  Transparent proxy mode: all PREROUTING traffic → ${INBOUND_TLS_PORT}"
        PRERT_CATCHALL="-A ${CHAIN_PREFIX}_PRERT ! -d 127.0.0.1/32 -p tcp -m mark ! --mark ${MARK_ZTUNNEL} -j REDIRECT --to-ports ${INBOUND_TLS_PORT}"
    else
        PRERT_CATCHALL="-A ${CHAIN_PREFIX}_PRERT ! -d 127.0.0.1/32 -p tcp ! --dport ${INBOUND_TLS_PORT} -m mark ! --mark ${MARK_ZTUNNEL} -j REDIRECT --to-ports ${INBOUND_PORT}"
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
-A ${CHAIN_PREFIX}_OUTPUT -p tcp -m mark --mark ${MARK_CONNMARK} -j ACCEPT
-A ${CHAIN_PREFIX}_OUTPUT ! -d 127.0.0.1/32 -o lo -j ACCEPT
-A ${CHAIN_PREFIX}_OUTPUT ! -d 127.0.0.1/32 -p tcp -m mark ! --mark ${MARK_ZTUNNEL} -j REDIRECT --to-ports ${OUTBOUND_PORT}
-A ${CHAIN_PREFIX}_PRERT -s 169.254.7.127/32 -p tcp -m tcp -j ACCEPT
${VM_PRERT_RULES}
${PRERT_CATCHALL}
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
