#!/bin/bash
# simulate-workload.sh — Simulate a non-K8s workload for ztunnel enrollment
#
# Creates a network namespace via unshare, holds it open with sleep,
# sets up a veth pair through a linux bridge so the workload netns
# can communicate with the root namespace, then writes a manifest
# manifest.json so ManifestPidFetcher can attest the PID.
#
# Usage:
#   simulate-workload.sh <name> <namespace> <service_account> [instances_dir]
#
# Example:
#   simulate-workload.sh agent-a cluster-a default /instances
#
# This will:
#   1. Generate a UID for the workload
#   2. Create a new network namespace via unshare + sleep
#   3. Create a linux bridge (simwl-br0) in the root netns (if not exists)
#   4. Create a veth pair, attach one end to the bridge, other to the workload netns
#   5. Assign IP addresses and routes for connectivity
#   6. Write {instances_dir}/{uid}/manifest.json with shimProcessId
#   7. Print the ZDS add and WDS add commands to run
#
# Networking:
#   Bridge:     simwl-br0    10.200.0.1/24  (root netns)
#   Workload:   eth0         10.200.0.X/24  (workload netns, auto-assigned)
#
# To clean up:
#   simulate-workload.sh --cleanup <uid> [instances_dir]

set -euo pipefail

BRIDGE_NAME="simwl-br0"
BRIDGE_SUBNET="10.200.0"
BRIDGE_IP="${BRIDGE_SUBNET}.1"
BRIDGE_CIDR="${BRIDGE_IP}/24"
INSTANCES_DIR="${4:-/instances}"

# Find the next available IP on the bridge subnet by scanning existing workloads
next_ip() {
    local used=()
    # Collect IPs already assigned from existing manifest.json files
    if [[ -d "$INSTANCES_DIR" ]]; then
        for cfg in "$INSTANCES_DIR"/*/manifest.json; do
            [[ -f "$cfg" ]] || continue
            local ip
            ip=$(grep -o '"ip": *"[^"]*"' "$cfg" 2>/dev/null | grep -o '[0-9.]*' || true)
            if [[ -n "$ip" ]]; then
                used+=("$ip")
            fi
        done
    fi
    # Start from .2, find first unused
    for i in $(seq 2 254); do
        local candidate="${BRIDGE_SUBNET}.$i"
        local found=false
        for u in "${used[@]+"${used[@]}"}"; do
            if [[ "$u" == "$candidate" ]]; then
                found=true
                break
            fi
        done
        if [[ "$found" == "false" ]]; then
            echo "$candidate"
            return
        fi
    done
    echo "ERROR: No available IPs on ${BRIDGE_SUBNET}.0/24" >&2
    exit 1
}

cleanup() {
    local uid="$2"
    local dir="${3:-/instances}"
    local cfgfile="$dir/$uid/manifest.json"

    if [[ ! -f "$cfgfile" ]]; then
        echo "ERROR: No manifest.json found at $cfgfile"
        exit 1
    fi

    local pid name
    pid=$(grep -o '"shimProcessId": *[0-9]*' "$cfgfile" | grep -o '[0-9]*$')
    name=$(grep -o '"name": *"[^"]*"' "$cfgfile" | cut -d'"' -f4)
    local veth_host="veth-${name}"

    echo "Killing sleep process (PID $pid)..."
    kill "$pid" 2>/dev/null || true

    # Remove the veth (this also removes the peer inside the netns)
    if ip link show "$veth_host" &>/dev/null; then
        echo "Removing veth $veth_host..."
        ip link del "$veth_host" 2>/dev/null || true
    fi

    echo "Removing $dir/$uid/"
    rm -rf "$dir/$uid"

    # If no more workloads, remove the bridge
    local remaining
    remaining=$(find "$dir" -name manifest.json 2>/dev/null | wc -l)
    if [[ "$remaining" -eq 0 ]] && ip link show "$BRIDGE_NAME" &>/dev/null; then
        echo "No more workloads, removing bridge $BRIDGE_NAME..."
        ip link set "$BRIDGE_NAME" down 2>/dev/null || true
        ip link del "$BRIDGE_NAME" 2>/dev/null || true
    fi

    echo "Cleaned up workload $uid"
    exit 0
}

if [[ "${1:-}" == "--cleanup" ]]; then
    cleanup "$@"
fi

if [[ $# -lt 3 ]]; then
    echo "Usage: $0 <name> <namespace> <service_account> [instances_dir]"
    echo "       $0 --cleanup <uid> [instances_dir]"
    exit 1
fi

NAME="$1"
NAMESPACE="$2"
SA="$3"

# Generate a UUID for the workload UID
if command -v uuidgen &>/dev/null; then
    UID_VAL=$(uuidgen | tr '[:upper:]' '[:lower:]')
else
    UID_VAL=$(cat /proc/sys/kernel/random/uuid)
fi

# Pick an IP for this workload
WORKLOAD_IP=$(next_ip)

echo "=== Simulating workload ==="
echo "  Name:            $NAME"
echo "  Namespace:       $NAMESPACE"
echo "  Service Account: $SA"
echo "  UID:             $UID_VAL"
echo "  Instances Dir:   $INSTANCES_DIR"
echo ""

# Step 1: Create network namespace with unshare + sleep
echo "Creating network namespace with unshare..."
unshare --net sleep infinity &
SLEEP_PID=$!

# Give it a moment to start
sleep 0.5

# Verify the process is running
if ! kill -0 "$SLEEP_PID" 2>/dev/null; then
    echo "ERROR: sleep process failed to start"
    exit 1
fi

# The netns is accessible at /proc/$PID/ns/net
NETNS_PATH="/proc/$SLEEP_PID/ns/net"

if [[ ! -e "$NETNS_PATH" ]]; then
    echo "ERROR: Network namespace not found at $NETNS_PATH"
    kill "$SLEEP_PID" 2>/dev/null || true
    exit 1
fi

echo "  Sleep PID:       $SLEEP_PID"
echo "  Netns Path:      $NETNS_PATH"
echo ""

# Step 2: Create a named netns symlink so "ip netns exec" works
# ip netns expects entries under /var/run/netns/
NETNS_NAME="simwl-${NAME}"
mkdir -p /var/run/netns
# Remove stale symlink if it exists
rm -f "/var/run/netns/$NETNS_NAME"
ln -sf "$NETNS_PATH" "/var/run/netns/$NETNS_NAME"
echo "  Netns Name:      $NETNS_NAME (symlinked to $NETNS_PATH)"

# Step 3: Set up the bridge in the root namespace (idempotent)
if ! ip link show "$BRIDGE_NAME" &>/dev/null; then
    echo ""
    echo "Creating bridge $BRIDGE_NAME with IP $BRIDGE_CIDR..."
    ip link add "$BRIDGE_NAME" type bridge
    ip addr add "$BRIDGE_CIDR" dev "$BRIDGE_NAME"
    ip link set "$BRIDGE_NAME" up
    # Enable IP forwarding so traffic can flow
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
else
    echo "  Bridge $BRIDGE_NAME already exists"
fi

# Step 4: Create veth pair
VETH_HOST="veth-${NAME}"
VETH_PEER="vpeer-${NAME}"
VETH_NS="eth0"

echo ""
echo "Creating veth pair: $VETH_HOST <-> $VETH_PEER..."

# Remove stale veth if it exists from a previous run
ip link del "$VETH_HOST" 2>/dev/null || true

# Create the veth pair (use unique peer name to avoid conflicts with root eth0)
ip link add "$VETH_HOST" type veth peer name "$VETH_PEER"

# Attach host end to the bridge
ip link set "$VETH_HOST" master "$BRIDGE_NAME"
ip link set "$VETH_HOST" up

# Move peer end into the workload's network namespace
ip link set "$VETH_PEER" netns "$NETNS_NAME"

# Rename the peer to eth0 inside the netns (safe — it's a separate namespace)
ip netns exec "$NETNS_NAME" ip link set "$VETH_PEER" name "$VETH_NS"

# Step 5: Configure networking inside the workload netns
echo "Configuring workload netns networking..."

# Bring up lo + eth0, assign IP, add default route via bridge
ip netns exec "$NETNS_NAME" ip link set lo up
ip netns exec "$NETNS_NAME" ip addr add "${WORKLOAD_IP}/24" dev "$VETH_NS"
ip netns exec "$NETNS_NAME" ip link set "$VETH_NS" up
ip netns exec "$NETNS_NAME" ip route add default via "$BRIDGE_IP"

echo "  Workload IP:     $WORKLOAD_IP/24"
echo "  Gateway:         $BRIDGE_IP (bridge)"
echo "  Veth host:       $VETH_HOST"
echo "  Veth netns:      $VETH_NS"
echo ""

# Step 6: Verify connectivity
echo "Verifying connectivity..."
PING_BIN=$(command -v ping 2>/dev/null || echo "/usr/bin/ping")
if ip netns exec "$NETNS_NAME" "$PING_BIN" -c 1 -W 1 "$BRIDGE_IP" &>/dev/null; then
    echo "  Ping root netns ($BRIDGE_IP): OK"
else
    echo "  Ping root netns ($BRIDGE_IP): FAILED (non-fatal, continuing)"
fi
echo ""

# Step 7: Create the manifest.json
MANIFEST_DIR="$INSTANCES_DIR/$UID_VAL"
mkdir -p "$MANIFEST_DIR"

cat > "$MANIFEST_DIR/manifest.json" <<EOF
{
    "id": "$UID_VAL",
    "name": "$NAME",
    "namespace": "$NAMESPACE",
    "serviceAccount": "$SA",
    "shimProcessId": $SLEEP_PID,
    "ip": "$WORKLOAD_IP",
    "netns": "$NETNS_NAME",
    "vethHost": "$VETH_HOST"
}
EOF

echo "Wrote manifest: $MANIFEST_DIR/manifest.json"
cat "$MANIFEST_DIR/manifest.json"
echo ""

# Step 8: Print the commands to enroll this workload
echo "=== Next Steps ==="
echo ""
echo "1. ZDS enroll (run on local node's zds-server):"
echo "   zds-client send --control-socket /var/run/ztunnel/control.sock \\"
echo "     'add $UID_VAL $NAME $NAMESPACE $SA $NETNS_PATH'"
echo ""
echo "2. WDS register (run on xds-aggregator):"
echo "   zds-client send --control-socket /tmp/control.sock \\"
echo "     'wds-add $UID_VAL $NAME $NAMESPACE $SA $WORKLOAD_IP TCP <NODE_NAME>'"
echo ""
echo "3. SPIRE entry create:"
echo "   spire-server entry create \\"
echo "     -spiffeID spiffe://<trust-domain>/ns/$NAMESPACE/sa/$SA \\"
echo "     -parentID spiffe://<trust-domain>/spire/agent/<node-attestor>/<node-id> \\"
echo "     -selector unix:pid:$SLEEP_PID"
echo ""
echo "4. Test connectivity from workload netns:"
echo "   ip netns exec $NETNS_NAME ping $BRIDGE_IP"
echo "   ip netns exec $NETNS_NAME curl <target_ip>:<port>"
echo ""
echo "5. Cleanup when done:"
echo "   $0 --cleanup $UID_VAL $INSTANCES_DIR"
echo ""
echo "=== Workload ready for enrollment ==="
