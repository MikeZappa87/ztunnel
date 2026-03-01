# simulate-workload.sh

Simulate a non-Kubernetes workload for ztunnel mesh enrollment. This script creates an isolated network namespace with full L2/L3 connectivity back to the host, writes a manifest file for PID attestation, and prints the exact commands needed to enroll the workload into the mesh.

## What It Does

1. Creates a new **network namespace** via `unshare --net` + `sleep infinity`
2. Creates a **Linux bridge** (`simwl-br0` at `10.200.0.1/24`) in the root namespace (idempotent — reused across workloads)
3. Creates a **veth pair** — host end attached to the bridge, peer end moved into the workload namespace and renamed to `eth0`
4. **Assigns an IP** (`10.200.0.2`, `.3`, etc.) auto-incrementing, with a default route via the bridge
5. Writes a **`config.json` manifest** that `ManifestPidFetcher` uses for SPIRE PID attestation
6. **Verifies connectivity** by pinging the bridge from inside the namespace

## Network Topology

```
Root Network Namespace
┌─────────────────────────────────────────────────┐
│                                                 │
│  simwl-br0 (10.200.0.1/24)                     │
│       │           │           │                 │
│  veth-agent-a  veth-agent-b  veth-...           │
│       │           │           │                 │
└───────┼───────────┼───────────┼─────────────────┘
        │           │           │
   ┌────┴────┐ ┌────┴────┐ ┌───┴─────┐
   │  netns  │ │  netns  │ │  netns  │
   │  eth0   │ │  eth0   │ │  eth0   │
   │ .0.2/24 │ │ .0.3/24 │ │ .0.4/24 │
   │ agent-a │ │ agent-b │ │   ...   │
   └─────────┘ └─────────┘ └─────────┘
```

All workload namespaces can reach each other and the root namespace through the bridge.

## Prerequisites

- Linux with `NET_ADMIN` capability (root or equivalent)
- `iproute2` (`ip` command)
- `unshare` (from `util-linux`)
- `iputils-ping` (optional, for connectivity verification)

## Usage

### Create a workload

```bash
./scripts/simulate-workload.sh <name> <namespace> <service_account> [instances_dir]
```

**Arguments:**

| Argument | Description | Example |
|----------|-------------|---------|
| `name` | Workload name | `agent-a` |
| `namespace` | Logical namespace | `cluster-a` |
| `service_account` | Service account for SPIFFE ID | `default` |
| `instances_dir` | Directory for manifest files (default: `/instances`) | `/tmp/instances` |

**Example:**

```bash
./scripts/simulate-workload.sh agent-a cluster-a default /tmp/instances
```

Output:
```
=== Simulating workload ===
  Name:            agent-a
  Namespace:       cluster-a
  Service Account: default
  UID:             839a5dc8-32a0-4f6b-9e46-da33bad646cf
  Instances Dir:   /tmp/instances

Creating network namespace with unshare...
  Sleep PID:       39894
  Netns Path:      /proc/39894/ns/net

  Netns Name:      simwl-agent-a (symlinked to /proc/39894/ns/net)

Creating bridge simwl-br0 with IP 10.200.0.1/24...

Creating veth pair: veth-agent-a <-> vpeer-agent-a...
Configuring workload netns networking...
  Workload IP:     10.200.0.2/24
  Gateway:         10.200.0.1 (bridge)
  Veth host:       veth-agent-a
  Veth netns:      eth0

Verifying connectivity...
  Ping root netns (10.200.0.1): OK
```

### Clean up a workload

```bash
./scripts/simulate-workload.sh --cleanup <uid> [instances_dir]
```

Cleanup removes the veth pair, kills the sleep process, deletes the manifest directory, and tears down the bridge if no workloads remain.

**Example:**

```bash
./scripts/simulate-workload.sh --cleanup 839a5dc8-32a0-4f6b-9e46-da33bad646cf /tmp/instances
```

## Manifest File

The script writes a `config.json` to `{instances_dir}/{uid}/config.json`:

```json
{
    "id": "839a5dc8-32a0-4f6b-9e46-da33bad646cf",
    "name": "agent-a",
    "namespace": "cluster-a",
    "serviceAccount": "default",
    "shimProcessId": 39894,
    "ip": "10.200.0.2",
    "netns": "simwl-agent-a",
    "vethHost": "veth-agent-a"
}
```

The `shimProcessId` field is what `ManifestPidFetcher` reads for SPIRE `unix:pid` attestation.

## Mesh Enrollment

After creating a workload, three steps are needed to fully enroll it in the mesh:

### 1. ZDS — Bind ztunnel to the workload's network namespace

Run on the local node's zds-server:

```bash
zds-client send --control-socket /var/run/ztunnel/control.sock \
  'add <uid> <name> <namespace> <sa> /proc/<pid>/ns/net'
```

This tells ztunnel to start proxying traffic inside the workload's netns (inbound on `:15008`, outbound on `:15001`).

### 2. WDS — Register the workload globally

Run on the xds-aggregator:

```bash
zds-client send --control-socket /tmp/control.sock \
  'wds-add <uid> <name> <namespace> <sa> <ip> HBONE <node_name>'
```

> **Important:** Use `HBONE` as the protocol to enable mTLS encryption via HBONE tunneling (port 15008). Using `TCP` results in plaintext passthrough with no encryption.

This registers the workload's identity and IP in the global workload directory. The aggregator relays it via XDS to all per-node zds-servers, so every ztunnel in every cluster knows about the workload.

### 3. SPIRE — Create a registration entry

For Kubernetes workloads, use `k8s:ns` and `k8s:sa` selectors with the SPIRE agent as parent:

```bash
kubectl exec -n spire spire-server-0 -- /opt/spire/bin/spire-server entry create \
  -spiffeID spiffe://<trust-domain>/ns/<namespace>/sa/<sa> \
  -parentID spiffe://<trust-domain>/agent \
  -selector k8s:ns:<namespace> -selector k8s:sa:<sa>
```

For non-Kubernetes workloads (e.g., simulated with `simulate-workload.sh`), use `unix:pid`:

```bash
spire-server entry create \
  -spiffeID spiffe://<trust-domain>/ns/<namespace>/sa/<sa> \
  -parentID spiffe://<trust-domain>/spire/agent/<attestor>/<node-id> \
  -selector unix:pid:<pid>
```

This allows the SPIRE agent to issue an X.509 SVID for the workload, which ztunnel uses for mTLS.

> **Note:** SPIRE >= 1.10.0 is required for PID-based delegate attestation (used by ztunnel's `spire-api` crate). Earlier versions ignore the `pid` field in `SubscribeToX509SVIDsRequest`.

## Testing Connectivity

From inside the workload namespace:

```bash
# Ping the bridge (root namespace)
ip netns exec simwl-agent-a ping 10.200.0.1

# Ping another workload
ip netns exec simwl-agent-a ping 10.200.0.3

# Run a command inside the namespace
ip netns exec simwl-agent-a curl http://10.200.0.3:8080
```

## Multiple Workloads

The script supports multiple concurrent workloads. Each gets a unique IP auto-assigned from the `10.200.0.0/24` subnet. The bridge is created once and shared.

```bash
./scripts/simulate-workload.sh agent-a cluster-a default /tmp/instances  # gets 10.200.0.2
./scripts/simulate-workload.sh agent-b cluster-b default /tmp/instances  # gets 10.200.0.3
./scripts/simulate-workload.sh agent-c cluster-a myapp  /tmp/instances   # gets 10.200.0.4
```

Cleanup is per-workload. The bridge is automatically removed when the last workload is cleaned up.
