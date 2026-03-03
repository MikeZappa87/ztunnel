# ZDS Tools

This directory contains the tooling for testing ztunnel without istiod. It provides a standalone ZDS/XDS/WDS server, a command-line client, and iptables redirect scripts — everything needed to enroll workloads into the mesh and establish mTLS between them.

## Components

| Component | Description |
|-----------|-------------|
| `zds-server` | Combined ZDS + XDS + WDS server with upstream XDS relay and iptables management |
| `zds-client` | CLI tool for sending ZDS/WDS commands to the server |
| `ztunnel-redirect-workload.sh` | Install/remove iptables redirect rules in a workload's network namespace |
| `Dockerfile` | Ubuntu 24.04-based image packaging all tools |
| `deploy.yaml` | DaemonSet deployment for per-node zds-server + standalone client pod |
| `multi-cluster-poc.yaml` | Multi-cluster test infrastructure with aggregator, test namespaces, and sample pods |

## Architecture

```
                     ┌───────────────────────┐
                     │    XDS Aggregator     │
                     │   (Deployment)        │
                     │   TCP port 15010      │
                     │                       │
                     │  Holds global view of │
                     │  all workloads (WDS)  │
                     └───────────┬───────────┘
                                 │ gRPC (upstream XDS)
                  ┌──────────────┼──────────────┐
                  │              │              │
         ┌────────▼──────┐ ┌────▼────────┐ ┌───▼─────────┐
         │  zds-server   │ │ zds-server  │ │ zds-server  │
         │  (DaemonSet)  │ │ (DaemonSet) │ │ (DaemonSet) │
         │  Node 1       │ │  Node 2     │ │  Node 3     │
         └──┬─────┬──────┘ └──┬────┬─────┘ └──┬────┬─────┘
            │     │           │    │           │    │
        ZDS UDS  XDS UDS  ZDS UDS XDS UDS  ZDS UDS XDS UDS
            │     │           │    │           │    │
         ┌──▼─────▼──┐   ┌───▼────▼──┐   ┌───▼────▼──┐
         │  ztunnel   │   │  ztunnel  │   │  ztunnel  │
         └────────────┘   └───────────┘   └───────────┘
```

### Data Flow

1. **WDS registration**: Workload identity/IP is registered on the aggregator via `wds-add`
2. **XDS relay**: Per-node zds-servers subscribe to the aggregator and pull all remote workloads
3. **Local merge**: Each zds-server merges remote workloads with locally ZDS-enrolled pods
4. **XDS push**: Combined workload set is pushed to the local ztunnel via Unix domain socket
5. **iptables setup**: On ZDS `add`, ztunnel-redirect rules are automatically installed in the workload's netns
6. **mTLS**: With HBONE protocol and SPIRE certificates, traffic is encrypted via HBONE tunneling (port 15008)

## Building

From the workspace root:

```bash
# Build the binaries (ARM64 example)
export CARGO_TARGET_DIR=/tmp/ztunnel-build
cargo build --bin zds-server --bin zds-client

# Copy binaries to the docker context
cp $CARGO_TARGET_DIR/debug/zds-server docker/zds-tools/zds-server
cp $CARGO_TARGET_DIR/debug/zds-client docker/zds-tools/zds-client

# Build the Docker image and load into Kind
docker build -t zds-tools:local docker/zds-tools/
kind load docker-image zds-tools:local --name ztunnel-test
```

## Deployment

### 1. Deploy the DaemonSet and client

```bash
kubectl apply -f docker/zds-tools/deploy.yaml
```

This creates:
- `zds-tools` namespace
- `zds-server` DaemonSet (one pod per node, sharing `/var/run/ztunnel` with ztunnel)
- `zds-client` pod for running administrative commands

### 2. Deploy the multi-cluster POC (optional)

```bash
kubectl apply -f docker/zds-tools/multi-cluster-poc.yaml
```

This creates:
- `xds-aggregator` Deployment + Service (central workload directory)
- `cluster-a` and `cluster-b` namespaces with sample pods (web-a, web-b, curl-a, curl-b)

## Usage

### Enrolling a Workload

Three steps are needed to fully enroll a Kubernetes pod:

#### Step 1: ZDS — Bind ztunnel to the workload's network namespace

Find the pod's network namespace:
```bash
NODE_POD=$(kubectl -n zds-tools get pods -l app=zds-server \
  --field-selector spec.nodeName=<node> -o name | head -1)

# Get pod details
POD_UID=$(kubectl get pod <pod-name> -n <namespace> -o jsonpath='{.metadata.uid}')
POD_IP=$(kubectl get pod <pod-name> -n <namespace> -o jsonpath='{.status.podIP}')

# Find the network namespace by IP (CNI netns names are random UUIDs)
NODE=<docker-node-name>  # e.g., ztunnel-test-worker
NETNS=$(docker exec $NODE sh -c '
  for ns in /var/run/netns/cni-*; do
    ip=$(nsenter --net=$ns ip -4 addr show eth0 2>/dev/null | grep -o "inet [0-9.]*" | cut -d" " -f2)
    [ "$ip" = "'"$POD_IP"'" ] && basename $ns && break
  done')
```

Send the ZDS add command:
```bash
kubectl exec -n zds-tools $NODE_POD -- \
  zds-client send --control-socket /var/run/ztunnel/control.sock \
  add $POD_UID <name> <namespace> <sa> /run/netns/$NETNS
```

This tells ztunnel to proxy traffic in the workload's netns and automatically installs iptables redirect rules.

#### Step 2: WDS — Register the workload globally

```bash
kubectl exec -n zds-tools deploy/xds-aggregator -- \
  zds-client send --control-socket /tmp/control.sock \
  wds-add $POD_UID <name> <namespace> <sa> $POD_IP HBONE <node>
```

> **Important:** Use `HBONE` as the protocol to enable mTLS. Using `TCP` results in plaintext passthrough.

#### Step 3: SPIRE — Create a registration entry

See [docker/spire/README.md](../spire/README.md) for SPIRE registration entry commands.

### Removing a Workload

```bash
# Remove from ZDS (also removes iptables rules)
kubectl exec -n zds-tools $NODE_POD -- \
  zds-client send --control-socket /var/run/ztunnel/control.sock \
  del $POD_UID

# Remove from WDS
kubectl exec -n zds-tools deploy/xds-aggregator -- \
  zds-client send --control-socket /tmp/control.sock \
  wds-del $POD_UID
```

## iptables Redirect Rules

The `ztunnel-redirect-workload.sh` script manages traffic interception rules inside workload network namespaces. It is called automatically by `zds-server` on `add`/`del` commands.

### What It Redirects

| Traffic | Destination | Rule |
|---------|-------------|------|
| Outbound TCP | ztunnel port 15001 | All non-ztunnel TCP redirected |
| Outbound DNS (UDP 53) | ztunnel port 15053 | DNS interception |
| Outbound DNS (TCP 53) | ztunnel port 15053 | DNS interception |
| Inbound TCP (non-15008) | ztunnel port 15006 | Inbound passthrough |
| Inbound TLS (15008) | No redirect | HBONE traffic goes directly to ztunnel |

### Marks

| Mark | Purpose |
|------|---------|
| `0x539/0xfff` | Set by ztunnel on its own traffic (excluded from redirect) |
| `0x111/0xfff` | CONNMARK for original source IP preservation |

### Manual Usage

```bash
# Install rules in a network namespace
ztunnel-redirect-workload.sh install /run/netns/<netns-name>
ztunnel-redirect-workload.sh install /proc/<pid>/ns/net

# Remove rules
ztunnel-redirect-workload.sh remove /run/netns/<netns-name>
```

The script is idempotent — reinstalling in an already-configured namespace is a no-op.

## DaemonSet Configuration

The zds-server DaemonSet requires:

| Capability | Reason |
|------------|--------|
| `NET_ADMIN` | Installing iptables rules via `nsenter` |
| `SYS_ADMIN` | Entering workload network namespaces |

Volume mounts:

| Mount | HostPath | Purpose |
|-------|----------|---------|
| `/var/run/ztunnel` | `/var/run/ztunnel` | ZDS/XDS Unix sockets shared with ztunnel |
| `/run/netns` | `/run/netns` | CNI-created network namespaces |

## Troubleshooting

### Stale ZDS Connections

If ztunnel restarts, the old ZDS connection becomes stale. The zds-server automatically uses the newest connection and cleans up stale ones on send failure.

### Plaintext Traffic

If traffic between enrolled pods is not encrypted, verify:
1. WDS entries use `HBONE` protocol (not `TCP`)
2. SPIRE registration entries exist for the workload identities
3. SPIRE version is >= 1.10.0

Check ztunnel access logs for `dst.addr=...:15008` (HBONE) vs direct IP (plaintext).

### iptables Rules Not Visible

The rules use the `nft` backend. Use `iptables-nft` (not `iptables-legacy`) to inspect:

```bash
nsenter --net=/run/netns/<netns> iptables-nft -t nat -L -n -v
nsenter --net=/run/netns/<netns> iptables-nft -t mangle -L -n -v
```
