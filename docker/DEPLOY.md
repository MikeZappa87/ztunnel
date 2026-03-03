# Deploying ztunnel with SPIRE + zds-server

This guide covers deploying ztunnel with SPIRE identity (replacing istiod CA) and zds-server (replacing istiod XDS) on an AKS cluster.

## Architecture

```
┌─────────────────────────────────────────────────┐
│                  AKS Cluster                    │
│                                                 │
│  ┌──────────────┐       ┌────────────────────┐  │
│  │ SPIRE Server │◄──────│   SPIRE Agent      │  │
│  │ (StatefulSet) │       │   (DaemonSet)      │  │
│  └──────────────┘       └────────┬───────────┘  │
│                                  │ admin.sock   │
│  ┌──────────────┐       ┌────────▼───────────┐  │
│  │    XDS       │◄──────│   zds-server       │  │
│  │  Aggregator  │ xds   │   (DaemonSet)      │  │
│  │ (Deployment) │       └────────┬───────────┘  │
│  └──────────────┘       ztunnel.sock │ xds.sock │
│                          ┌───────▼───────────┐  │
│                          │    ztunnel        │  │
│                          │   (DaemonSet)     │  │
│                          └───────────────────┘  │
└─────────────────────────────────────────────────┘
```

- **SPIRE** provides mTLS certificates (SPIFFE SVIDs) to ztunnel
- **zds-server** provides workload discovery (XDS) and CNI enrollment (ZDS) to ztunnel
- **XDS Aggregator** is a central workload directory that per-node zds-servers relay from
- **ztunnel** is the ambient mesh data plane proxy

## Prerequisites

- AKS cluster with `containerd` runtime
- Images pushed to your ACR:
  - `<acr>.azurecr.io/<repo>/ztunnel:vx100-dev`
  - `<acr>.azurecr.io/<repo>/xds:vx100-dev`
  - `spire-agent:latest` (custom build with admin API) — push to ACR or use official image
- `kubectl` configured for your cluster

## Files

| File | Contents |
|------|----------|
| `spire/deploy.yaml` | SPIRE server (StatefulSet), agent (DaemonSet), RBAC, bootstrap CA |
| `zds-tools/deploy.yaml` | zds-server DaemonSet, zds-client pod, RBAC |
| `zds-tools/multi-cluster-poc.yaml` | XDS aggregator Deployment + Service, test workload namespaces/pods |
| `ztunnel-daemonset.yaml` | ztunnel DaemonSet + ServiceAccount |

## Pre-deploy configuration

### 1. Update cluster name

In `spire/deploy.yaml`, replace `ztunnel-test` with your AKS cluster name in **two** places:

- SPIRE Server ConfigMap → `NodeAttestor "k8s_psat"` → `clusters` key
- SPIRE Agent ConfigMap → `NodeAttestor "k8s_psat"` → `cluster` value

### 2. Update image references

| File | Change |
|------|--------|
| `spire/deploy.yaml` | `image: spire-agent:latest` → your ACR image, set `imagePullPolicy: IfNotPresent` |
| `zds-tools/deploy.yaml` | `image: zds-tools:local` → `<acr>.azurecr.io/<repo>/xds:vx100-dev`, set `imagePullPolicy: IfNotPresent` |
| `zds-tools/multi-cluster-poc.yaml` | `image: zds-tools:local` → `<acr>.azurecr.io/<repo>/xds:vx100-dev`, set `imagePullPolicy: IfNotPresent` |
| `ztunnel-daemonset.yaml` | `image: ztunnel:v4fix` → `<acr>.azurecr.io/<repo>/ztunnel:vx100-dev`, set `imagePullPolicy: IfNotPresent` |

### 3. Verify containerd socket path

AKS nodes typically use `/run/containerd/containerd.sock`. Verify this matches the `hostPath` in `ztunnel-daemonset.yaml`.

## Deployment order

### Step 1: SPIRE

SPIRE must be deployed first — everything depends on it for certificates.

```bash
kubectl apply -f docker/spire/deploy.yaml

# Wait for SPIRE server
kubectl wait -n spire pod/spire-server-0 --for=condition=Ready --timeout=120s

# Wait for SPIRE agents (one per node)
kubectl wait -n spire -l app=spire-agent --for=condition=Ready --timeout=120s
```

#### Option A: k8s_psat attestation (recommended)

If agents attest via `k8s_psat` (projected service account token), create a node entry:

```bash
kubectl exec -n spire spire-server-0 -- /opt/spire/bin/spire-server entry create \
  -spiffeID spiffe://cluster.local/agent \
  -parentID spiffe://cluster.local/spire/server \
  -selector k8s_psat:cluster:<your-cluster-name> \
  -node
```

> **Finding the cluster name:** The cluster name in the selector must match the `cluster` value in the SPIRE server's `NodeAttestor "k8s_psat"` config. To verify, check the agent list after agents start:
> ```bash
> kubectl exec -n spire spire-server-0 -- /opt/spire/bin/spire-server agent list
> ```
> The agent's SPIFFE ID will contain the cluster name: `spiffe://cluster.local/spire/agent/k8s_psat/<cluster-name>/<uuid>`

#### Option B: Join token attestation

If `k8s_psat` isn't available, generate a one-time join token:

```bash
# Generate a token (valid for 1 hour)
kubectl exec -n spire spire-server-0 -- /opt/spire/bin/spire-server token generate \
  -spiffeID spiffe://cluster.local/agent \
  -ttl 36000
```

This returns a token string. Pass it to the agent via its config:

```hcl
# In the SPIRE agent ConfigMap, under plugins:
NodeAttestor "join_token" {
    plugin_data {}
}
```

And set the token as an environment variable or mount it:

```yaml
env:
  - name: SPIRE_JOIN_TOKEN
    value: "<token-from-above>"
args:
  - "-joinToken"
  - "$(SPIRE_JOIN_TOKEN)"
```

> **Note:** Join token agents get a unique SPIFFE ID like `spiffe://cluster.local/spire/agent/join_token/<token-uuid>`. You must use this exact ID as the `parentID` for workload entries (not the alias `spiffe://cluster.local/agent`). Join token agents cannot re-attest — if the agent restarts, you need a new token and new entries.

#### Understanding parentID

Workload entries need a `parentID` that resolves to the SPIRE agent. Two approaches:

1. **Node alias** (stable, survives agent restarts with `k8s_psat`): Use `spiffe://cluster.local/agent` as parentID, requires the `-node` flag on the agent entry.

2. **Direct agent SPIFFE ID** (always works, but changes if agent re-attests with new UUID):
   ```bash
   # Get the agent's actual SPIFFE ID
   kubectl exec -n spire spire-server-0 -- /opt/spire/bin/spire-server agent list
   # Use the full ID as parentID, e.g.:
   # spiffe://cluster.local/spire/agent/k8s_psat/fabricControlPlane/c7c90fc6-...
   ```

If node alias doesn't work (entries show "no identity issued"), fall back to the direct agent SPIFFE ID.

#### Create ztunnel's identity entry

> **Important:** The selectors must match ztunnel's **actual** namespace and service account, not the SPIFFE ID namespace. If ztunnel runs in `agentfabric-system` with SA `ztunnel`, use those values.

```bash
kubectl exec -n spire spire-server-0 -- /opt/spire/bin/spire-server entry create \
  -spiffeID spiffe://cluster.local/ns/istio-system/sa/ztunnel \
  -parentID <agent-spiffe-id-or-alias> \
  -selector k8s:ns:<ztunnel-namespace> \
  -selector k8s:sa:<ztunnel-service-account> \
  -admin \
  -x509SVIDTTL 300
```

The `-admin` flag is **required** — it allows ztunnel to use the Delegated Identity API to fetch certs on behalf of workloads.

#### Create workload entries

Create entries for each workload namespace/SA pair that ztunnel will manage:

```bash
kubectl exec -n spire spire-server-0 -- /opt/spire/bin/spire-server entry create \
  -spiffeID spiffe://cluster.local/ns/<namespace>/sa/<service-account> \
  -parentID <agent-spiffe-id-or-alias> \
  -selector k8s:ns:<namespace> \
  -selector k8s:sa:<service-account> \
  -x509SVIDTTL 300
```

#### Verify entries

```bash
# List all entries
kubectl exec -n spire spire-server-0 -- /opt/spire/bin/spire-server entry show

# Check a specific entry
kubectl exec -n spire spire-server-0 -- /opt/spire/bin/spire-server entry show \
  -spiffeID spiffe://cluster.local/ns/default/sa/default
```

### Step 2: XDS Aggregator

The central workload directory. Must be up before zds-server starts (zds-server connects to it via `--upstream-xds`).

```bash
kubectl apply -f docker/zds-tools/multi-cluster-poc.yaml

kubectl wait -n zds-tools deploy/xds-aggregator --for=condition=Available --timeout=60s
```

### Step 3: zds-server DaemonSet

Runs on every node. Provides ZDS (CNI protocol) and XDS (workload discovery) to ztunnel via UDS.

```bash
kubectl apply -f docker/zds-tools/deploy.yaml

kubectl wait -n zds-tools -l app=zds-server --for=condition=Ready --timeout=60s
```

### Step 4: ztunnel DaemonSet

The ambient mesh proxy. Connects to zds-server for ZDS + XDS, and to SPIRE agent for certificates.

```bash
kubectl apply -f docker/ztunnel-daemonset.yaml

kubectl wait -n istio-system -l app=ztunnel --for=condition=Ready --timeout=120s
```

### Step 5: Enroll workloads

For each workload pod, you need to send two commands to the zds-server on the **same node** as the pod:

1. **ZDS add** — registers the pod's network namespace with ztunnel (enables traffic interception)
2. **WDS add** — registers the pod in the XDS workload directory (enables discovery)

```bash
# Find the zds-server pod on the same node as your workload
ZDS_POD=$(kubectl get pods -n zds-tools -l app=zds-server \
  --field-selector spec.nodeName=<node-name> -o jsonpath='{.items[0].metadata.name}')

# Get workload info
UID=$(kubectl get pod -n <ns> <pod-name> -o jsonpath='{.metadata.uid}')
IP=$(kubectl get pod -n <ns> <pod-name> -o jsonpath='{.status.podIP}')
NODE=$(kubectl get pod -n <ns> <pod-name> -o jsonpath='{.spec.nodeName}')

# Get network namespace path (requires crictl on the node)
# For AKS, exec into the node or use: 
NETNS=$(docker exec <node> crictl inspectp <sandbox-id> | jq -r '.info.runtimeSpec.linux.namespaces[] | select(.type=="network") | .path')

# ZDS add (CNI enrollment — tells ztunnel to intercept this pod's traffic)
kubectl exec -n zds-tools $ZDS_POD -- zds-client send \
  --control-socket /var/run/ztunnel/control.sock \
  add $UID <pod-name> <namespace> <service-account> $NETNS

# WDS add (workload discovery — makes pod visible via XDS)
kubectl exec -n zds-tools $ZDS_POD -- zds-client send \
  --control-socket /var/run/ztunnel/control.sock \
  wds-add $UID <pod-name> <namespace> <service-account> $IP HBONE $NODE
```

## Verification

### Check SPIRE is issuing certificates
```bash
kubectl logs -n istio-system -l app=ztunnel --tail=20 | grep "cert fetch OK"
```
You should see lines like:
```
identity::manager  worker: cert fetch OK — scheduling refresh  id=spiffe://cluster.local/ns/<ns>/sa/<sa> refresh_in_secs=1800
```

### Check mTLS connectivity
```bash
kubectl exec -n <src-ns> <src-pod> -- curl -s -o /dev/null -w '%{http_code}' http://<dst-pod-ip>
```
Should return `200`. Check ztunnel logs for:
```
access  connection complete  src.identity="spiffe://..." dst.identity="spiffe://..." direction="outbound"
```

### Check certificate rotation (heartbeat)
```bash
kubectl logs -n istio-system -l app=ztunnel --tail=5 | grep heartbeat
```
You should see periodic heartbeats with a countdown timer:
```
identity::manager  worker heartbeat  pending_len=1 fetches_len=0 next_timer=Some("+600s")
```

## Key environment variables (ztunnel)

| Variable | Value | Purpose |
|----------|-------|---------|
| `CA_ADDRESS` | *(empty)* | Disables istiod CA — uses SPIRE instead |
| `XDS_ADDRESS` | `unix:///var/run/ztunnel/xds.sock` | XDS via UDS from zds-server |
| `SPIRE_ENABLED` | `true` | Enables SPIRE certificate fetching |
| `SPIRE_ADMIN_ENDPOINT_SOCKET` | `unix:///run/spire/admin/admin.sock` | SPIRE agent admin API socket |
| `INPOD_ENABLED` | `true` | Enables in-pod traffic interception |
| `RUST_LOG` | `info` | Log level |

## Troubleshooting

### ztunnel not getting certificates
- Check SPIRE agent is running: `kubectl get pods -n spire -l app=spire-agent`
- Check SPIRE entries exist: `kubectl exec -n spire spire-server-0 -- /opt/spire/bin/spire-server entry show`
- Check ztunnel logs for SPIRE errors: `kubectl logs -n istio-system -l app=ztunnel | grep -i spire`

### "no identity issued" from SPIRE

This is the most common SPIRE error. Check these in order:

1. **Are agents attested?**
   ```bash
   kubectl exec -n spire spire-server-0 -- /opt/spire/bin/spire-server agent list
   ```
   If empty, the `k8s_psat` cluster name in entries doesn't match the server config.

2. **Does the agent entry selector match?**
   The agent entry selector (e.g., `k8s_psat:cluster:fabricControlPlane`) must match the cluster name the agent attested with. Check the agent's SPIFFE ID for the actual cluster name.

3. **Does the parentID resolve?**
   Workload entries use `parentID` to link to an agent. If using node alias (`spiffe://cluster.local/agent`), verify the node entry exists with `-node` flag. If it doesn't work, use the agent's full SPIFFE ID instead.

4. **Do selectors match the actual pod?**
   Entry selectors must match the pod's **real** namespace and service account — not the SPIFFE ID. Check agent logs for the actual selectors SPIRE sees:
   ```bash
   kubectl -n spire logs -l app=spire-agent --tail=30 | grep "no identity issued"
   ```
   The `delegate_selectors` field shows what SPIRE resolves for the workload.

5. **Is ztunnel's entry marked admin?**
   Ztunnel uses the Delegated Identity API, which requires the `-admin` flag on its entry.

6. **Is ztunnel connecting to the admin socket?**
   Ztunnel must connect to `/run/spire/admin/admin.sock` (not `/run/spire/sockets/agent.sock`). Set `SPIRE_ADMIN_ENDPOINT_SOCKET=unix:///run/spire/admin/admin.sock`.

### ztunnel not discovering workloads
- Check zds-server is running: `kubectl get pods -n zds-tools -l app=zds-server`
- Check XDS aggregator is running: `kubectl get pods -n zds-tools -l app=xds-aggregator`
- List registered workloads: `kubectl exec -n zds-tools <zds-server-pod> -- zds-client send --control-socket /var/run/ztunnel/control.sock wds-list`

### Connection refused on first request
- Normal — ztunnel takes a moment to fetch the first certificate after enrollment. Retry after a few seconds.

### SPIRE agent socket not found after restart
- If you restart the SPIRE agent DaemonSet, ztunnel may lose its socket connection. Restart ztunnel too:
  ```bash
  kubectl -n <ztunnel-namespace> rollout restart daemonset ztunnel
  ```
  Then re-enroll all workloads (ZDS add + WDS add).
