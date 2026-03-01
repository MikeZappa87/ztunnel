# SPIRE Deployment for Ztunnel

This directory contains a Kubernetes manifest that deploys [SPIRE](https://spiffe.io/docs/latest/spire-about/) as the Certificate Authority for ztunnel, replacing Istio's built-in CA (istiod). SPIRE issues SPIFFE X.509 SVIDs that ztunnel uses for workload-to-workload mTLS.

## Architecture

```
                    ┌──────────────────┐
                    │  SPIRE Server    │
                    │  (StatefulSet)   │
                    │  port 8081       │
                    └────────┬─────────┘
                             │ gRPC
              ┌──────────────┼──────────────┐
              │              │              │
     ┌────────▼──────┐ ┌────▼────────┐ ┌───▼─────────┐
     │  SPIRE Agent  │ │ SPIRE Agent │ │ SPIRE Agent │
     │  (DaemonSet)  │ │ (DaemonSet) │ │ (DaemonSet) │
     │  Node 1       │ │  Node 2     │ │  Node 3     │
     └────────┬──────┘ └──────┬──────┘ └──────┬──────┘
              │               │               │
     Workload API      Workload API    Workload API
     (Unix socket)     (Unix socket)   (Unix socket)
              │               │               │
     ┌────────▼──────┐ ┌──────▼──────┐ ┌──────▼──────┐
     │   ztunnel     │ │  ztunnel    │ │  ztunnel    │
     └───────────────┘ └─────────────┘ └─────────────┘
```

## Components

| Component | Kind | Namespace | Description |
|-----------|------|-----------|-------------|
| spire-server | StatefulSet | spire | Central certificate authority, stores registration entries |
| spire-agent | DaemonSet | spire | Per-node agent, serves Workload API to ztunnel |
| spire-bootstrap | Secret | spire | Self-signed P-256 bootstrap CA (for testing only) |

## Configuration

### Trust Domain

The trust domain is `cluster.local`, matching the SPIFFE ID format ztunnel expects:

```
spiffe://cluster.local/ns/<namespace>/sa/<service_account>
```

### Authorized Delegates

The SPIRE agent is configured with `authorized_delegates` to allow ztunnel to request certificates on behalf of workloads using PID-based delegation:

```hcl
authorized_delegates = ["spiffe://cluster.local/ns/istio-system/sa/ztunnel"]
```

This is required because ztunnel calls `SubscribeToX509SVIDsRequest` with a workload's PID, and the SPIRE agent needs to know ztunnel is authorized to make delegated requests.

### SPIRE Version Requirement

**SPIRE >= 1.10.0 is required.** PID-based delegation (`SubscribeToX509SVIDsRequest` with the `pid` field) was added in SPIRE 1.10.0. Earlier versions (e.g., 1.9.0) silently ignore the `pid` field and only attest the caller (ztunnel) instead of the target workload.

The current deploy.yaml uses **SPIRE 1.10.4**.

### Node Attestation

Uses `k8s_psat` (Projected Service Account Token) attestation:
- Server validates tokens from the `ztunnel-test` cluster
- Agent uses the `spire-agent` service account in the `spire` namespace

## Deployment

```bash
kubectl apply -f docker/spire/deploy.yaml
```

Wait for all pods to be ready:

```bash
kubectl -n spire rollout status statefulset/spire-server
kubectl -n spire rollout status daemonset/spire-agent
```

## Post-Deployment: Registration Entries

After deploying SPIRE, you must create registration entries for each identity that needs certificates. The server uses `emptyDir` storage, so **entries are lost on restart** and must be recreated.

### 1. Agent Entry

An agent entry should already exist from PSAT attestation. Verify:

```bash
kubectl exec -n spire spire-server-0 -- /opt/spire/bin/spire-server entry show
```

### 2. Ztunnel Entry

Create an admin entry for ztunnel so it can use delegated attestation:

```bash
kubectl exec -n spire spire-server-0 -- /opt/spire/bin/spire-server entry create \
  -spiffeID spiffe://cluster.local/ns/istio-system/sa/ztunnel \
  -parentID spiffe://cluster.local/agent \
  -selector k8s:ns:istio-system -selector k8s:sa:ztunnel \
  -admin
```

The `-admin` flag is required so ztunnel can perform delegated identity requests.

### 3. Workload Entries

Create entries for each namespace/service-account pair that workloads use:

```bash
# For workloads in cluster-a namespace
kubectl exec -n spire spire-server-0 -- /opt/spire/bin/spire-server entry create \
  -spiffeID spiffe://cluster.local/ns/cluster-a/sa/default \
  -parentID spiffe://cluster.local/agent \
  -selector k8s:ns:cluster-a -selector k8s:sa:default

# For workloads in cluster-b namespace
kubectl exec -n spire spire-server-0 -- /opt/spire/bin/spire-server entry create \
  -spiffeID spiffe://cluster.local/ns/cluster-b/sa/default \
  -parentID spiffe://cluster.local/agent \
  -selector k8s:ns:cluster-b -selector k8s:sa:default
```

## Customization

### Changing the Trust Domain

Update `trust_domain` in both `spire-server` and `spire-agent` ConfigMaps. The trust domain must match what ztunnel expects (configured via `TRUST_DOMAIN` env var, defaults to `cluster.local`).

### Changing the Cluster Name

Update the cluster name in:
1. Server ConfigMap: `clusters = { "<name>" = { ... } }`
2. Agent ConfigMap: `cluster = "<name>"`

### Production Considerations

This deployment is designed for **testing and development**:
- Uses a self-signed bootstrap CA (replace with a proper root CA for production)
- Server data is stored in `emptyDir` (lost on restart; use persistent storage for production)
- Agent runs in `privileged` mode (required for PID attestation)
- `insecure_bootstrap = true` on the agent (use proper trust bundle distribution for production)
