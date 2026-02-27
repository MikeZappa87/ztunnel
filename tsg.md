# Ztunnel Troubleshooting Guide

This guide provides comprehensive troubleshooting steps for ztunnel when using **Cilium as the control plane** instead of Istiod. When Cilium is configured with `encryption.type=ztunnel`, the Cilium agent acts as the xDS control plane for ztunnel, managing workload enrollment and traffic redirection. Certificate issuance is handled by SPIRE.

## Table of Contents

- [Overview](#overview)
- [Verifying Ztunnel is Working](#verifying-ztunnel-is-working)
- [Troubleshooting Scenarios](#troubleshooting-scenarios)
  - [Scenario 1: Ztunnel Pods Not Starting](#scenario-1-ztunnel-pods-not-starting)
  - [Scenario 2: Namespace Not Enrolled](#scenario-2-namespace-not-enrolled)
  - [Scenario 3: Traffic Not Encrypted](#scenario-3-traffic-not-encrypted)
  - [Scenario 4: iptables Rules Missing](#scenario-4-iptables-rules-missing)
  - [Scenario 5: Listening Sockets Issues](#scenario-5-listening-sockets-issues)
  - [Scenario 6: Certificate Issues](#scenario-6-certificate-issues)
  - [Scenario 7: Control Plane Connection Issues](#scenario-7-control-plane-connection-issues)
  - [Scenario 8: Endpoint Restore After Agent Restart](#scenario-8-endpoint-restore-after-agent-restart)
  - [Scenario 9: Cross-Namespace and Cross-Node Traffic Issues](#scenario-9-cross-namespace-and-cross-node-traffic-issues)
- [Diagnostic Commands Reference](#diagnostic-commands-reference)
- [Known Limitations](#known-limitations)
- [SPIRE Troubleshooting](#spire-troubleshooting)
- [Ztunnel Log Patterns Reference](#ztunnel-log-patterns-reference)
- [Ztunnel Admin Endpoints](#ztunnel-admin-endpoints)
- [Additional Resources](#additional-resources)

---

## Overview

### Architecture with Cilium Control Plane

When using Cilium as the control plane:

1. **Cilium Agent** provides the xDS server via Unix domain socket (`/var/run/cilium/xds.sock`) for ztunnel configuration
2. **ZDS Server** communicates with ztunnel via Unix domain socket (`/var/run/cilium/ztunnel.sock`)
3. **Namespace Enrollment** is controlled via the `io.cilium/mtls-enabled=true` label
4. **iptables Rules** are installed by Cilium in each enrolled pod's network namespace

### Key Ports and Sockets

| Port/Socket                        | Purpose                               | Network Namespace |
|------------------------------------|---------------------------------------|-------------------|
| 15001                              | Pod outbound traffic capture          | Pod               |
| 15006                              | Pod inbound plaintext traffic capture | Pod               |
| 15008                              | Pod inbound HBONE traffic capture     | Pod               |
| `/var/run/cilium/xds.sock`         | xDS control plane (Cilium CA)         | Node              |
| `/var/run/cilium/ztunnel.sock`     | ZDS workload enrollment               | Node              |
| 15021                              | Ztunnel health/readiness              | Node              |

---

## Verifying Ztunnel is Working

### Step 1: Check Ztunnel is Enabled in Cilium

```bash
kubectl -n kube-system describe cm cilium-config | grep enable-ztunnel
```

Expected output:
```
enable-ztunnel: "true"
```

### Step 2: Verify Ztunnel Pods are Running

```bash
kubectl get pods -n kube-system -l app=ztunnel-cilium
```

Expected: All ztunnel pods should be in `Running` state with all containers ready.

### Step 3: Check Encryption Status

```bash
kubectl exec -n kube-system ds/cilium -- cilium-dbg encrypt status
```

Expected output should show:
```
Encryption: ztunnel
```

### Step 4: Verify Namespace Enrollment

List all enrolled namespaces:
```bash
kubectl get namespaces -l io.cilium/mtls-enabled=true
```

Verify enrollment in Cilium's StateDB:
```bash
kubectl exec -n kube-system ds/cilium -- cilium-dbg statedb dump | jq '.["mtls-enrolled-namespaces"]'
```

### Step 5: Verify Traffic is Encrypted

To capture HBONE traffic, you need to use a pod with its own network namespace (not the Cilium agent, which runs in the host network namespace). You can either:

**Option A: Use an enrolled workload pod with tcpdump:**
```bash
# From an enrolled workload pod
kubectl exec -n <enrolled-namespace> <workload-pod> -- tcpdump -i eth0 port 15008
```

**Option B: Verify iptables redirection is working:**
```bash
# Capture traffic on loopback - you should see cleartext application traffic here
# This indicates iptables rules are correctly redirecting traffic to ztunnel
kubectl exec -n <enrolled-namespace> <workload-pod> -- tcpdump -i lo -n
```

**Option C: Use nsenter from the node to enter a pod's network namespace:**
```bash
# Get the container ID for a pod in an enrolled namespace
CONTAINER_ID=$(crictl ps --name <pod-name> -q | head -1)

# Get the PID from the container ID
POD_PID=$(crictl inspect $CONTAINER_ID | jq '.info.pid')

# From the node, enter the pod's network namespace and capture traffic
nsenter -t $POD_PID -n tcpdump -i eth0 port 15008
```

**Option C: Use a debug pod with host networking disabled:**
```bash
# Deploy a debug pod in an enrolled namespace
kubectl run tcpdump-debug -n <enrolled-namespace> --image=nicolaka/netshoot --rm -it -- tcpdump -i any port 15008
```

Encrypted traffic will show destination port 15008 (HBONE):
```
13:00:06.982499 IP 10.244.1.95.15008 > 10.244.2.3.33446: ...
```

> **Note:** The Cilium agent pod uses `hostNetwork: true`, so it shares the node's network namespace and won't see pod-level HBONE traffic correctly.

---

## Troubleshooting Scenarios

### Scenario 1: Ztunnel Pods Not Starting

#### Symptoms
- Ztunnel pods stuck in `Pending`, `CrashLoopBackOff`, or `Error` state

#### Diagnostic Steps

1. **Check pod events:**
   ```bash
   kubectl describe pod -n kube-system -l app=ztunnel-cilium
   ```

2. **Check ztunnel logs:**
   ```bash
   kubectl logs -n kube-system -l app=ztunnel-cilium --tail=100
   ```

3. **Verify secrets exist:**
   ```bash
   kubectl get secret -n kube-system ztunnel-bootstrap
   kubectl get secret -n kube-system ztunnel-ca
   ```

4. **Validate secret content:**
   ```bash
   kubectl get secret -n kube-system ztunnel-bootstrap -o jsonpath='{.data.bootstrap-root\.crt}' | base64 -d | openssl x509 -text -noout
   ```

#### Common Fixes
- Regenerate secrets using the provided script if certificates are expired or missing
- Ensure `encryption.ztunnel.secrets.bootstrapRootCert` is properly base64-encoded
- Check node resources (CPU/memory) if pods are pending

---

### Scenario 2: Namespace Not Enrolled

#### Symptoms
- Traffic from pods in a labeled namespace is not encrypted
- Pods not appearing in ztunnel workload list

#### Diagnostic Steps

1. **Verify namespace label:**
   ```bash
   kubectl get namespace <namespace> --show-labels | grep io.cilium/mtls-enabled
   ```

2. **Check Cilium agent logs for enrollment:**
   ```bash
   kubectl logs -n kube-system ds/cilium | grep -i "enroll"
   ```

3. **Verify endpoints are registered:**
   ```bash
   kubectl exec -n kube-system ds/cilium -- cilium-dbg endpoint list
   ```

4. **Check StateDB for enrolled namespaces:**
   ```bash
   kubectl exec -n kube-system ds/cilium -- cilium-dbg statedb dump | jq '.["mtls-enrolled-namespaces"]'
   ```

#### Common Fixes
```bash
# Apply the enrollment label
kubectl label namespace <namespace> io.cilium/mtls-enabled=true

# Force re-enrollment by removing and re-adding
kubectl label namespace <namespace> io.cilium/mtls-enabled-
kubectl label namespace <namespace> io.cilium/mtls-enabled=true
```

---

### Scenario 3: Traffic Not Encrypted

#### Symptoms
- Unencrypted traffic visible on the network
- No HBONE (port 15008) traffic between pods

#### Diagnostic Steps

1. **Verify both source and destination namespaces are enrolled:**
   ```bash
   kubectl get ns -l io.cilium/mtls-enabled=true
   ```

2. **Check if pods have network namespace paths:**
   ```bash
   kubectl exec -n kube-system ds/cilium -- cilium-dbg endpoint list -o json | jq '.[] | select(.status.networking.container-netns-path != "")'
   ```

3. **Verify iptables rules in pod (see [Scenario 4](#scenario-4-iptables-rules-missing))**

4. **Check ztunnel is receiving workload information:**
   ```bash
   # Use port-forward since ztunnel uses a distroless image without curl
   kubectl port-forward -n kube-system <ztunnel-pod> 15000:15000 &
   curl -s localhost:15000/config_dump | jq '.workloads'
   ```

5. **Capture traffic to verify:**
   ```bash
   # From the node where the pods are running
   tcpdump -i any port 15008
   ```

#### Common Fixes
- Ensure both communicating namespaces are enrolled
- Host-networked pods cannot be enrolled - check if pods use `hostNetwork: true`
- Verify ztunnel is healthy and receiving XDS updates

---

### Scenario 4: iptables Rules Missing

#### Symptoms
- Traffic not being redirected to ztunnel
- Pods in enrolled namespace behaving as if not enrolled

#### Diagnostic Steps

1. **Get the pod's PID (see [Getting Pod PID](#getting-pod-pid) for details):**
   ```bash
   CONTAINER_ID=$(crictl ps --name <pod-name> -q | head -1)
   POD_PID=$(crictl inspect $CONTAINER_ID | jq '.info.pid')
   ```

2. **Check iptables rules inside the pod's network namespace:**
   ```bash
   # From the node where the pod is running
   nsenter -t $POD_PID -n iptables -t nat -L -v -n
   nsenter -t $POD_PID -n iptables -t mangle -L -v -n
   ```

3. **Verify expected chains exist:**
   
   **NAT table (expected rules):**
   ```bash
   iptables -t nat -S CILIUM_PREROUTING
   iptables -t nat -S CILIUM_OUTPUT
   ```
   
   **Mangle table (expected rules):**
   ```bash
   iptables -t mangle -S CILIUM_PREROUTING
   iptables -t mangle -S CILIUM_OUTPUT
   ```

4. **Verify the expected iptables rules are present:**

   **Inbound (PREROUTING):**
   ```
   -A CILIUM_PREROUTING -m mark --mark 0x539/0xfff -j CONNMARK --set-xmark 0x111/0xfff
   -A CILIUM_PREROUTING ! -d 127.0.0.1/32 -p tcp ! --dport 15008 -m mark ! --mark 0x539/0xfff -j REDIRECT --to-ports 15006
   ```
   
   **Outbound (OUTPUT):**
   ```
   -A CILIUM_OUTPUT -m connmark --mark 0x111/0xfff -j CONNMARK --restore-mark
   -A CILIUM_OUTPUT -p tcp -m mark --mark 0x111/0xfff -j ACCEPT
   -A CILIUM_OUTPUT ! -d 127.0.0.1/32 -o lo -j ACCEPT
   -A CILIUM_OUTPUT ! -d 127.0.0.1/32 -p tcp -m mark ! --mark 0x539/0xfff -j REDIRECT --to-ports 15001
   ```

5. **Check for routing rules:**
   ```bash
   nsenter -t <pod-pid> -n ip rule list
   ```
   
   Expected output should include:
   ```
   32764:  from all fwmark 0x111/0xfff lookup 100
   ```

6. **Check loopback route:**
   ```bash
   nsenter -t <pod-pid> -n ip route show table 100
   ```
   
   Expected:
   ```
   local default dev lo scope host
   ```

#### Understanding the Traffic Flow

| Mark Value | Meaning |
|------------|---------|
| `0x539`    | Set by ztunnel on outbound traffic (already processed) |
| `0x111`    | TProxy mark for connection tracking |
| `0xfff`    | Mask for mark comparison |

**Inbound Traffic Flow:**
1. Packets arrive at PREROUTING
2. Packets with mark 0x539 get connmark set to 0x111
3. Non-localhost TCP traffic (except port 15008) without mark 0x539 is redirected to port 15006

**Outbound Traffic Flow:**
1. Connmarks are restored to packet marks
2. Traffic with mark 0x111 is accepted (already processed by ztunnel)
3. Loopback self-addressed traffic is allowed
4. All other TCP traffic without mark 0x539 is redirected to port 15001

#### Common Fixes

If rules are missing, the Cilium agent may have failed to inject them:

```bash
# Check Cilium agent logs for iptables errors
kubectl logs -n kube-system ds/cilium | grep -i "iptable"

# Force re-enrollment by restarting the pod or the namespace enrollment
kubectl delete pod <pod-name> -n <namespace>
```

#### Understanding iptables Rule Management

Cilium uses the `go-iptables` library to manage iptables rules. The implementation is **idempotent**, meaning:

- Rules are checked for existence before creation
- Duplicate chains are not created if they already exist
- Re-enrollment will not create duplicate rules

**Chain creation logic:**
1. Check if `CILIUM_PREROUTING` and `CILIUM_OUTPUT` chains exist in nat/mangle tables
2. If not, create them
3. Check if jump rules to these chains exist in PREROUTING/OUTPUT
4. If not, add them

**Rule cleanup on disenrollment:**
When a pod is disenrolled (namespace label removed or pod deleted), Cilium calls `DeleteInPodRules()` which:
1. Removes jump rules from PREROUTING and OUTPUT chains
2. Flushes CILIUM_PREROUTING and CILIUM_OUTPUT chains
3. Deletes the custom chains
4. Removes the routing rules and routes

If you see stale iptables rules after disenrollment:
```bash
# Manually verify rules are cleaned up
nsenter -t <pod-pid> -n iptables -t nat -L PREROUTING -v
nsenter -t <pod-pid> -n iptables -t mangle -L PREROUTING -v

# If stale rules remain, check for errors in Cilium logs
kubectl logs -n kube-system ds/cilium | grep -i "delete.*rule\|DeleteInPodRules"
```

---

### Scenario 5: Listening Sockets Issues

#### Symptoms
- Connection refused errors
- Ztunnel not accepting traffic

#### Diagnostic Steps

1. **Verify ztunnel is listening on expected ports (inside pod network namespace):**
   ```bash
   nsenter -t <pod-pid> -n ss -tlnp
   ```
   
   Expected listening sockets:
   ```
   State    Recv-Q   Send-Q     Local Address:Port      Peer Address:Port
   LISTEN   0        128              0.0.0.0:15001          0.0.0.0:*
   LISTEN   0        128              0.0.0.0:15006          0.0.0.0:*
   LISTEN   0        128              0.0.0.0:15008          0.0.0.0:*
   ```

2. **Check ztunnel health:**
   ```bash
   kubectl port-forward -n kube-system <ztunnel-pod> 15021:15021 &
   curl -s localhost:15021/healthz
   ```

3. **Verify ztunnel admin endpoint:**
   ```bash
   kubectl port-forward -n kube-system <ztunnel-pod> 15000:15000 &
   curl -s localhost:15000/
   ```

4. **Check for socket errors in ztunnel logs:**
   ```bash
   kubectl logs -n kube-system <ztunnel-pod> | grep -i "bind\|socket\|listen"
   ```

#### Common Fixes
- Ensure no other process is binding to ports 15001, 15006, or 15008
- Check if the ztunnel container has sufficient capabilities
- Restart the ztunnel pod if sockets are not properly initialized

---

### Scenario 6: Certificate Issues

#### Symptoms
- TLS handshake failures
- Certificate validation errors in logs
- `certificate verify failed` errors

#### Diagnostic Steps

1. **Check ztunnel certificate status:**
   ```bash
   kubectl port-forward -n kube-system <ztunnel-pod> 15000:15000 &
   curl -s localhost:15000/config_dump | jq '.certificates'
   ```

2. **Verify CA certificate validity:**
   ```bash
   kubectl get secret -n kube-system ztunnel-ca -o jsonpath='{.data.ca-root\.crt}' | base64 -d | openssl x509 -text -noout | grep -A2 "Validity"
   ```

3. **Check bootstrap certificate:**
   ```bash
   kubectl get secret -n kube-system ztunnel-bootstrap -o jsonpath='{.data.bootstrap-root\.crt}' | base64 -d | openssl x509 -text -noout | grep -A2 "Validity"
   ```

4. **Verify Cilium xDS socket exists:**
   ```bash
   kubectl exec -n kube-system ds/cilium -- ls -la /var/run/cilium/xds.sock
   ```

5. **Check for certificate signing errors:**
   ```bash
   kubectl logs -n kube-system ds/cilium | grep -i "certificate\|CSR\|signing"
   ```

#### Common Fixes
- Regenerate secrets if certificates are expired
- Ensure time synchronization across nodes (NTP)
- Verify the CA private key matches the CA certificate

---

### Scenario 7: Control Plane Connection Issues

#### Symptoms
- Ztunnel not receiving workload updates
- Stale configuration
- XDS connection errors

#### Diagnostic Steps

1. **Check ZDS socket exists:**
   ```bash
   kubectl exec -n kube-system ds/cilium -- ls -la /var/run/cilium/ztunnel.sock
   ```

2. **Verify Cilium xDS socket exists:**
   ```bash
   kubectl exec -n kube-system ds/cilium -- ls -la /var/run/cilium/xds.sock
   ```

3. **Check for xDS connection errors in ztunnel:**
   ```bash
   kubectl logs -n kube-system <ztunnel-pod> | grep -i "xds\|grpc\|connection"
   ```

4. **Check Cilium agent logs for ZDS errors:**
   ```bash
   kubectl logs -n kube-system ds/cilium | grep -i "zds\|ztunnel"
   ```

5. **Verify xDS socket permissions:**
   ```bash
   # Check the xDS socket is accessible
   kubectl exec -n kube-system ds/cilium -- stat /var/run/cilium/xds.sock
   ```

6. **Test xDS socket connectivity from ztunnel:**
   ```bash
   # Verify the xDS socket is mounted (check from Cilium agent since ztunnel is distroless)
   kubectl exec -n kube-system ds/cilium -- ls -la /var/run/cilium/xds.sock
   ```

#### Common Fixes
- Restart Cilium agent if xDS or ZDS sockets are missing
- Check if ztunnel and Cilium are using compatible versions
- Verify the `/var/run/cilium` directory is properly mounted in both Cilium and ztunnel pods
- Check socket file permissions allow ztunnel to connect

---

### Scenario 8: Endpoint Restore After Agent Restart

#### Symptoms
- After Cilium agent restart, pods lose connectivity temporarily
- Traffic is blackholed briefly after agent restart
- Pods that were previously enrolled show connectivity issues

#### Explanation

When the Cilium agent restarts, it needs to restore endpoint state from disk before ztunnel can receive the correct snapshot. If ztunnel receives a snapshot before endpoints are fully restored, it may have an incomplete view of workloads.

The Cilium agent waits for endpoint restoration before sending the first snapshot to ztunnel. This includes:
- Restoring container network namespace paths from disk
- Re-enrolling endpoints with ztunnel via ZDS
- Ensuring iptables rules are reinstalled in pod network namespaces

#### Diagnostic Steps

1. **Check for endpoint restore messages:**
   ```bash
   kubectl logs -n kube-system ds/cilium | grep -i "endpoint restore\|restoring endpoint"
   ```

2. **Verify all endpoints are restored:**
   ```bash
   kubectl exec -n kube-system ds/cilium -- cilium-dbg endpoint list
   ```

3. **Check if ztunnel received the snapshot:**
   ```bash
   kubectl logs -n kube-system <ztunnel-pod> | grep -i "snapshot\|workload update"
   ```

4. **Verify container netns paths are restored:**
   ```bash
   # Check endpoint state directory
   kubectl exec -n kube-system ds/cilium -- ls -la /var/run/cilium/state/
   ```

#### Common Fixes
- Wait for endpoint restoration to complete before testing connectivity
- If endpoints are not restoring, check CRI socket connectivity
- Verify `/var/run/cilium/state` is properly mounted and persisted

---

### Scenario 9: Cross-Namespace and Cross-Node Traffic Issues

#### Symptoms
- Traffic works within same namespace but fails across namespaces
- Traffic works on same node but fails across nodes
- Some pod-to-pod connections work while others fail

#### Traffic Matrix Reference

The following matrix shows expected behavior based on enrollment status:

| Source Namespace | Dest Namespace | Same Node | Cross Node | Expected Behavior |
|------------------|----------------|-----------|------------|-------------------|
| Enrolled         | Enrolled       | ✓         | ✓          | Full mTLS via HBONE |
| Enrolled         | Enrolled       | ✓         | -          | mTLS via HBONE |
| Enrolled         | Enrolled       | -         | ✓          | mTLS via HBONE |
| Enrolled         | Unenrolled     | ✓         | -          | Plaintext (no interception) |
| Enrolled         | Unenrolled     | -         | ✓          | Plaintext (no interception) |
| Unenrolled       | Enrolled       | ✓         | -          | Plaintext inbound |
| Unenrolled       | Enrolled       | -         | ✓          | Plaintext inbound |
| Unenrolled       | Unenrolled     | ✓         | ✓          | Plaintext (bypass ztunnel) |

#### Diagnostic Steps

1. **Verify both namespaces' enrollment status:**
   ```bash
   kubectl get ns <source-ns> <dest-ns> --show-labels | grep mtls-enabled
   ```

2. **Check if pods are on same or different nodes:**
   ```bash
   kubectl get pods -n <namespace> -o wide
   ```

3. **Verify ztunnel on both nodes has correct workload information:**
   ```bash
   # On source node's ztunnel (use port-forward since ztunnel is distroless)
   kubectl port-forward -n kube-system <ztunnel-pod-source-node> 15000:15000 &
   curl -s localhost:15000/config_dump | jq '.workloads'
   
   # On dest node's ztunnel
   kubectl port-forward -n kube-system <ztunnel-pod-dest-node> 15000:15000 &
   curl -s localhost:15000/config_dump | jq '.workloads'
   ```

4. **Check for HBONE connection establishment:**
   ```bash
   # Get ztunnel PID and use nsenter (ztunnel is distroless)
   CONTAINER_ID=$(crictl ps --name ztunnel -q | head -1)
   ZTUNNEL_PID=$(crictl inspect $CONTAINER_ID | jq '.info.pid')
   nsenter -t $ZTUNNEL_PID -n ss -tlnp | grep 15008
   ```

5. **Trace traffic path:**
   ```bash
   # Check iptables on source pod's netns
   kubectl exec -n kube-system ds/cilium -- nsenter -t <pid> -n iptables -t mangle -L -v
   
   # Check if traffic is reaching destination ztunnel
   kubectl logs -n kube-system <ztunnel-pod-dest-node> | grep -i "<dest-pod-ip>"
   ```

#### Common Fixes
- Ensure both source and destination namespaces are properly labeled
- Verify ztunnel pods are running on all relevant nodes
- Check that HBONE port (15008) is not blocked by NetworkPolicy or firewall
- Ensure Cilium CNI is correctly routing HBONE traffic between nodes

---

## Diagnostic Commands Reference

### Cilium Agent Commands

```bash
# Check encryption status
kubectl exec -n kube-system ds/cilium -- cilium-dbg encrypt status

# List all endpoints
kubectl exec -n kube-system ds/cilium -- cilium-dbg endpoint list

# Dump StateDB for enrolled namespaces
kubectl exec -n kube-system ds/cilium -- cilium-dbg statedb dump | jq '.["mtls-enrolled-namespaces"]'

# Check Cilium status
kubectl exec -n kube-system ds/cilium -- cilium-dbg status
```

### Ztunnel Commands

Ztunnel uses a distroless image without curl. Use `kubectl port-forward` to access the admin endpoints:

```bash
# Port-forward to ztunnel admin ports
kubectl port-forward -n kube-system <ztunnel-pod> 15000:15000 15020:15020 15021:15021 &

# Health check
curl -s localhost:15021/healthz

# Configuration dump
curl -s localhost:15000/config_dump

# Metrics
curl -s localhost:15020/metrics
```

### Getting Pod PID

Many diagnostic commands require the pod's PID to enter its network namespace. Use `crictl` on the node where the pod is running:

```bash
# Get the container ID for a pod
CONTAINER_ID=$(crictl ps --name <pod-name> -q | head -1)

# Get the PID from the container
POD_PID=$(crictl inspect $CONTAINER_ID | jq '.info.pid')

# Now use nsenter to access the pod's network namespace
nsenter -t $POD_PID -n <command>
```

**Helper script for common use:**
```bash
#!/bin/bash
# get-pod-pid.sh - Get PID for a pod's main container
# Usage: ./get-pod-pid.sh <namespace> <pod-name>

NAMESPACE=$1
POD_NAME=$2

# Get container ID from pod status
CONTAINER_ID=$(kubectl get pod -n $NAMESPACE $POD_NAME \
  -o jsonpath='{.status.containerStatuses[0].containerID}' | sed 's|containerd://||')

# Get PID using crictl
POD_PID=$(crictl inspect $CONTAINER_ID 2>/dev/null | jq -r '.info.pid')

if [ -z "$POD_PID" ] || [ "$POD_PID" == "null" ]; then
  echo "Could not find PID for pod $POD_NAME in namespace $NAMESPACE"
  exit 1
fi

echo $POD_PID
```

### Network Diagnostics

Once you have the pod PID, you can use nsenter to inspect the pod's network namespace:

```bash
# List iptables rules in a pod's network namespace
nsenter -t <pod-pid> -n iptables -t nat -L -v -n
nsenter -t <pod-pid> -n iptables -t mangle -L -v -n

# Check listening sockets
nsenter -t <pod-pid> -n ss -tlnp

# Check routing rules
nsenter -t <pod-pid> -n ip rule list
nsenter -t <pod-pid> -n ip route show table 100

# Capture HBONE traffic
tcpdump -i any port 15008
```

### Kubernetes Diagnostics

```bash
# Check ztunnel pods
kubectl get pods -n kube-system -l app=ztunnel-cilium -o wide

# Check ztunnel logs
kubectl logs -n kube-system -l app=ztunnel-cilium --tail=100

# Check Cilium agent logs
kubectl logs -n kube-system ds/cilium --tail=100

# Check enrolled namespaces
kubectl get ns -l io.cilium/mtls-enabled=true

# Describe ztunnel pod for events
kubectl describe pod -n kube-system -l app=ztunnel-cilium
```

---

## Known Limitations

1. **Namespace-level enrollment only**: Pod-level enrollment is not supported. You must label the entire namespace.

2. **TCP traffic only**: UDP and other protocols are not redirected to ztunnel for mTLS encryption.

3. **iptables required**: The integration requires iptables support in the kernel.

4. **Host-networked pods excluded**: Pods using `hostNetwork: true` cannot be enrolled.

5. **Cluster Mesh incompatibility**: Ztunnel is not compatible with Cilium Cluster Mesh. Attempting to enable both will result in a validation error.

6. **Network Policy interference**: Ztunnel encrypts traffic before it leaves the pod, meaning L4 network policies won't work except for rules targeting the HBONE port (15008).

7. **Endpoint restore timing**: After Cilium agent restart, there is a brief window where endpoints are being restored from disk. Traffic may be affected during this period until ztunnel receives the updated snapshot.

8. **Deferred endpoint queue**: When a namespace is labeled for enrollment, existing pods in that namespace enter a "deferred queue" until the reconciler processes them. New pods created after labeling are enrolled immediately.

9. **No graceful disenrollment**: When removing the `io.cilium/mtls-enabled` label from a namespace, existing connections may be disrupted as iptables rules are removed.

---

## SPIRE Troubleshooting

Ztunnel uses SPIRE (SPIFFE Runtime Environment) as the certificate authority.

### Symptoms of SPIRE Issues
- Certificate fetch failures in ztunnel logs
- "no identity issued" errors
- Timeout errors when connecting to SPIRE

### Diagnostic Steps

1. **Check SPIRE Agent is running:**
   ```bash
   kubectl get pods -n spire -l app=spire-agent
   ```

2. **Verify SPIRE Agent socket exists:**
   ```bash
   # Check from SPIRE agent pod (ztunnel is distroless)
   kubectl exec -n spire -l app=spire-agent -- ls -la /run/spire/sockets/admin.sock
   ```

3. **Check ztunnel is authorized as a delegate:**
   ```bash
   # Look for authorized_delegates in SPIRE Agent config
   kubectl get configmap -n spire spire-agent -o yaml | grep authorized_delegates
   ```

4. **Verify workload registration entries exist:**
   ```bash
   kubectl exec -n spire <spire-server-pod> -- \
     /opt/spire/bin/spire-server entry show
   ```

5. **Check SPIRE Agent logs for attestation errors:**
   ```bash
   kubectl logs -n spire -l app=spire-agent | grep -i "error\|denied\|attestation"
   ```

6. **Check ztunnel logs for SPIRE errors:**
   ```bash
   kubectl logs -n kube-system <ztunnel-pod> | grep -i "spire\|svid\|certificate"
   ```

### Common SPIRE Fixes
- Ensure ztunnel's service account SPIFFE ID is in `authorized_delegates`
- Verify the SPIRE admin socket is mounted in the ztunnel pod
- Check workload registration entries match the expected selectors
- Ensure SPIRE Agent has connectivity to SPIRE Server

### SPIRE Log Patterns (from ztunnel)

| Log Pattern | Level | Meaning |
|-------------|-------|---------|
| `Fetching PID for workload UID: <uid>` | INFO | Starting PID-based certificate fetch |
| `Failed to fetch certificate for PID <pid>` | ERROR | SPIRE certificate fetch failed |
| `PID mismatch for workload UID` | ERROR | PID changed during certificate fetch |
| `Failed to fetch PID for workload UID` | ERROR | Could not determine workload PID |
| `Timeout while waiting for SVID stream` | ERROR | SPIRE response timeout |
| `No SVIDs received in stream` | ERROR | SPIRE returned no certificates |
| `Error receiving SVID response` | WARN | SPIRE stream error, will retry |
| `Fetched bundle for trust domain` | DEBUG | Successfully fetched trust bundle |

---

## Ztunnel Log Patterns Reference

These are the actual log messages from the ztunnel source code that are useful for troubleshooting:

### Startup and Readiness

| Log Pattern | Level | Meaning |
|-------------|-------|---------|
| `version: <version>` | INFO | Ztunnel startup with version info |
| `running with config: <yaml>` | INFO | Full configuration dump at startup |
| `shared proxy mode - in-pod mode enabled` | INFO | InPod mode is active |
| `Task '<name>' complete, marking server ready` | INFO | All readiness tasks complete |
| `Task '<name>' complete, still awaiting <N> tasks` | INFO | Partial readiness, still waiting |

### ZDS/Control Plane Connection

| Log Pattern | Level | Meaning |
|-------------|-------|---------|
| `connecting to server: <path>` | DEBUG | Attempting to connect to ZDS socket |
| `failed to connect to the Istio CNI node agent over <path>` | WARN | ZDS connection failure, will retry |
| `handling new stream` | INFO | New ZDS connection established |
| `workload proxy manager is ready` | DEBUG | Successfully connected to ZDS |
| `workload proxy manager is NOT ready` | DEBUG | ZDS connection lost or not established |
| `node agent announcement failed, retrying in <duration>` | ERROR | Protocol handshake failure |
| `protocol mismatch error while processing stream, shutting down` | ERROR | Incompatible protocol version |
| `process stream ended with eof` | INFO | ZDS connection closed normally |

### Workload Management

| Log Pattern | Level | Meaning |
|-------------|-------|---------|
| `pod received, starting proxy` (with uid, name, namespace) | INFO | New workload enrollment |
| `pod keep received. will not delete it when snapshot is sent` | INFO | Workload retained during snapshot |
| `pod delete request, shutting down proxy` | INFO | Workload disenrollment |
| `received snapshot sent` | INFO | Snapshot synchronization complete |
| `retrying workload` (with uid) | INFO | Retrying failed workload proxy |
| `failed to start proxy` (with uid) | ERROR | Workload proxy startup failure |
| `scheduling retry` (with uids) | INFO | Pending workloads queued for retry |

### XDS Connection

| Log Pattern | Level | Meaning |
|-------------|-------|---------|
| `XDS client connection error, retrying in <duration>` | WARN | Connection failure, will backoff |
| `XDS client error, retrying` | WARN | XDS protocol error |
| `XDS client complete` | WARN | XDS stream completed |
| `on demand dropped event for <key>` | WARN | On-demand request dropped |

### Certificate Management

| Log Pattern | Level | Meaning |
|-------------|-------|---------|
| `couldn't prefetch: <error>` | INFO | Certificate prefetch failure |
| `couldn't clear identity: <error>` | INFO | Failed to clear cached identity |

### Drain and Shutdown

| Log Pattern | Level | Meaning |
|-------------|-------|---------|
| `drain requested` | INFO | Graceful shutdown initiated |
| `shutdown complete` | INFO | Component shutdown complete |
| `Shutdown completed gracefully` | INFO | Admin shutdown success |
| `drain duration expired with pending connections, forcefully shutting down` | WARN | Forced shutdown due to timeout |

### Useful Grep Commands

```bash
# Check for ZDS connection issues
kubectl logs -n kube-system <ztunnel-pod> | grep -i "failed to connect\|announcement failed\|protocol mismatch"

# Check workload enrollment
kubectl logs -n kube-system <ztunnel-pod> | grep -i "pod received\|pod delete\|snapshot sent"

# Check for errors
kubectl logs -n kube-system <ztunnel-pod> | grep -E "ERROR|error!"

# Check readiness state
kubectl logs -n kube-system <ztunnel-pod> | grep -i "ready\|awaiting"

# Check XDS connection
kubectl logs -n kube-system <ztunnel-pod> | grep -i "XDS client"

# Check proxy startup failures
kubectl logs -n kube-system <ztunnel-pod> | grep -i "failed to start proxy\|retrying workload"
```

---

## Ztunnel Admin Endpoints

Ztunnel exposes an admin API on port 15000:

| Endpoint | Description |
|----------|-------------|
| `/` | Dashboard with links to all endpoints |
| `/config_dump` | Full configuration dump (workloads, policies, certs) |
| `/logging` | Query or change logging levels |
| `/quitquitquit` | Graceful shutdown (POST) |
| `/debug/pprof/profile` | CPU profiling (if supported) |
| `/debug/pprof/heap` | Heap profiling (if jemalloc enabled) |

### Readiness Endpoint (port 15021)

| Endpoint | Description |
|----------|-------------|
| `/healthz/ready` | Returns 200 if ready, 500 with pending tasks if not |

### Metrics Endpoint (port 15020)

| Endpoint | Description |
|----------|-------------|
| `/metrics` | Prometheus metrics |
| `/stats/prometheus` | Prometheus metrics (alternate path) |

### Example Usage

Ztunnel uses a distroless image without curl. Use `kubectl port-forward` to access these endpoints:

```bash
# Port-forward to ztunnel admin ports
kubectl port-forward -n kube-system <ztunnel-pod> 15000:15000 15020:15020 15021:15021 &

# Get full config dump
curl -s localhost:15000/config_dump | jq

# Check readiness with pending tasks
curl -s localhost:15021/healthz/ready

# Get metrics
curl -s localhost:15020/metrics

# Change log level to debug
curl -s -X POST "localhost:15000/logging?level=debug"
```

---

## Additional Resources

### Cilium
- [Cilium Ztunnel Encryption Documentation](https://docs.cilium.io/en/stable/security/network/encryption-ztunnel/)
- [Cilium Helm Charts](https://github.com/cilium/cilium/tree/main/install/kubernetes/cilium)
- [Cilium GitHub Repository - ztunnel package](https://github.com/cilium/cilium/tree/main/pkg/ztunnel)

### Ztunnel
- [Ztunnel Architecture](./ARCHITECTURE.md)
- [Istio Ambient Mesh](https://istio.io/latest/docs/ambient/)

### SPIRE/SPIFFE
- [SPIRE GitHub Repository](https://github.com/spiffe/spire)
- [SPIRE Agent Configuration Reference](https://github.com/spiffe/spire/blob/main/doc/spire_agent.md)
- [SPIRE Delegated Identity API](https://github.com/spiffe/spire/blob/main/doc/spire_agent.md#delegated-identity-api)
- [SPIFFE Workload API](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md)
