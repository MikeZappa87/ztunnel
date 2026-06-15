# WIP: Windows Support

> **Companion docs (istio-cni side):**
> [istio/istio @ `experimental-windows-ambient` — WINDOWS.md](https://github.com/istio/istio/blob/experimental-windows-ambient/WINDOWS.md)
>
> That branch hosts the experimental Windows ambient istio-cni, the install
> manifests, and the build instructions for the CNI side of the data plane.
> This document covers the ztunnel side only; the two must be deployed
> together for Windows ambient to function.

Easiest way is probably to cross-compile? On Debian-based distros, install mingw:

```bash
sudo apt-get install mingw-w64
```

Then, add Rust cross-compile support with rustup:

```bash
rustup target add x86_64-pc-windows-gnu
```

Test a build with:

```bash
cargo build --target x86_64-pc-windows-gnu
```

Docker does support cross-building for Windows, but it is a bit of a pain. You can use the `docker buildx` command to build images for Windows. First, you need to create a new builder instance:

```bash
docker buildx create --name windows-builder --platform=windows/amd64 # change to windows/arm64 if you want to build for arm64
```

Then, build a docker image with:

```bash
docker buildx build . -f Dockerfile.ztunnel-windows --platform=windows/amd64 --output type=registry -t localhost:5000/ztunnel-windows --builder windows-builder
```

## DNS

HostProcess pods in Windows can't resolve cluster local DNS names. This is a known issue. In the meantime, you can use ALT_XDS_HOSTNAME and ALT_CA_HOSTNAME environment variables to set the expected certificate dns names for both XDS and CA clients.

UPDATE: looks like there are some powershell commands we can run (perhaps as an init container?) to set the nameserver for a certain DNS namespace:

```powershell
Add-DnsClientNrptRule -Namespace ".cluster.local" -NameServers "$env:KUBE_DNS_IP"
Clear-DnsClientCache # Clears the DNS client cache. Equivalent to `ipconfig /flushdns`
```

## REUSE_PORT

Socket reuse is effectively not supported on Windows (despite the options existing, they're either insecure or ineffective for our purposes)

## Traffic redirection

On Linux, ztunnel (via istio-cni) installs iptables rules inside each enrolled
pod's netns that REDIRECT outbound/inbound traffic to ztunnel's capture ports
(15001, 15006, 15008, 15053). See `scripts/ztunnel-redirect-inpod.sh`.

**ztunnel does not install any redirection on Windows.** There is no Windows
equivalent of that script, and ztunnel's Windows code path never programs
iptables, netfilter, VFP, or WFP rules. Redirection is the responsibility of
the Windows ambient CNI (see the companion
[istio/istio `experimental-windows-ambient` branch](https://github.com/istio/istio/blob/experimental-windows-ambient/WINDOWS.md));
ztunnel only provides the in-compartment listeners that the CNI's rules
target.

### What ztunnel actually does

For every workload it learns about over the `\\.\pipe\istio-zds` Named Pipe,
ztunnel:

1. Looks up the pod's HNS namespace by GUID (`hcn::get_namespace`) and reads
   the backing network **compartment ID**. See
   [`InpodNamespace::new`](src/inpod/windows/namespace.rs#L32-L50).
2. Switches the calling worker thread into that compartment using
   `SetCurrentThreadCompartmentId(compartment_id)`. See
   [`InpodNamespace::run`](src/inpod/windows/namespace.rs#L52-L63) and
   [`set_compartment`](src/inpod/windows/namespace.rs#L66-L75).
3. While the thread is in the pod's compartment, binds the per-workload
   listening sockets for 15001 / 15006 / 15008 / 15053 via the
   `InPodSocketFactory`. See
   [src/inpod/windows/config.rs](src/inpod/windows/config.rs#L84-L106).
4. Switches the thread back to compartment `1` (the host compartment) before
   returning.

The result is that, from inside the pod's network compartment, ztunnel's
capture ports are reachable on every IP at 15001/15006/15008/15053. ztunnel
does **not** add any rules that say "send my traffic to those ports" — it
just makes the ports available.

### What the Windows CNI is expected to do

The Windows ambient CNI is expected to attach HNS endpoint policies to each
enrolled pod's endpoint that perform L4 proxy redirection through the Windows
Filtering Platform (WFP). Conceptually this is the moral equivalent of an
iptables `REDIRECT` jump on Linux:

| Direction                              | Redirected to ztunnel port |
|----------------------------------------|----------------------------|
| Pod-originated TCP (outbound)          | 15001                      |
| Inbound plaintext TCP to the pod       | 15006                      |
| Inbound HBONE (mTLS) TCP to the pod    | 15008 (no rewrite)         |
| Pod-originated DNS (UDP/TCP port 53)   | 15053                      |

When a WFP-based L4 proxy policy redirects a connection, it preserves the
pre-redirect 5-tuple and makes it available to the receiving socket via the
`SO_ORIGINAL_DST` / `SO_ORIGINAL_DST_V6` socket options — the same option
names and numeric values as on Linux. ztunnel reads these on every accepted
connection to recover the original destination address:

- [`orig_dst_addr`](src/socket.rs#L82-L93) — Windows code path
- [`windows::original_dst` / `original_dst_ipv6`](src/socket.rs#L175-L189)

If `SO_ORIGINAL_DST` is missing on an accepted connection, ztunnel falls back
to `stream.local_addr()` (see
[`orig_dst_addr_or_default`](src/socket.rs#L51-L57)), which on Windows means
ztunnel will think the request was destined for its own listener. This is
almost always a sign that the CNI's redirection policy is misconfigured or
absent for that pod.

### Practical consequences

- A pod whose endpoint has no L4 proxy policy attached will simply bypass
  ztunnel — its traffic will egress and ingress normally. Nothing in ztunnel
  will warn about this, because from ztunnel's perspective the pod was
  enrolled and the listeners came up successfully.
- 15008 (HBONE) does not get a destination rewrite from the CNI in the same
  sense — it just needs to be reachable on the pod IP so peer ztunnels can
  HBONE-tunnel into it. NetworkPolicy on the pod must allow 15008 inbound,
  same as on Linux (see `ARCHITECTURE.md`).
- Because compartment switching is **per-thread**, the
  `InpodNamespace::run` closure must be short-lived and synchronous; only the
  socket creation/bind happens inside it. Once the socket exists, it stays
  bound in the pod's compartment for its lifetime regardless of which
  compartment the owning thread is currently in.
- Pods whose HNS namespace exists but whose compartment has not been assigned
  yet (HCN omits the field when `CompartmentId == 0`) are queued and retried
  every 500ms with exponential backoff; see
  [`WorkloadProxyManagerState::retry_compartmentless`](src/inpod/windows/statemanager.rs#L357-L444).

