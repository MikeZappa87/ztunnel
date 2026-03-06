// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! ZDS Server - A test server that acts as a CNI agent and XDS server for ztunnel.
//!
//! This server:
//! 1. Listens on a UDS socket for ztunnel to connect (ZDS protocol)
//! 2. Listens on a gRPC port for ztunnel XDS connections (WDS protocol)
//! 3. Exposes a control socket for the CLI to send ZDS and WDS commands
//! 4. Forwards AddWorkload/DelWorkload commands from CLI to ztunnel via ZDS
//! 5. Serves workload discovery to ztunnel via XDS (WDS)

use anyhow::{Context, Result, anyhow, bail};
use nix::sys::socket::{
    self, AddressFamily, MsgFlags, SockFlag, SockType, UnixAddr, bind as nixbind, listen,
    socket as nix_socket,
};
use prost::Message;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{IoSlice, IoSliceMut};
use std::net::{IpAddr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Command;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::sync::{RwLock, broadcast, mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};

use ztunnel::inpod::istio::zds::{
    Ack, AddWorkload, DelWorkload, KeepWorkload, SnapshotSent, WorkloadInfo, WorkloadRequest,
    WorkloadResponse, ZdsHello, workload_request::Payload,
    workload_response::Payload as ResponsePayload,
};

// XDS types
use ztunnel::xds::istio::workload::{
    Address as XdsAddress, TunnelProtocol, Workload as XdsWorkload, WorkloadStatus, WorkloadType,
    address::Type as AddressType,
};
use ztunnel::xds::service::discovery::v3::{
    DeltaDiscoveryRequest, DeltaDiscoveryResponse, Resource,
    aggregated_discovery_service_server::{
        AggregatedDiscoveryService, AggregatedDiscoveryServiceServer,
    },
};
use ztunnel::xds::{ADDRESS_TYPE, AUTHORIZATION_TYPE};

const DEFAULT_ZDS_SOCKET: &str = "/var/run/ztunnel/ztunnel.sock";
const DEFAULT_CONTROL_SOCKET: &str = "/var/run/ztunnel/control.sock";
const DEFAULT_XDS_SOCKET: &str = "/var/run/ztunnel/xds.sock";
const DEFAULT_XDS_PORT: u16 = 15010;

#[derive(Debug)]
struct Args {
    zds_socket: PathBuf,
    control_socket: PathBuf,
    xds_socket: Option<PathBuf>, // If set, use UDS instead of TCP
    xds_port: u16,
    upstream_xds: Option<String>, // If set, connect to upstream XDS server for remote workloads
}

/// Shared state for WDS workloads
#[derive(Clone)]
struct WorkloadStore {
    inner: Arc<RwLock<WorkloadStoreInner>>,
    update_tx: broadcast::Sender<WorkloadUpdate>,
}

struct WorkloadStoreInner {
    workloads: HashMap<String, StoredWorkload>,
}

#[derive(Clone, Debug)]
struct StoredWorkload {
    uid: String,
    name: String,
    namespace: String,
    service_account: String,
    ips: Vec<IpAddr>,
    node: String,
    protocol: String,
}

/// Channel for pushing local WDS changes to upstream XDS aggregator
type UpstreamPushTx = mpsc::Sender<WorkloadUpdate>;

#[derive(Clone, Debug)]
enum WorkloadUpdate {
    Add(StoredWorkload),
    Remove(String), // uid
}

impl WorkloadStore {
    fn new() -> Self {
        let (update_tx, _) = broadcast::channel(100);
        Self {
            inner: Arc::new(RwLock::new(WorkloadStoreInner {
                workloads: HashMap::new(),
            })),
            update_tx,
        }
    }

    async fn add(&self, workload: StoredWorkload) {
        let uid = workload.uid.clone();
        self.inner
            .write()
            .await
            .workloads
            .insert(uid, workload.clone());
        let _ = self.update_tx.send(WorkloadUpdate::Add(workload));
    }

    async fn remove(&self, uid: &str) -> bool {
        let removed = self.inner.write().await.workloads.remove(uid).is_some();
        if removed {
            let _ = self.update_tx.send(WorkloadUpdate::Remove(uid.to_string()));
        }
        removed
    }

    async fn list(&self) -> Vec<StoredWorkload> {
        self.inner
            .read()
            .await
            .workloads
            .values()
            .cloned()
            .collect()
    }

    async fn get(&self, uid: &str) -> Option<StoredWorkload> {
        self.inner.read().await.workloads.get(uid).cloned()
    }

    fn subscribe(&self) -> broadcast::Receiver<WorkloadUpdate> {
        self.update_tx.subscribe()
    }
}

fn print_help() {
    eprintln!(
        r#"zds-server - ZDS and WDS protocol server for testing ztunnel

USAGE:
    zds-server [OPTIONS]

OPTIONS:
    --zds-socket <PATH>      ZDS socket path for ztunnel (default: /var/run/ztunnel/ztunnel.sock)
    --control-socket <PATH>  Control socket for CLI (default: /var/run/ztunnel/control.sock)
    --xds-socket <PATH>      XDS UDS path (if set, uses UDS instead of TCP)
    --xds-port <PORT>        XDS gRPC port for WDS (default: 15010, ignored if --xds-socket is set)
    --help                   Print this help message

The server listens on three endpoints:
1. ZDS socket: ztunnel connects here for CNI protocol (SEQPACKET)
2. Control socket: CLI connects here to send commands (STREAM)
3. XDS port/socket: ztunnel connects here for workload discovery (gRPC)

ZDS CONTROL COMMANDS (for CNI protocol):
    add <uid> <name> <namespace> <service_account> <netns_path>
    del <uid>
    keep <uid>
    snapshot
    status

WDS CONTROL COMMANDS (for XDS workload discovery):
    wds-add <uid> <name> <namespace> <sa> <ip> [protocol]
    wds-del <uid>
    wds-list
    wds-get <uid>

EXAMPLE:
    # Start the server with UDS for XDS (recommended)
    zds-server --zds-socket /var/run/ztunnel/ztunnel.sock \
               --control-socket /var/run/ztunnel/control.sock \
               --xds-socket /var/run/ztunnel/xds.sock

    # Start the server with TCP for XDS
    zds-server --zds-socket /var/run/ztunnel/ztunnel.sock \
               --control-socket /var/run/ztunnel/control.sock \
               --xds-port 15010

    # Add workload via ZDS (CNI protocol with netns)
    zds-client send --control-socket /var/run/ztunnel/control.sock \
        add "pod-123" "my-pod" "default" "default" "/run/netns/test"

    # Add workload to WDS (XDS discovery)
    zds-client send --control-socket /var/run/ztunnel/control.sock \
        wds-add "Kubernetes//Pod/demo/nginx" "nginx" "demo" "default" "10.244.1.5" HBONE

    # List WDS workloads
    zds-client send --control-socket /var/run/ztunnel/control.sock wds-list

    # Configure ztunnel to use this server for XDS via UDS:
    XDS_ADDRESS=unix:///var/run/ztunnel/xds.sock ztunnel

MULTI-CLUSTER MODE:
    # Run a central XDS aggregator (no ZDS needed, just serves workloads):
    zds-server --xds-port 15010

    # Run a workload-cluster zds-server that relays from the central aggregator:
    zds-server --upstream-xds http://central-xds:15010 \
               --xds-socket /var/run/ztunnel/xds.sock

    # Register workloads on the central aggregator:
    zds-client send --control-socket /var/run/ztunnel/control.sock \
        wds-add "cluster-b//Pod/demo/nginx" "nginx" "demo" "default" "10.244.2.5" HBONE
"#
    );
}

fn parse_args() -> Result<Args> {
    let mut args = std::env::args().skip(1).peekable();
    let mut zds_socket = PathBuf::from(DEFAULT_ZDS_SOCKET);
    let mut control_socket = PathBuf::from(DEFAULT_CONTROL_SOCKET);
    let mut xds_socket: Option<PathBuf> = None;
    let mut xds_port = DEFAULT_XDS_PORT;
    let mut upstream_xds: Option<String> = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--zds-socket" => {
                zds_socket = PathBuf::from(
                    args.next()
                        .ok_or_else(|| anyhow!("--zds-socket requires a path"))?,
                );
            }
            "--control-socket" => {
                control_socket = PathBuf::from(
                    args.next()
                        .ok_or_else(|| anyhow!("--control-socket requires a path"))?,
                );
            }
            "--xds-socket" => {
                xds_socket = Some(PathBuf::from(
                    args.next()
                        .ok_or_else(|| anyhow!("--xds-socket requires a path"))?,
                ));
            }
            "--xds-port" => {
                xds_port = args
                    .next()
                    .ok_or_else(|| anyhow!("--xds-port requires a port number"))?
                    .parse()
                    .context("--xds-port must be a valid port number")?;
            }
            "--upstream-xds" => {
                upstream_xds = Some(args.next().ok_or_else(|| {
                    anyhow!("--upstream-xds requires a URL (e.g. http://host:port)")
                })?);
            }
            "--help" | "-h" | "help" => {
                print_help();
                std::process::exit(0);
            }
            _ => {
                bail!("Unknown argument: {}. Use --help for usage.", arg);
            }
        }
    }

    Ok(Args {
        zds_socket,
        control_socket,
        xds_socket,
        xds_port,
        upstream_xds,
    })
}

/// Command from CLI to be sent to ztunnel (ZDS protocol only)
#[derive(Debug)]
enum ZdsCommand {
    Add {
        uid: String,
        name: String,
        namespace: String,
        service_account: String,
        netns_path: PathBuf,
        vm_internal_ip: Option<String>,
        transparent_proxy: bool,
        vm_iface_mode: bool,
        response: oneshot::Sender<Result<String>>,
    },
    Del {
        uid: String,
        response: oneshot::Sender<Result<String>>,
    },
    Keep {
        uid: String,
        response: oneshot::Sender<Result<String>>,
    },
    Snapshot {
        response: oneshot::Sender<Result<String>>,
    },
    Status {
        response: oneshot::Sender<Result<String>>,
    },
}

/// State of a single ZDS connection to ztunnel
struct ZdsConnection {
    id: u64,
    fd: OwnedFd,
    connected: bool,
}

/// Manages multiple concurrent ztunnel connections
struct ZdsConnectionManager {
    connections: HashMap<u64, ZdsConnection>,
    next_id: u64,
}

impl ZdsConnectionManager {
    fn new() -> Self {
        Self {
            connections: HashMap::new(),
            next_id: 1,
        }
    }

    fn add(&mut self, fd: OwnedFd) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.connections.insert(
            id,
            ZdsConnection {
                id,
                fd,
                connected: true,
            },
        );
        id
    }

    fn get(&self, id: u64) -> Option<&ZdsConnection> {
        self.connections.get(&id)
    }

    fn remove(&mut self, id: u64) {
        self.connections.remove(&id);
    }

    fn len(&self) -> usize {
        self.connections.len()
    }

    /// Send delete to all connections
    fn broadcast_del(&self, uid: &str) {
        for conn in self.connections.values() {
            if let Err(e) = conn.send_del_workload(uid) {
                eprintln!("[ZDS] Failed to send del to connection {}: {}", conn.id, e);
            }
        }
    }
}

impl ZdsConnection {
    fn recv_hello(&self) -> Result<()> {
        let mut buf = [0u8; 4096];
        let bytes = {
            let mut iov = [IoSliceMut::new(&mut buf)];
            let msg = socket::recvmsg::<()>(self.fd.as_raw_fd(), &mut iov, None, MsgFlags::empty())
                .context("Failed to receive hello")?;
            msg.bytes
        };

        let hello = ZdsHello::decode(&buf[..bytes]).context("Failed to decode hello")?;

        eprintln!(
            "[ZDS] Received hello from ztunnel, version={}",
            hello.version
        );
        Ok(())
    }

    fn recv_ack(&self) -> Result<Ack> {
        let mut buf = [0u8; 4096];
        let bytes = {
            let mut iov = [IoSliceMut::new(&mut buf)];
            let msg = socket::recvmsg::<()>(self.fd.as_raw_fd(), &mut iov, None, MsgFlags::empty())
                .context("Failed to receive ack")?;
            msg.bytes
        };

        let response =
            WorkloadResponse::decode(&buf[..bytes]).context("Failed to decode response")?;

        match response.payload {
            Some(ResponsePayload::Ack(ack)) => {
                if ack.error.is_empty() {
                    eprintln!("[ZDS] Received ACK (success)");
                } else {
                    eprintln!("[ZDS] Received NACK: {}", ack.error);
                }
                Ok(ack)
            }
            None => bail!("Received empty response"),
        }
    }

    fn send_add_workload(
        &self,
        uid: &str,
        name: &str,
        namespace: &str,
        service_account: &str,
        netns_fd: RawFd,
    ) -> Result<Ack> {
        eprintln!(
            "[ZDS] Sending AddWorkload: uid={}, name={}, namespace={}, sa={}",
            uid, name, namespace, service_account
        );

        let request = WorkloadRequest {
            payload: Some(Payload::Add(AddWorkload {
                uid: uid.to_string(),
                workload_info: Some(WorkloadInfo {
                    name: name.to_string(),
                    namespace: namespace.to_string(),
                    service_account: service_account.to_string(),
                }),
            })),
        };

        let data = request.encode_to_vec();
        let iov = [IoSlice::new(&data)];
        let fds = [netns_fd];
        let cmsg = [socket::ControlMessage::ScmRights(&fds)];

        socket::sendmsg::<()>(self.fd.as_raw_fd(), &iov, &cmsg, MsgFlags::empty(), None)
            .context("Failed to send AddWorkload")?;

        self.recv_ack()
    }

    fn send_del_workload(&self, uid: &str) -> Result<Ack> {
        eprintln!("[ZDS] Sending DelWorkload: uid={}", uid);

        let request = WorkloadRequest {
            payload: Some(Payload::Del(DelWorkload {
                uid: uid.to_string(),
            })),
        };

        let data = request.encode_to_vec();
        let iov = [IoSlice::new(&data)];

        socket::sendmsg::<()>(self.fd.as_raw_fd(), &iov, &[], MsgFlags::empty(), None)
            .context("Failed to send DelWorkload")?;

        self.recv_ack()
    }

    fn send_keep_workload(&self, uid: &str) -> Result<Ack> {
        eprintln!("[ZDS] Sending KeepWorkload: uid={}", uid);

        let request = WorkloadRequest {
            payload: Some(Payload::Keep(KeepWorkload {
                uid: uid.to_string(),
            })),
        };

        let data = request.encode_to_vec();
        let iov = [IoSlice::new(&data)];

        socket::sendmsg::<()>(self.fd.as_raw_fd(), &iov, &[], MsgFlags::empty(), None)
            .context("Failed to send KeepWorkload")?;

        self.recv_ack()
    }

    fn send_snapshot(&self) -> Result<Ack> {
        eprintln!("[ZDS] Sending SnapshotSent");

        let request = WorkloadRequest {
            payload: Some(Payload::SnapshotSent(SnapshotSent {})),
        };

        let data = request.encode_to_vec();
        let iov = [IoSlice::new(&data)];

        socket::sendmsg::<()>(self.fd.as_raw_fd(), &iov, &[], MsgFlags::empty(), None)
            .context("Failed to send SnapshotSent")?;

        self.recv_ack()
    }
}

/// Create a SEQPACKET socket and listen for ztunnel connections
fn create_zds_listener(path: &PathBuf) -> Result<OwnedFd> {
    // Remove existing socket
    let _ = std::fs::remove_file(path);

    // Create parent directory if needed
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let socket = nix_socket(
        AddressFamily::Unix,
        SockType::SeqPacket,
        SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
        None,
    )?;

    let addr = UnixAddr::new(path)?;
    nixbind(socket.as_raw_fd(), &addr)?;

    let backlog = std::cmp::min(1024, libc::SOMAXCONN - 1);
    listen(&socket, nix::sys::socket::Backlog::new(backlog)?)?;

    eprintln!("[ZDS] Listening on {:?}", path);
    Ok(socket)
}

/// Bring up the loopback (lo) device inside the workload's network namespace.
/// Without this, localhost communication within the netns will not work.
fn set_lo_up(netns_path: &Path) -> Result<()> {
    let netns_str = netns_path.to_string_lossy();
    eprintln!("[ZDS] Setting lo up in netns {}", netns_str);

    let output = Command::new("nsenter")
        .arg(format!("--net={}", netns_str))
        .args(["--", "ip", "link", "set", "lo", "up"])
        .output()
        .with_context(|| format!("Failed to run nsenter for lo up in {:?}", netns_path))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "Failed to set lo up in netns {:?}: {}",
            netns_path,
            stderr.trim()
        );
    }

    eprintln!("[ZDS] lo is up in netns {}", netns_str);
    Ok(())
}

/// Run the ztunnel-redirect-workload.sh script to install or remove iptables rules
/// in a workload's network namespace.
fn run_redirect_script(action: &str, netns_path: &Path, vm_internal_ip: Option<&str>, transparent_proxy: bool, vm_iface_mode: bool) -> Result<()> {
    // Look for the script in several locations
    let script_candidates = [
        PathBuf::from("/usr/local/bin/ztunnel-redirect-workload.sh"),
        PathBuf::from("scripts/ztunnel-redirect-workload.sh"),
        {
            let mut p = std::env::current_exe()
                .unwrap_or_default()
                .parent()
                .unwrap_or(Path::new("/"))
                .to_path_buf();
            p.push("ztunnel-redirect-workload.sh");
            p
        },
    ];

    let script = script_candidates
        .iter()
        .find(|p| p.exists())
        .ok_or_else(|| {
            anyhow!(
                "ztunnel-redirect-workload.sh not found in any of: {:?}",
                script_candidates
            )
        })?;

    let netns_str = netns_path.to_string_lossy();
    eprintln!(
        "[ZDS] Running redirect script: {} {} {}{}{}{}",
        script.display(),
        action,
        netns_str,
        vm_internal_ip.map(|ip| format!(" --vm-internal-ip {}", ip)).unwrap_or_default(),
        if transparent_proxy { " --transparent-proxy" } else { "" },
        if vm_iface_mode { " --vm-iface-mode" } else { "" }
    );

    let mut cmd = Command::new(script.as_os_str());
    cmd.arg(action).arg(netns_str.as_ref());
    if let Some(ip) = vm_internal_ip {
        cmd.arg("--vm-internal-ip").arg(ip);
    }
    if transparent_proxy {
        cmd.arg("--transparent-proxy");
    }
    if vm_iface_mode {
        cmd.arg("--vm-iface-mode");
    }
    let output = cmd
        .output()
        .with_context(|| format!("Failed to execute redirect script: {}", script.display()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        bail!(
            "Redirect script failed (exit {}): stdout={}, stderr={}",
            output.status,
            stdout.trim(),
            stderr.trim()
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    if !stdout.is_empty() {
        eprintln!("[ZDS] {}", stdout.trim());
    }

    Ok(())
}

/// Accept a connection from ztunnel - returns Ok(Some(fd)) on success,
/// Ok(None) if no connection pending (EAGAIN), Err on real errors
fn accept_ztunnel(listener_fd: RawFd) -> Result<Option<OwnedFd>> {
    use nix::errno::Errno;
    // Use blocking socket for the connected client so recv_ack can wait for responses
    match socket::accept4(listener_fd, SockFlag::SOCK_CLOEXEC) {
        Ok(fd) => {
            eprintln!("[ZDS] Ztunnel connected!");
            Ok(Some(unsafe { OwnedFd::from_raw_fd(fd) }))
        }
        Err(Errno::EAGAIN) | Err(Errno::EWOULDBLOCK) => {
            Ok(None) // No pending connection, not an error
        }
        Err(e) => {
            // Debug: print what error we're actually getting
            eprintln!("[ZDS] DEBUG: Got error {:?} (raw: {})", e, e as i32);
            Err(anyhow::anyhow!("Accept failed: {}", e))
        }
    }
}

// ============================================================================
// XDS Service Implementation (WDS)
// ============================================================================

/// XDS service implementation for workload discovery
struct XdsService {
    store: WorkloadStore,
}

impl XdsService {
    fn new(store: WorkloadStore) -> Self {
        Self { store }
    }

    /// Convert a StoredWorkload to XDS Address proto
    fn workload_to_xds(workload: &StoredWorkload) -> XdsAddress {
        let protocol = match workload.protocol.to_uppercase().as_str() {
            "HBONE" => TunnelProtocol::Hbone,
            _ => TunnelProtocol::None,
        };

        let addresses: Vec<prost::bytes::Bytes> = workload
            .ips
            .iter()
            .map(|ip| match ip {
                IpAddr::V4(v4) => prost::bytes::Bytes::from(v4.octets().to_vec()),
                IpAddr::V6(v6) => prost::bytes::Bytes::from(v6.octets().to_vec()),
            })
            .collect();

        XdsAddress {
            r#type: Some(AddressType::Workload(XdsWorkload {
                uid: workload.uid.clone(),
                name: workload.name.clone(),
                namespace: workload.namespace.clone(),
                service_account: workload.service_account.clone(),
                addresses,
                node: workload.node.clone(),
                tunnel_protocol: protocol.into(),
                status: WorkloadStatus::Healthy.into(),
                workload_type: WorkloadType::Pod.into(),
                ..Default::default()
            })),
        }
    }

    /// Create a DeltaDiscoveryResponse with all current workloads
    async fn create_initial_response(&self, nonce: &str) -> DeltaDiscoveryResponse {
        let workloads = self.store.list().await;
        let resources: Vec<Resource> = workloads
            .iter()
            .map(|w| {
                let xds = Self::workload_to_xds(w);
                Resource {
                    name: w.uid.clone(),
                    resource: Some(prost_types::Any {
                        type_url: ADDRESS_TYPE.to_string(),
                        value: xds.encode_to_vec(),
                    }),
                    ..Default::default()
                }
            })
            .collect();

        DeltaDiscoveryResponse {
            type_url: ADDRESS_TYPE.to_string(),
            resources,
            nonce: nonce.to_string(),
            ..Default::default()
        }
    }

    /// Create an incremental update response
    fn create_update_response(update: &WorkloadUpdate, nonce: &str) -> DeltaDiscoveryResponse {
        match update {
            WorkloadUpdate::Add(workload) => {
                let xds = Self::workload_to_xds(workload);
                DeltaDiscoveryResponse {
                    type_url: ADDRESS_TYPE.to_string(),
                    resources: vec![Resource {
                        name: workload.uid.clone(),
                        resource: Some(prost_types::Any {
                            type_url: ADDRESS_TYPE.to_string(),
                            value: xds.encode_to_vec(),
                        }),
                        ..Default::default()
                    }],
                    nonce: nonce.to_string(),
                    ..Default::default()
                }
            }
            WorkloadUpdate::Remove(uid) => DeltaDiscoveryResponse {
                type_url: ADDRESS_TYPE.to_string(),
                removed_resources: vec![uid.clone()],
                nonce: nonce.to_string(),
                ..Default::default()
            },
        }
    }
}

// ============================================================================
// Upstream XDS Client (for multi-cluster relay)
// ============================================================================

use ztunnel::xds::service::discovery::v3::aggregated_discovery_service_client::AggregatedDiscoveryServiceClient;

/// A custom type_url used to push workload registrations from a downstream
/// zds-server to the upstream XDS aggregator via the Delta ADS stream.
const WORKLOAD_REGISTER_TYPE: &str = "istio.io/workloadRegister";
const WORKLOAD_UNREGISTER_TYPE: &str = "istio.io/workloadUnregister";

/// Connect to an upstream XDS server and pull workloads into the local store.
/// This enables multi-cluster: remote workloads discovered upstream are merged
/// into the local WorkloadStore and pushed to local ztunnel.
///
/// If `local_push_rx` is provided, local WDS changes are forwarded to the
/// upstream aggregator so they become visible to all other clusters.
async fn run_upstream_xds_client(
    upstream_url: String,
    store: WorkloadStore,
    mut local_push_rx: mpsc::Receiver<WorkloadUpdate>,
    local_uids: Arc<RwLock<HashSet<String>>>,
) -> Result<()> {
    eprintln!("[Upstream XDS] Connecting to {}", upstream_url);

    let channel = tonic::transport::Endpoint::from_shared(upstream_url.clone())
        .context("Invalid upstream XDS URL")?
        .connect()
        .await
        .context("Failed to connect to upstream XDS server")?;

    let mut client = AggregatedDiscoveryServiceClient::new(channel);

    let (tx, rx) = mpsc::channel(32);
    let request_stream = ReceiverStream::new(rx);

    // Send initial subscription for Address type
    let initial_request = DeltaDiscoveryRequest {
        type_url: ADDRESS_TYPE.to_string(),
        ..Default::default()
    };
    tx.send(initial_request)
        .await
        .context("Failed to send initial request")?;

    let response = client
        .delta_aggregated_resources(Request::new(request_stream))
        .await
        .context("Failed to start upstream delta stream")?;

    let mut stream = response.into_inner();

    eprintln!("[Upstream XDS] Connected, waiting for workloads...");

    // Spawn a task to forward local WDS updates to the upstream via the request stream
    let tx_for_push = tx.clone();
    let local_uids_for_push = local_uids.clone();
    tokio::spawn(async move {
        while let Some(update) = local_push_rx.recv().await {
            let req = match &update {
                WorkloadUpdate::Add(workload) => {
                    // Mark this UID as locally-originated to suppress echo-back
                    local_uids_for_push
                        .write()
                        .await
                        .insert(workload.uid.clone());
                    let xds = XdsService::workload_to_xds(workload);
                    eprintln!(
                        "[Upstream Push] Forwarding wds-add upstream: uid={}",
                        workload.uid
                    );
                    DeltaDiscoveryRequest {
                        type_url: WORKLOAD_REGISTER_TYPE.to_string(),
                        resource_names_subscribe: vec![workload.uid.clone()],
                        initial_resource_versions: std::collections::HashMap::from([(
                            workload.uid.clone(),
                            xds.encode_to_vec()
                                .iter()
                                .map(|b| format!("{:02x}", b))
                                .collect::<String>(),
                        )]),
                        ..Default::default()
                    }
                }
                WorkloadUpdate::Remove(uid) => {
                    // Remove from local_uids so future remote adds are allowed
                    local_uids_for_push.write().await.remove(uid.as_str());
                    eprintln!("[Upstream Push] Forwarding wds-del upstream: uid={}", uid);
                    DeltaDiscoveryRequest {
                        type_url: WORKLOAD_UNREGISTER_TYPE.to_string(),
                        resource_names_unsubscribe: vec![uid.clone()],
                        ..Default::default()
                    }
                }
            };
            if tx_for_push.send(req).await.is_err() {
                eprintln!("[Upstream Push] Channel closed, stopping push forwarder");
                break;
            }
        }
    });

    while let Some(msg) = stream.message().await.context("Upstream stream error")? {
        eprintln!(
            "[Upstream XDS] Received: {} resources, {} removed",
            msg.resources.len(),
            msg.removed_resources.len()
        );

        // Process additions/updates
        for resource in &msg.resources {
            if let Some(ref any) = resource.resource {
                if any.type_url == ADDRESS_TYPE {
                    match XdsAddress::decode(any.value.as_ref()) {
                        Ok(addr) => {
                            if let Some(AddressType::Workload(wl)) = addr.r#type {
                                let ips: Vec<IpAddr> = wl
                                    .addresses
                                    .iter()
                                    .filter_map(|b| match b.len() {
                                        4 => {
                                            let arr: [u8; 4] = b[..4].try_into().ok()?;
                                            Some(IpAddr::V4(std::net::Ipv4Addr::from(arr)))
                                        }
                                        16 => {
                                            let arr: [u8; 16] = b[..16].try_into().ok()?;
                                            Some(IpAddr::V6(std::net::Ipv6Addr::from(arr)))
                                        }
                                        _ => None,
                                    })
                                    .collect();

                                let protocol = match TunnelProtocol::try_from(wl.tunnel_protocol) {
                                    Ok(TunnelProtocol::Hbone) => "HBONE".to_string(),
                                    _ => "NONE".to_string(),
                                };

                                let stored = StoredWorkload {
                                    uid: wl.uid.clone(),
                                    name: wl.name.clone(),
                                    namespace: wl.namespace.clone(),
                                    service_account: wl.service_account.clone(),
                                    ips,
                                    node: wl.node.clone(),
                                    protocol,
                                };

                                eprintln!(
                                    "[Upstream XDS] Adding workload: uid={} name={} ns={} ips={:?}",
                                    stored.uid, stored.name, stored.namespace, stored.ips
                                );
                                // Suppress echo-back: skip if this UID was locally originated
                                if local_uids.read().await.contains(&stored.uid) {
                                    eprintln!(
                                        "[Upstream XDS] Skipping echo-back add for local uid={}",
                                        stored.uid
                                    );
                                } else {
                                    store.add(stored).await;
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("[Upstream XDS] Failed to decode Address: {}", e);
                        }
                    }
                }
            }
        }

        // Process removals
        for uid in &msg.removed_resources {
            // Suppress echo-back: skip if this UID was locally removed
            if !local_uids.read().await.contains(uid) {
                eprintln!("[Upstream XDS] Removing workload: uid={}", uid);
                store.remove(uid).await;
            } else {
                eprintln!(
                    "[Upstream XDS] Skipping echo-back remove for local uid={}",
                    uid
                );
            }
        }

        // ACK the response
        let ack = DeltaDiscoveryRequest {
            type_url: ADDRESS_TYPE.to_string(),
            response_nonce: msg.nonce.clone(),
            ..Default::default()
        };
        if tx.send(ack).await.is_err() {
            eprintln!("[Upstream XDS] Request channel closed");
            break;
        }
    }

    eprintln!("[Upstream XDS] Stream ended");
    Ok(())
}

type DeltaStream =
    Pin<Box<dyn tokio_stream::Stream<Item = Result<DeltaDiscoveryResponse, Status>> + Send>>;
type SotWStream = Pin<
    Box<
        dyn tokio_stream::Stream<
                Item = Result<ztunnel::xds::service::discovery::v3::DiscoveryResponse, Status>,
            > + Send,
    >,
>;

#[tonic::async_trait]
impl AggregatedDiscoveryService for XdsService {
    type StreamAggregatedResourcesStream = SotWStream;
    type DeltaAggregatedResourcesStream = DeltaStream;

    async fn stream_aggregated_resources(
        &self,
        _request: Request<Streaming<ztunnel::xds::service::discovery::v3::DiscoveryRequest>>,
    ) -> Result<Response<Self::StreamAggregatedResourcesStream>, Status> {
        Err(Status::unimplemented(
            "Use DeltaAggregatedResources instead",
        ))
    }

    async fn delta_aggregated_resources(
        &self,
        request: Request<Streaming<DeltaDiscoveryRequest>>,
    ) -> Result<Response<Self::DeltaAggregatedResourcesStream>, Status> {
        let mut request_stream = request.into_inner();
        let store = self.store.clone();
        let mut update_rx = store.subscribe();

        eprintln!("[XDS] Client connected");

        let (tx, rx) = mpsc::channel(32);

        // Spawn handler for this client connection
        tokio::spawn(async move {
            let mut nonce_counter = 0u64;
            let mut sent_address = false;
            let mut sent_authorization = false;

            // Wait for initial subscriptions from the client.
            // ztunnel subscribes to both Address and Authorization.
            // Upstream relay clients only subscribe to Address.
            // We use a short timeout after the first subscription to catch any
            // additional subscriptions that arrive quickly.
            let mut deadline: Option<tokio::time::Instant> = None;
            loop {
                let next_msg = async {
                    if let Some(dl) = deadline {
                        tokio::select! {
                            msg = request_stream.message() => msg,
                            _ = tokio::time::sleep_until(dl) => {
                                // Timeout waiting for additional subscriptions
                                return Ok(None);
                            }
                        }
                    } else {
                        request_stream.message().await
                    }
                };

                match next_msg.await {
                    Ok(Some(req)) => {
                        let type_url = req.type_url.clone();
                        eprintln!(
                            "[XDS] Received request: type_url={} nonce={}",
                            type_url, req.response_nonce
                        );

                        // If this is an ACK (has response_nonce), don't send a new response
                        if !req.response_nonce.is_empty() {
                            continue;
                        }

                        // Handle initial subscriptions for different types
                        if type_url == ADDRESS_TYPE.to_string() && !sent_address {
                            // Send initial snapshot for Address type
                            let nonce = format!("nonce-{}", nonce_counter);
                            nonce_counter += 1;

                            let store_clone = store.clone();
                            let response = store_clone.inner.read().await;
                            let workloads: Vec<_> = response.workloads.values().cloned().collect();
                            drop(response);

                            let resources: Vec<Resource> = workloads
                                .iter()
                                .map(|w| {
                                    let xds = XdsService::workload_to_xds(w);
                                    Resource {
                                        name: w.uid.clone(),
                                        resource: Some(prost_types::Any {
                                            type_url: ADDRESS_TYPE.to_string(),
                                            value: xds.encode_to_vec(),
                                        }),
                                        ..Default::default()
                                    }
                                })
                                .collect();

                            let initial_response = DeltaDiscoveryResponse {
                                type_url: ADDRESS_TYPE.to_string(),
                                resources,
                                nonce,
                                ..Default::default()
                            };

                            eprintln!(
                                "[XDS] Sending {} Address resources",
                                initial_response.resources.len()
                            );
                            if tx.send(Ok(initial_response)).await.is_err() {
                                return;
                            }
                            sent_address = true;
                        } else if type_url == AUTHORIZATION_TYPE.to_string() && !sent_authorization
                        {
                            // Send empty Authorization response
                            let nonce = format!("nonce-{}", nonce_counter);
                            nonce_counter += 1;

                            let empty_response = DeltaDiscoveryResponse {
                                type_url: AUTHORIZATION_TYPE.to_string(),
                                resources: vec![],
                                nonce,
                                ..Default::default()
                            };

                            eprintln!("[XDS] Sending empty Authorization response");
                            if tx.send(Ok(empty_response)).await.is_err() {
                                return;
                            }
                            sent_authorization = true;
                        }

                        // Once we've handled both subscriptions, break to event loop
                        // If only one is handled, set a brief deadline for the other
                        if sent_address && sent_authorization {
                            break;
                        } else if (sent_address || sent_authorization) && deadline.is_none() {
                            // Give 100ms for the other subscription to arrive
                            deadline = Some(
                                tokio::time::Instant::now() + std::time::Duration::from_millis(100),
                            );
                        }
                    }
                    Ok(None) => {
                        if deadline.is_some() {
                            // Timeout expired, break to event loop with what we have
                            eprintln!(
                                "[XDS] Subscription timeout, proceeding with sent_address={} sent_authorization={}",
                                sent_address, sent_authorization
                            );
                            break;
                        }
                        eprintln!("[XDS] Client closed connection");
                        return;
                    }
                    Err(e) => {
                        eprintln!("[XDS] Error receiving request: {}", e);
                        return;
                    }
                }
            }

            // Listen for updates and send them to client
            loop {
                tokio::select! {
                    // Handle subsequent requests (ACKs, subscriptions)
                    msg = request_stream.message() => {
                        match msg {
                            Ok(Some(req)) => {
                                eprintln!("[XDS] Received ACK/request: type_url={} nonce={}", req.type_url, req.response_nonce);

                                // Handle workload registration pushes from downstream servers
                                if req.type_url == WORKLOAD_REGISTER_TYPE {
                                    for (uid, hex_data) in &req.initial_resource_versions {
                                        let bytes: Vec<u8> = (0..hex_data.len())
                                            .step_by(2)
                                            .filter_map(|i| u8::from_str_radix(&hex_data[i..i+2], 16).ok())
                                            .collect();
                                        match XdsAddress::decode(bytes.as_slice()) {
                                            Ok(addr) => {
                                                if let Some(AddressType::Workload(wl)) = addr.r#type {
                                                    let ips: Vec<IpAddr> = wl.addresses.iter().filter_map(|b| {
                                                        match b.len() {
                                                            4 => {
                                                                let arr: [u8; 4] = b[..4].try_into().ok()?;
                                                                Some(IpAddr::V4(std::net::Ipv4Addr::from(arr)))
                                                            }
                                                            16 => {
                                                                let arr: [u8; 16] = b[..16].try_into().ok()?;
                                                                Some(IpAddr::V6(std::net::Ipv6Addr::from(arr)))
                                                            }
                                                            _ => None,
                                                        }
                                                    }).collect();
                                                    let protocol = match TunnelProtocol::try_from(wl.tunnel_protocol) {
                                                        Ok(TunnelProtocol::Hbone) => "HBONE".to_string(),
                                                        _ => "NONE".to_string(),
                                                    };
                                                    let stored = StoredWorkload {
                                                        uid: wl.uid.clone(),
                                                        name: wl.name.clone(),
                                                        namespace: wl.namespace.clone(),
                                                        service_account: wl.service_account.clone(),
                                                        ips,
                                                        node: wl.node.clone(),
                                                        protocol,
                                                    };
                                                    eprintln!("[XDS] Registered workload from downstream: uid={} ips={:?}", stored.uid, stored.ips);
                                                    store.add(stored).await;
                                                }
                                            }
                                            Err(e) => {
                                                eprintln!("[XDS] Failed to decode pushed workload {}: {}", uid, e);
                                            }
                                        }
                                    }
                                    continue;
                                }
                                if req.type_url == WORKLOAD_UNREGISTER_TYPE {
                                    for uid in &req.resource_names_unsubscribe {
                                        eprintln!("[XDS] Unregistered workload from downstream: uid={}", uid);
                                        store.remove(uid).await;
                                    }
                                    continue;
                                }

                                // Handle late subscriptions (empty nonce = initial subscription)
                                if req.response_nonce.is_empty() {
                                    if req.type_url == AUTHORIZATION_TYPE.to_string() && !sent_authorization {
                                        let nonce = format!("nonce-{}", nonce_counter);
                                        nonce_counter += 1;
                                        let empty_response = DeltaDiscoveryResponse {
                                            type_url: AUTHORIZATION_TYPE.to_string(),
                                            resources: vec![],
                                            nonce,
                                            ..Default::default()
                                        };
                                        eprintln!("[XDS] Sending empty Authorization response (late subscription)");
                                        if tx.send(Ok(empty_response)).await.is_err() {
                                            break;
                                        }
                                        sent_authorization = true;
                                    } else if req.type_url == ADDRESS_TYPE.to_string() && !sent_address {
                                        let store_clone = store.clone();
                                        let response = store_clone.inner.read().await;
                                        let workloads: Vec<_> = response.workloads.values().cloned().collect();
                                        drop(response);
                                        let resources: Vec<Resource> = workloads.iter().map(|w| {
                                            let xds = XdsService::workload_to_xds(w);
                                            Resource {
                                                name: w.uid.clone(),
                                                resource: Some(prost_types::Any {
                                                    type_url: ADDRESS_TYPE.to_string(),
                                                    value: xds.encode_to_vec(),
                                                }),
                                                ..Default::default()
                                            }
                                        }).collect();
                                        let nonce = format!("nonce-{}", nonce_counter);
                                        nonce_counter += 1;
                                        let initial_response = DeltaDiscoveryResponse {
                                            type_url: ADDRESS_TYPE.to_string(),
                                            resources,
                                            nonce,
                                            ..Default::default()
                                        };
                                        eprintln!("[XDS] Sending {} Address resources (late subscription)", initial_response.resources.len());
                                        if tx.send(Ok(initial_response)).await.is_err() {
                                            break;
                                        }
                                        sent_address = true;
                                    }
                                }
                            }
                            Ok(None) => {
                                eprintln!("[XDS] Client disconnected");
                                break;
                            }
                            Err(e) => {
                                eprintln!("[XDS] Stream error: {}", e);
                                break;
                            }
                        }
                    }
                    // Handle workload updates
                    update = update_rx.recv() => {
                        match update {
                            Ok(upd) => {
                                let nonce = format!("nonce-{}", nonce_counter);
                                nonce_counter += 1;
                                let response = XdsService::create_update_response(&upd, &nonce);
                                eprintln!("[XDS] Sending update: {:?}", upd);
                                if tx.send(Ok(response)).await.is_err() {
                                    break;
                                }
                            }
                            Err(_) => {
                                // Channel closed
                                break;
                            }
                        }
                    }
                }
            }
        });

        let stream = ReceiverStream::new(rx);
        Ok(Response::new(Box::pin(stream) as DeltaStream))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = parse_args()?;

    eprintln!("ZDS Server starting...");
    eprintln!("  ZDS socket: {:?}", args.zds_socket);
    eprintln!("  Control socket: {:?}", args.control_socket);
    if let Some(ref xds_socket) = args.xds_socket {
        eprintln!("  XDS socket: {:?}", xds_socket);
    } else {
        eprintln!("  XDS port: {}", args.xds_port);
    }
    if let Some(ref upstream) = args.upstream_xds {
        eprintln!("  Upstream XDS: {}", upstream);
    }

    // Create WDS workload store
    let workload_store = WorkloadStore::new();

    // Create command channel
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<ZdsCommand>(32);

    // Create ZDS listener for ztunnel
    let zds_listener = create_zds_listener(&args.zds_socket)?;

    // Remove existing control socket
    let _ = std::fs::remove_file(&args.control_socket);
    if let Some(parent) = args.control_socket.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Create control socket listener (TCP-style for easier CLI interaction)
    let control_listener = tokio::net::UnixListener::bind(&args.control_socket)?;
    eprintln!("[Control] Listening on {:?}", args.control_socket);

    // Start XDS gRPC server
    let xds_service = XdsService::new(workload_store.clone());

    if let Some(xds_socket) = args.xds_socket {
        // Use UDS for XDS
        let _ = std::fs::remove_file(&xds_socket);
        if let Some(parent) = xds_socket.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let uds_listener = tokio::net::UnixListener::bind(&xds_socket)?;
        eprintln!("[XDS] Starting gRPC server on UDS {:?}", xds_socket);

        tokio::spawn(async move {
            let incoming = tokio_stream::wrappers::UnixListenerStream::new(uds_listener);
            if let Err(e) = tonic::transport::Server::builder()
                .add_service(AggregatedDiscoveryServiceServer::new(xds_service))
                .serve_with_incoming(incoming)
                .await
            {
                eprintln!("[XDS] Server error: {}", e);
            }
        });
    } else {
        // Use TCP for XDS
        let xds_addr: SocketAddr = format!("0.0.0.0:{}", args.xds_port).parse()?;
        eprintln!("[XDS] Starting gRPC server on {}", xds_addr);

        tokio::spawn(async move {
            if let Err(e) = tonic::transport::Server::builder()
                .add_service(AggregatedDiscoveryServiceServer::new(xds_service))
                .serve(xds_addr)
                .await
            {
                eprintln!("[XDS] Server error: {}", e);
            }
        });
    }

    // Start upstream XDS client (for multi-cluster relay)
    // Create a push channel so local wds-add/wds-del can be forwarded upstream
    let upstream_push_tx: Option<UpstreamPushTx> = if let Some(upstream_url) = args.upstream_xds {
        let (push_tx, push_rx) = mpsc::channel::<WorkloadUpdate>(64);
        let store_for_upstream = workload_store.clone();
        let local_uids: Arc<RwLock<HashSet<String>>> = Arc::new(RwLock::new(HashSet::new()));
        tokio::spawn(async move {
            // The push_rx can only be consumed once, so we pass it into the first
            // successful connection. On reconnect we lose buffered pushes, but
            // the local store is still correct and a full resync would restore state.
            let mut push_rx_opt = Some(push_rx);
            loop {
                eprintln!("[Upstream XDS] Connecting to {}...", upstream_url);
                // Create a dummy receiver if we already consumed the real one
                let rx = push_rx_opt.take().unwrap_or_else(|| {
                    let (_tx, rx) = mpsc::channel::<WorkloadUpdate>(1);
                    rx
                });
                match run_upstream_xds_client(
                    upstream_url.clone(),
                    store_for_upstream.clone(),
                    rx,
                    local_uids.clone(),
                )
                .await
                {
                    Ok(()) => {
                        eprintln!("[Upstream XDS] Connection ended cleanly, reconnecting in 5s...");
                    }
                    Err(e) => {
                        eprintln!("[Upstream XDS] Connection error: {}, retrying in 5s...", e);
                    }
                }
                // Clear local_uids on reconnect since state is unknown
                local_uids.write().await.clear();
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        });
        Some(push_tx)
    } else {
        None
    };

    // Spawn control socket handler
    let cmd_tx_clone = cmd_tx.clone();
    let store_clone = workload_store.clone();
    let upstream_tx_clone = upstream_push_tx.clone();
    tokio::spawn(async move {
        loop {
            match control_listener.accept().await {
                Ok((stream, _)) => {
                    let tx = cmd_tx_clone.clone();
                    let store = store_clone.clone();
                    let upstream_tx = upstream_tx_clone.clone();
                    tokio::spawn(handle_control_client(stream, tx, store, upstream_tx));
                }
                Err(e) => {
                    eprintln!("[Control] Accept error: {}", e);
                }
            }
        }
    });

    // Main loop: wait for ztunnel connection and handle commands
    let mut conn_manager = ZdsConnectionManager::new();
    // Track netns paths per UID for iptables cleanup on delete
    let mut netns_by_uid: HashMap<String, PathBuf> = HashMap::new();

    eprintln!("[ZDS] Waiting for ztunnel to connect...");

    loop {
        tokio::select! {
            // Check for ztunnel connection (non-blocking poll)
            _ = tokio::time::sleep(tokio::time::Duration::from_millis(100)) => {
                // Always try to accept new connections (each ztunnel gets its own)
                match accept_ztunnel(zds_listener.as_raw_fd()) {
                    Ok(Some(fd)) => {
                        let id = conn_manager.add(fd);
                        eprintln!("[ZDS] New ztunnel connection (id={}), total: {}", id, conn_manager.len());

                        // Receive hello and send snapshot for the new connection
                        if let Some(conn) = conn_manager.get(id) {
                            if let Err(e) = conn.recv_hello() {
                                eprintln!("[ZDS] Failed to recv hello from {}: {}", id, e);
                                conn_manager.remove(id);
                            } else if let Err(e) = conn.send_snapshot() {
                                eprintln!("[ZDS] Failed to send snapshot to {}: {}", id, e);
                                conn_manager.remove(id);
                            } else {
                                eprintln!("[ZDS] Connection {} ready", id);
                            }
                        }
                    }
                    Ok(None) => {
                        // No pending connection - this is normal (EAGAIN)
                    }
                    Err(e) => {
                        eprintln!("[ZDS] Accept error: {}", e);
                    }
                }
            }

            // Handle ZDS commands from CLI (WDS commands handled directly in control handler)
            Some(cmd) = cmd_rx.recv() => {
                // Handle ZDS commands
                if conn_manager.len() == 0 {
                    match cmd {
                        ZdsCommand::Status { response } => {
                            let _ = response.send(Ok("Waiting for ztunnel connection".to_string()));
                        }
                        ZdsCommand::Add { response, .. } |
                        ZdsCommand::Del { response, .. } |
                        ZdsCommand::Keep { response, .. } |
                        ZdsCommand::Snapshot { response } => {
                            let _ = response.send(Err(anyhow!("Ztunnel not connected")));
                        }
                    }
                    continue;
                }

                // Get the newest connection for ZDS commands
                // When ztunnel restarts, the old connection becomes stale
                let conn_id = *conn_manager.connections.keys().max().unwrap();
                let conn = conn_manager.get(conn_id).unwrap();

                match cmd {
                    ZdsCommand::Add { uid, name, namespace, service_account, netns_path, vm_internal_ip, transparent_proxy, vm_iface_mode, response } => {
                        let result = (|| {
                            // Bring up loopback inside the workload's netns
                            set_lo_up(&netns_path)?;

                            // Install iptables redirect rules in the workload's netns
                            run_redirect_script("install", &netns_path, vm_internal_ip.as_deref(), transparent_proxy, vm_iface_mode)?;

                            let file = File::open(&netns_path)
                                .with_context(|| format!("Failed to open netns: {:?}", netns_path))?;
                            let ack = conn.send_add_workload(
                                &uid, &name, &namespace, &service_account,
                                file.as_raw_fd(),
                            )?;
                            if ack.error.is_empty() {
                                Ok("OK".to_string())
                            } else {
                                Ok(format!("NACK: {}", ack.error))
                            }
                        })();
                        if result.is_err() {
                            // Connection is likely stale — remove it
                            eprintln!("[ZDS] Removing stale connection {} after send failure", conn_id);
                            conn_manager.remove(conn_id);
                        }
                        if result.is_ok() {
                            netns_by_uid.insert(uid.clone(), netns_path);
                        }
                        let _ = response.send(result);
                    }
                    ZdsCommand::Del { uid, response } => {
                        // Remove iptables redirect rules from the workload's netns
                        if let Some(netns_path) = netns_by_uid.remove(&uid) {
                            if let Err(e) = run_redirect_script("remove", &netns_path, None, false, false) {
                                eprintln!("[ZDS] WARNING: Failed to remove iptables rules: {}", e);
                            }
                        }
                        // Broadcast delete to all connections
                        conn_manager.broadcast_del(&uid);
                        let _ = response.send(Ok("OK (broadcast)".to_string()));
                    }
                    ZdsCommand::Keep { uid, response } => {
                        let result = conn.send_keep_workload(&uid)
                            .map(|ack| {
                                if ack.error.is_empty() {
                                    "OK".to_string()
                                } else {
                                    format!("NACK: {}", ack.error)
                                }
                            });
                        let _ = response.send(result);
                    }
                    ZdsCommand::Snapshot { response } => {
                        let result = conn.send_snapshot()
                            .map(|ack| {
                                if ack.error.is_empty() {
                                    "OK".to_string()
                                } else {
                                    format!("NACK: {}", ack.error)
                                }
                            });
                        let _ = response.send(result);
                    }
                    ZdsCommand::Status { response } => {
                        let _ = response.send(Ok(format!("{} ztunnel connection(s)", conn_manager.len())));
                    }
                }
            }
        }
    }
}

async fn handle_control_client(
    mut stream: tokio::net::UnixStream,
    cmd_tx: mpsc::Sender<ZdsCommand>,
    workload_store: WorkloadStore,
    upstream_tx: Option<UpstreamPushTx>,
) {
    let (reader, mut writer) = stream.split();
    let mut reader = tokio::io::BufReader::new(reader);
    let mut line = String::new();

    eprintln!("[Control] Client connected");

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => {
                eprintln!("[Control] Client disconnected");
                break;
            }
            Ok(_) => {
                let response =
                    handle_control_command(&line.trim(), &cmd_tx, &workload_store, &upstream_tx)
                        .await;
                let _ = writer.write_all(format!("{}\n", response).as_bytes()).await;
            }
            Err(e) => {
                eprintln!("[Control] Read error: {}", e);
                break;
            }
        }
    }
}

async fn handle_control_command(
    line: &str,
    cmd_tx: &mpsc::Sender<ZdsCommand>,
    workload_store: &WorkloadStore,
    upstream_tx: &Option<UpstreamPushTx>,
) -> String {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.is_empty() {
        return "ERROR: Empty command".to_string();
    }

    match parts[0] {
        // ===== WDS COMMANDS (handled directly, no channel) =====
        "wds-add" => {
            // wds-add <uid> <name> <ns> <sa> <ip>[,<ip>...] [protocol] [node]
            if parts.len() < 6 {
                return "ERROR: Usage: wds-add <uid> <name> <namespace> <sa> <ip>[,<ip>...] [protocol] [node]".to_string();
            }
            let protocol = parts.get(6).map(|s| s.to_string()).unwrap_or_else(|| "HBONE".to_string());
            let node = parts.get(7).map(|s| s.to_string()).unwrap_or_else(|| "test-node".to_string());
            let mut ips = Vec::new();
            for ip_str in parts[5].split(',') {
                match ip_str.trim().parse::<std::net::IpAddr>() {
                    Ok(ip) => ips.push(ip),
                    Err(e) => return format!("ERROR: Invalid IP address '{}': {}", ip_str, e),
                }
            }
            let workload = StoredWorkload {
                uid: parts[1].to_string(),
                name: parts[2].to_string(),
                namespace: parts[3].to_string(),
                service_account: parts[4].to_string(),
                ips,
                node,
                protocol,
            };
            workload_store.add(workload.clone()).await;
            // Forward to upstream XDS aggregator if configured
            if let Some(tx) = upstream_tx {
                if let Err(e) = tx.send(WorkloadUpdate::Add(workload)).await {
                    eprintln!("[Control] Failed to push wds-add upstream: {}", e);
                }
            }
            format!("OK: Added workload {}", parts[1])
        }
        "wds-del" => {
            if parts.len() != 2 {
                return "ERROR: Usage: wds-del <uid>".to_string();
            }
            let found = workload_store.remove(parts[1]).await;
            // Always forward to upstream XDS aggregator if configured,
            // even if the local store didn't have it (echo-back may have
            // already removed the local copy).
            if let Some(tx) = upstream_tx {
                if let Err(e) = tx.send(WorkloadUpdate::Remove(parts[1].to_string())).await {
                    eprintln!("[Control] Failed to push wds-del upstream: {}", e);
                }
            }
            if found {
                format!("OK: Removed workload {}", parts[1])
            } else {
                format!("OK: Removed workload {} (was not in local store)", parts[1])
            }
        }
        "wds-list" => {
            let workloads = workload_store.list().await;
            if workloads.is_empty() {
                return "OK: 0 workloads".to_string();
            }
            let output = workloads.iter()
                .map(|w| format!("  {}|{}|{}|{}|{:?}", w.uid, w.name, w.namespace, w.service_account, w.ips))
                .collect::<Vec<_>>()
                .join("\n");
            format!("OK: {} workloads\n{}", workloads.len(), output)
        }
        "wds-get" => {
            if parts.len() != 2 {
                return "ERROR: Usage: wds-get <uid>".to_string();
            }
            match workload_store.get(parts[1]).await {
                Some(w) => {
                    format!(
                        "OK: uid={} name={} ns={} sa={} ips={:?} proto={} node={}",
                        w.uid, w.name, w.namespace, w.service_account, w.ips, w.protocol, w.node
                    )
                }
                None => format!("WARN: Workload {} not found", parts[1]),
            }
        }
        // ===== ZDS COMMANDS (via channel to main loop) =====
        "add" => {
            // Usage: add <uid> <name> <namespace> <service_account> <netns_path> [vm_internal_ip] [--transparent-proxy] [--vm-iface-mode]
            if parts.len() < 6 || parts.len() > 9 {
                return "ERROR: Usage: add <uid> <name> <namespace> <service_account> <netns_path> [vm_internal_ip] [--transparent-proxy] [--vm-iface-mode]".to_string();
            }
            let (tx, rx) = oneshot::channel();
            let netns_input = parts[5];
            // If the user provided a bare name (no path separator), prepend /var/run/netns/
            let netns_path = if netns_input.contains('/') {
                PathBuf::from(netns_input)
            } else {
                PathBuf::from(format!("/var/run/netns/{}", netns_input))
            };
            // Parse remaining positional/flag args
            let mut vm_internal_ip = None;
            let mut transparent_proxy = false;
            let mut vm_iface_mode = false;
            for &part in &parts[6..] {
                if part == "--transparent-proxy" {
                    transparent_proxy = true;
                } else if part == "--vm-iface-mode" {
                    vm_iface_mode = true;
                } else if vm_internal_ip.is_none() && !part.starts_with('-') {
                    vm_internal_ip = Some(part.to_string());
                }
            }
            let cmd = ZdsCommand::Add {
                uid: parts[1].to_string(),
                name: parts[2].to_string(),
                namespace: parts[3].to_string(),
                service_account: parts[4].to_string(),
                netns_path,
                vm_internal_ip,
                transparent_proxy,
                vm_iface_mode,
                response: tx,
            };
            if cmd_tx.send(cmd).await.is_err() {
                return "ERROR: Server shutdown".to_string();
            }
            match rx.await {
                Ok(Ok(msg)) => msg,
                Ok(Err(e)) => format!("ERROR: {}", e),
                Err(_) => "ERROR: Channel closed".to_string(),
            }
        }
        "del" => {
            if parts.len() != 2 {
                return "ERROR: Usage: del <uid>".to_string();
            }
            let (tx, rx) = oneshot::channel();
            let cmd = ZdsCommand::Del {
                uid: parts[1].to_string(),
                response: tx,
            };
            if cmd_tx.send(cmd).await.is_err() {
                return "ERROR: Server shutdown".to_string();
            }
            match rx.await {
                Ok(Ok(msg)) => msg,
                Ok(Err(e)) => format!("ERROR: {}", e),
                Err(_) => "ERROR: Channel closed".to_string(),
            }
        }
        "keep" => {
            if parts.len() != 2 {
                return "ERROR: Usage: keep <uid>".to_string();
            }
            let (tx, rx) = oneshot::channel();
            let cmd = ZdsCommand::Keep {
                uid: parts[1].to_string(),
                response: tx,
            };
            if cmd_tx.send(cmd).await.is_err() {
                return "ERROR: Server shutdown".to_string();
            }
            match rx.await {
                Ok(Ok(msg)) => msg,
                Ok(Err(e)) => format!("ERROR: {}", e),
                Err(_) => "ERROR: Channel closed".to_string(),
            }
        }
        "snapshot" => {
            let (tx, rx) = oneshot::channel();
            let cmd = ZdsCommand::Snapshot { response: tx };
            if cmd_tx.send(cmd).await.is_err() {
                return "ERROR: Server shutdown".to_string();
            }
            match rx.await {
                Ok(Ok(msg)) => msg,
                Ok(Err(e)) => format!("ERROR: {}", e),
                Err(_) => "ERROR: Channel closed".to_string(),
            }
        }
        "status" => {
            let (tx, rx) = oneshot::channel();
            let cmd = ZdsCommand::Status { response: tx };
            if cmd_tx.send(cmd).await.is_err() {
                return "ERROR: Server shutdown".to_string();
            }
            match rx.await {
                Ok(Ok(msg)) => msg,
                Ok(Err(e)) => format!("ERROR: {}", e),
                Err(_) => "ERROR: Channel closed".to_string(),
            }
        }
        "help" => {
            "ZDS Commands: add <uid> <name> <ns> <sa> <netns>, del <uid>, keep <uid>, snapshot, status\nWDS Commands: wds-add <uid> <name> <ns> <sa> <ip>[,<ip>...] [proto] [node], wds-del <uid>, wds-list, wds-get <uid>".to_string()
        }
        _ => {
            format!("ERROR: Unknown command: {}. Use 'help' for commands.", parts[0])
        }
    }
}
