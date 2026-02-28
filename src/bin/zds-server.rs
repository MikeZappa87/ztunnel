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
    self, AddressFamily, MsgFlags, SockFlag, SockType, UnixAddr,
    bind as nixbind, listen, socket as nix_socket,
};
use prost::Message;
use std::collections::HashMap;
use std::fs::File;
use std::io::{IoSlice, IoSliceMut};
use std::net::{IpAddr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, RwLock, broadcast};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};

use ztunnel::inpod::istio::zds::{
    Ack, AddWorkload, DelWorkload, KeepWorkload, SnapshotSent, WorkloadInfo, 
    WorkloadRequest, WorkloadResponse, ZdsHello,
    workload_request::Payload,
    workload_response::Payload as ResponsePayload,
};

// XDS types
use ztunnel::xds::service::discovery::v3::{
    DeltaDiscoveryRequest, DeltaDiscoveryResponse, Resource,
    aggregated_discovery_service_server::{AggregatedDiscoveryService, AggregatedDiscoveryServiceServer},
};
use ztunnel::xds::istio::workload::{
    Address as XdsAddress, Workload as XdsWorkload, TunnelProtocol, WorkloadStatus, WorkloadType,
    address::Type as AddressType,
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
    xds_socket: Option<PathBuf>,  // If set, use UDS instead of TCP
    xds_port: u16,
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
        self.inner.write().await.workloads.insert(uid, workload.clone());
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
        self.inner.read().await.workloads.values().cloned().collect()
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
"#
    );
}

fn parse_args() -> Result<Args> {
    let mut args = std::env::args().skip(1).peekable();
    let mut zds_socket = PathBuf::from(DEFAULT_ZDS_SOCKET);
    let mut control_socket = PathBuf::from(DEFAULT_CONTROL_SOCKET);
    let mut xds_socket: Option<PathBuf> = None;
    let mut xds_port = DEFAULT_XDS_PORT;

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
                xds_port = args.next()
                    .ok_or_else(|| anyhow!("--xds-port requires a port number"))?
                    .parse()
                    .context("--xds-port must be a valid port number")?;
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
        self.connections.insert(id, ZdsConnection {
            id,
            fd,
            connected: true,
        });
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
            let msg = socket::recvmsg::<()>(
                self.fd.as_raw_fd(),
                &mut iov,
                None,
                MsgFlags::empty(),
            ).context("Failed to receive hello")?;
            msg.bytes
        };
        
        let hello = ZdsHello::decode(&buf[..bytes])
            .context("Failed to decode hello")?;
        
        eprintln!("[ZDS] Received hello from ztunnel, version={}", hello.version);
        Ok(())
    }

    fn recv_ack(&self) -> Result<Ack> {
        let mut buf = [0u8; 4096];
        let bytes = {
            let mut iov = [IoSliceMut::new(&mut buf)];
            let msg = socket::recvmsg::<()>(
                self.fd.as_raw_fd(),
                &mut iov,
                None,
                MsgFlags::empty(),
            ).context("Failed to receive ack")?;
            msg.bytes
        };

        let response = WorkloadResponse::decode(&buf[..bytes])
            .context("Failed to decode response")?;

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

        let addresses: Vec<prost::bytes::Bytes> = workload.ips.iter().map(|ip| {
            match ip {
                IpAddr::V4(v4) => prost::bytes::Bytes::from(v4.octets().to_vec()),
                IpAddr::V6(v6) => prost::bytes::Bytes::from(v6.octets().to_vec()),
            }
        }).collect();

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
        let resources: Vec<Resource> = workloads.iter().map(|w| {
            let xds = Self::workload_to_xds(w);
            Resource {
                name: w.uid.clone(),
                resource: Some(prost_types::Any {
                    type_url: ADDRESS_TYPE.to_string(),
                    value: xds.encode_to_vec(),
                }),
                ..Default::default()
            }
        }).collect();

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
            WorkloadUpdate::Remove(uid) => {
                DeltaDiscoveryResponse {
                    type_url: ADDRESS_TYPE.to_string(),
                    removed_resources: vec![uid.clone()],
                    nonce: nonce.to_string(),
                    ..Default::default()
                }
            }
        }
    }
}

type DeltaStream = Pin<Box<dyn tokio_stream::Stream<Item = Result<DeltaDiscoveryResponse, Status>> + Send>>;
type SotWStream = Pin<Box<dyn tokio_stream::Stream<Item = Result<ztunnel::xds::service::discovery::v3::DiscoveryResponse, Status>> + Send>>;

#[tonic::async_trait]
impl AggregatedDiscoveryService for XdsService {
    type StreamAggregatedResourcesStream = SotWStream;
    type DeltaAggregatedResourcesStream = DeltaStream;

    async fn stream_aggregated_resources(
        &self,
        _request: Request<Streaming<ztunnel::xds::service::discovery::v3::DiscoveryRequest>>,
    ) -> Result<Response<Self::StreamAggregatedResourcesStream>, Status> {
        Err(Status::unimplemented("Use DeltaAggregatedResources instead"))
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

            // Wait for initial request and handle multiple subscriptions
            loop {
                match request_stream.message().await {
                    Ok(Some(req)) => {
                        let type_url = req.type_url.clone();
                        eprintln!("[XDS] Received request: type_url={} nonce={}", type_url, req.response_nonce);

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

                            let initial_response = DeltaDiscoveryResponse {
                                type_url: ADDRESS_TYPE.to_string(),
                                resources,
                                nonce,
                                ..Default::default()
                            };

                            eprintln!("[XDS] Sending {} Address resources", initial_response.resources.len());
                            if tx.send(Ok(initial_response)).await.is_err() {
                                return;
                            }
                            sent_address = true;
                        } else if type_url == AUTHORIZATION_TYPE.to_string() && !sent_authorization {
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

                        // Once we've handled both initial subscriptions, break to event loop
                        if sent_address && sent_authorization {
                            break;
                        }
                    }
                    Ok(None) => {
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

    // Spawn control socket handler
    let cmd_tx_clone = cmd_tx.clone();
    let store_clone = workload_store.clone();
    tokio::spawn(async move {
        loop {
            match control_listener.accept().await {
                Ok((stream, _)) => {
                    let tx = cmd_tx_clone.clone();
                    let store = store_clone.clone();
                    tokio::spawn(handle_control_client(stream, tx, store));
                }
                Err(e) => {
                    eprintln!("[Control] Accept error: {}", e);
                }
            }
        }
    });

    // Main loop: wait for ztunnel connection and handle commands
    let mut conn_manager = ZdsConnectionManager::new();

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

                // Get the first available connection for ZDS commands
                // (ZDS Add/Keep commands target a specific workload in its netns)
                let conn_id = *conn_manager.connections.keys().next().unwrap();
                let conn = conn_manager.get(conn_id).unwrap();

                match cmd {
                    ZdsCommand::Add { uid, name, namespace, service_account, netns_path, response } => {
                        let result = (|| {
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
                        let _ = response.send(result);
                    }
                    ZdsCommand::Del { uid, response } => {
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
                let response = handle_control_command(&line.trim(), &cmd_tx, &workload_store).await;
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
) -> String {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.is_empty() {
        return "ERROR: Empty command".to_string();
    }

    match parts[0] {
        // ===== WDS COMMANDS (handled directly, no channel) =====
        "wds-add" => {
            // wds-add <uid> <name> <ns> <sa> <ip> [protocol] [node]
            if parts.len() < 6 {
                return "ERROR: Usage: wds-add <uid> <name> <namespace> <sa> <ip> [protocol] [node]".to_string();
            }
            let protocol = parts.get(6).map(|s| s.to_string()).unwrap_or_else(|| "HBONE".to_string());
            let node = parts.get(7).map(|s| s.to_string()).unwrap_or_else(|| "test-node".to_string());
            let ip = match parts[5].parse::<std::net::IpAddr>() {
                Ok(ip) => ip,
                Err(e) => return format!("ERROR: Invalid IP address: {}", e),
            };
            let workload = StoredWorkload {
                uid: parts[1].to_string(),
                name: parts[2].to_string(),
                namespace: parts[3].to_string(),
                service_account: parts[4].to_string(),
                ips: vec![ip],
                node,
                protocol,
            };
            workload_store.add(workload).await;
            format!("OK: Added workload {}", parts[1])
        }
        "wds-del" => {
            if parts.len() != 2 {
                return "ERROR: Usage: wds-del <uid>".to_string();
            }
            if workload_store.remove(parts[1]).await {
                format!("OK: Removed workload {}", parts[1])
            } else {
                format!("WARN: Workload {} not found", parts[1])
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
            if parts.len() != 6 {
                return "ERROR: Usage: add <uid> <name> <namespace> <service_account> <netns_path>".to_string();
            }
            let (tx, rx) = oneshot::channel();
            let cmd = ZdsCommand::Add {
                uid: parts[1].to_string(),
                name: parts[2].to_string(),
                namespace: parts[3].to_string(),
                service_account: parts[4].to_string(),
                netns_path: PathBuf::from(parts[5]),
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
            "ZDS Commands: add <uid> <name> <ns> <sa> <netns>, del <uid>, keep <uid>, snapshot, status\nWDS Commands: wds-add <uid> <name> <ns> <sa> <ip> [proto] [node], wds-del <uid>, wds-list, wds-get <uid>".to_string()
        }
        _ => {
            format!("ERROR: Unknown command: {}. Use 'help' for commands.", parts[0])
        }
    }
}
