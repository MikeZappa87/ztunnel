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

//! ZDS Client CLI - A test client for ztunnel's ZDS (Ztunnel Data Service) protocol.
//!
//! This tool simulates what Cilium's CNI agent does when sending workload information
//! to ztunnel, including sending network namespace file descriptors via SCM_RIGHTS.
//!
//! Additionally, this tool can generate LOCAL_XDS compatible YAML config files
//! for workload discovery (WDS), allowing complete simulation of the CNI + xDS data flow.

use anyhow::{Context, Result, anyhow, bail};
use nix::sys::socket::{self, AddressFamily, MsgFlags, SockFlag, SockType};
use prost::Message;
use std::collections::HashMap;
use std::fs::File;
use std::io::{IoSlice, IoSliceMut};
use std::net::IpAddr;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::PathBuf;
use std::time::Duration;

// Use the ZDS proto definitions from ztunnel lib
use tokio::runtime::Runtime;
use tokio_stream::StreamExt;
use tonic::transport::{Channel, Uri};
use ztunnel::inpod::istio::zds::{
    Ack, AddWorkload, DelWorkload, SnapshotSent, WorkloadInfo, WorkloadRequest, WorkloadResponse,
    ZdsHello,
};
use ztunnel::state::workload::{HealthStatus, InboundProtocol, Locality, NetworkMode, Workload};
use ztunnel::strng::Strng;
use ztunnel::xds::istio::workload::Address as XdsAddress;
use ztunnel::xds::service::discovery::v3::{
    DeltaDiscoveryRequest, aggregated_discovery_service_client::AggregatedDiscoveryServiceClient,
};
use ztunnel::xds::{ADDRESS_TYPE, LocalConfig, LocalWorkload};

#[derive(Debug)]
struct Args {
    command: Command,
    socket_path: PathBuf,
}

#[derive(Debug)]
enum Command {
    Add {
        uid: String,
        name: String,
        namespace: String,
        service_account: String,
        netns_path: PathBuf,
    },
    Del {
        uid: String,
    },
    Snapshot,
    Interactive,
    /// Generate or update a LOCAL_XDS config file with workload data
    Config {
        subcommand: ConfigSubcommand,
    },
    /// Send command to zds-server via control socket
    Send {
        control_socket: PathBuf,
        command: String,
    },
    /// Query WDS (Workload Discovery Service) from istiod
    Wds {
        subcommand: WdsSubcommand,
    },
    Help,
}

#[derive(Debug)]
enum ConfigSubcommand {
    /// Add a workload entry to the config file
    AddWorkload {
        config_path: PathBuf,
        uid: String,
        name: String,
        namespace: String,
        service_account: String,
        workload_ips: Vec<IpAddr>,
        protocol: String,
        node: Option<String>,
        network: Option<String>,
        services: Vec<(String, u16, u16)>, // (service_name, port, target_port)
    },
    /// Remove a workload from the config file
    RemoveWorkload { config_path: PathBuf, uid: String },
    /// Show the current config
    Show { config_path: PathBuf },
    /// Initialize an empty config file
    Init { config_path: PathBuf },
}

#[derive(Debug)]
enum WdsSubcommand {
    /// List all workloads from istiod
    List {
        /// istiod address (e.g., "localhost:15010" or "istiod.istio-system:15012")
        address: String,
        /// Use TLS (port 15012) vs plaintext (port 15010)
        tls: bool,
        /// Node name for the XDS identify
        node_id: String,
        /// Timeout in seconds for the request
        timeout_secs: u64,
        /// Output format: "table", "json", or "yaml"
        format: String,
        /// Filter by namespace
        namespace: Option<String>,
    },
    /// Get details for a specific workload
    Get {
        address: String,
        tls: bool,
        node_id: String,
        /// Workload UID to look up
        uid: String,
        format: String,
    },
}

fn print_help() {
    eprintln!(
        r#"zds-client - ZDS protocol and local XDS config client for ztunnel

USAGE:
    zds-client [OPTIONS] <COMMAND>

OPTIONS:
    --socket <PATH>   ZDS socket path (default: /var/run/ztunnel/ztunnel.sock)

ZDS COMMANDS (for direct CNI -> ztunnel communication via SEQPACKET):
    add <UID> <NAME> <NAMESPACE> <SERVICE_ACCOUNT> <NETNS_PATH>
        Add a workload to ztunnel with the given network namespace

    del <UID>
        Delete a workload from ztunnel

    snapshot
        Send a snapshot-sent message (signals end of initial sync)

    interactive
        Interactive mode - connect and send commands interactively

CONTROL SOCKET COMMANDS (for zds-server communication):
    send --control-socket <PATH> <COMMAND...>
        Send a command to zds-server via control socket
        
        ZDS Commands (CNI protocol):
            add <uid> <name> <ns> <sa> <netns_path>   Add workload with netns
            del <uid>                                  Delete workload
            keep <uid>                                 Keep workload (during sync)
            snapshot                                   Signal end of sync
            status                                     Get connection status
        
        WDS Commands (XDS workload store):
            wds-add <uid> <name> <ns> <sa> <ip> [proto] [node]   Add to XDS store
            wds-del <uid>                              Remove from XDS store
            wds-list                                   List all XDS workloads
            wds-get <uid>                              Get XDS workload details
        
        Example (ZDS):
            zds-client send --control-socket /var/run/ztunnel/control.sock \
                add pod-123 my-pod default default /run/netns/test
        
        Example (WDS):
            zds-client send --control-socket /var/run/ztunnel/control.sock \
                wds-add "Kubernetes//Pod/demo/nginx" nginx demo default 10.244.1.5 HBONE

CONFIG COMMANDS (for LOCAL_XDS workload discovery):
    config init <CONFIG_PATH>
        Initialize an empty config file

    config show <CONFIG_PATH>
        Show the current config file contents

    config add-workload <CONFIG_PATH> [OPTIONS]
        Add a workload to the config file
        
        Required options:
            --uid <UID>                Unique identifier (e.g., cluster1//v1/Pod/default/my-pod)
            --name <NAME>              Workload name
            --namespace <NAMESPACE>    Kubernetes namespace
            --sa <SERVICE_ACCOUNT>     Service account name
            --ip <IP>                  Workload IP (can be repeated for multiple IPs)
        
        Optional:
            --protocol <PROTOCOL>      HBONE or TCP (default: HBONE)
            --node <NODE>              Node name
            --network <NETWORK>        Network name
            --service <SVC:PORT:TARGET> Service mapping (can be repeated)
                                       e.g., "default/example.com:80:8080"

    config remove-workload <CONFIG_PATH> --uid <UID>
        Remove a workload from the config file

WDS COMMANDS (for Workload Discovery Service via XDS from istiod):
    wds list [OPTIONS]
        List all workloads from istiod via XDS
        
        Options:
            --address <ADDR>       istiod address (default: localhost:15010)
            --tls                  Use TLS (port 15012 typically)
            --node-id <ID>         Node ID for XDS (default: ztunnel~127.0.0.1~test.default~default.svc.cluster.local)
            --timeout <SECS>       Timeout in seconds (default: 10)
            --format <FMT>         Output: table, json, yaml (default: table)
            --namespace <NS>       Filter by namespace
        
        Example:
            zds-client wds list --address istiod.istio-system:15010

    wds get --uid <UID> [OPTIONS]
        Get details for a specific workload
        
        Options:
            --address <ADDR>       istiod address (default: localhost:15010)
            --tls                  Use TLS
            --node-id <ID>         Node ID for XDS 
            --format <FMT>         Output: table, json, yaml (default: yaml)
        
        Example:
            zds-client wds get --uid "Kubernetes//Pod/default/my-pod"

    help
        Print this help message

EXAMPLES:
    # Send ZDS commands to ztunnel
    zds-client --socket /var/run/cilium/ztunnel.sock add \
        "pod-uid-123" "my-pod" "default" "default" "/proc/12345/ns/net"

    # Initialize a local XDS config
    zds-client config init /tmp/workloads.yaml

    # Add a workload to local XDS config
    zds-client config add-workload /tmp/workloads.yaml \
        --uid "cluster1//v1/Pod/default/my-pod" \
        --name "my-pod" \
        --namespace "default" \
        --sa "default" \
        --ip "10.0.0.5" \
        --protocol HBONE \
        --node "node1" \
        --service "default/my-service.default.svc.cluster.local:80:8080"

    # Show config
    zds-client config show /tmp/workloads.yaml

    # List workloads from istiod (plaintext)
    zds-client wds list --address localhost:15010

    # List workloads from istiod (TLS, in-cluster)
    zds-client wds list --address istiod.istio-system:15012 --tls

    # Use with ztunnel:
    # LOCAL_XDS_PATH=/tmp/workloads.yaml ./ztunnel
"#
    );
}

fn parse_args() -> Result<Args> {
    let mut args = std::env::args().skip(1).peekable();
    let mut socket_path = PathBuf::from("/var/run/ztunnel/ztunnel.sock");
    let mut command = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--socket" | "-s" => {
                socket_path = PathBuf::from(
                    args.next()
                        .ok_or_else(|| anyhow!("--socket requires a path"))?,
                );
            }
            "add" => {
                let uid = args.next().ok_or_else(|| anyhow!("add requires UID"))?;
                let name = args.next().ok_or_else(|| anyhow!("add requires NAME"))?;
                let namespace = args
                    .next()
                    .ok_or_else(|| anyhow!("add requires NAMESPACE"))?;
                let service_account = args
                    .next()
                    .ok_or_else(|| anyhow!("add requires SERVICE_ACCOUNT"))?;
                let netns_path = PathBuf::from(
                    args.next()
                        .ok_or_else(|| anyhow!("add requires NETNS_PATH"))?,
                );
                command = Some(Command::Add {
                    uid,
                    name,
                    namespace,
                    service_account,
                    netns_path,
                });
            }
            "del" => {
                let uid = args.next().ok_or_else(|| anyhow!("del requires UID"))?;
                command = Some(Command::Del { uid });
            }
            "snapshot" => {
                command = Some(Command::Snapshot);
            }
            "interactive" => {
                command = Some(Command::Interactive);
            }
            "config" => {
                command = Some(parse_config_command(&mut args)?);
            }
            "send" => {
                command = Some(parse_send_command(&mut args)?);
            }
            "wds" => {
                command = Some(parse_wds_command(&mut args)?);
            }
            "help" | "--help" | "-h" => {
                command = Some(Command::Help);
            }
            unknown => {
                bail!("Unknown argument: {}", unknown);
            }
        }
    }

    Ok(Args {
        command: command.unwrap_or(Command::Help),
        socket_path,
    })
}

fn parse_config_command<I>(args: &mut std::iter::Peekable<I>) -> Result<Command>
where
    I: Iterator<Item = String>,
{
    let subcommand = args
        .next()
        .ok_or_else(|| anyhow!("config requires a subcommand"))?;

    match subcommand.as_str() {
        "init" => {
            let config_path = PathBuf::from(
                args.next()
                    .ok_or_else(|| anyhow!("config init requires CONFIG_PATH"))?,
            );
            Ok(Command::Config {
                subcommand: ConfigSubcommand::Init { config_path },
            })
        }
        "show" => {
            let config_path = PathBuf::from(
                args.next()
                    .ok_or_else(|| anyhow!("config show requires CONFIG_PATH"))?,
            );
            Ok(Command::Config {
                subcommand: ConfigSubcommand::Show { config_path },
            })
        }
        "add-workload" => {
            let config_path = PathBuf::from(
                args.next()
                    .ok_or_else(|| anyhow!("config add-workload requires CONFIG_PATH"))?,
            );

            // Parse options
            let mut uid = None;
            let mut name = None;
            let mut namespace = None;
            let mut service_account = None;
            let mut workload_ips = Vec::new();
            let mut protocol = "HBONE".to_string();
            let mut node = None;
            let mut network = None;
            let mut services = Vec::new();

            while let Some(opt) = args.next() {
                match opt.as_str() {
                    "--uid" => {
                        uid = Some(
                            args.next()
                                .ok_or_else(|| anyhow!("--uid requires a value"))?,
                        )
                    }
                    "--name" => {
                        name = Some(
                            args.next()
                                .ok_or_else(|| anyhow!("--name requires a value"))?,
                        )
                    }
                    "--namespace" | "--ns" => {
                        namespace = Some(
                            args.next()
                                .ok_or_else(|| anyhow!("--namespace requires a value"))?,
                        )
                    }
                    "--sa" | "--service-account" => {
                        service_account = Some(
                            args.next()
                                .ok_or_else(|| anyhow!("--sa requires a value"))?,
                        )
                    }
                    "--ip" => {
                        let ip_str = args
                            .next()
                            .ok_or_else(|| anyhow!("--ip requires a value"))?;
                        let ip: IpAddr = ip_str.parse().context("Invalid IP address")?;
                        workload_ips.push(ip);
                    }
                    "--protocol" => {
                        protocol = args
                            .next()
                            .ok_or_else(|| anyhow!("--protocol requires a value"))?
                    }
                    "--node" => {
                        node = Some(
                            args.next()
                                .ok_or_else(|| anyhow!("--node requires a value"))?,
                        )
                    }
                    "--network" => {
                        network = Some(
                            args.next()
                                .ok_or_else(|| anyhow!("--network requires a value"))?,
                        )
                    }
                    "--service" => {
                        let svc_str = args
                            .next()
                            .ok_or_else(|| anyhow!("--service requires a value"))?;
                        let parts: Vec<&str> = svc_str.split(':').collect();
                        if parts.len() != 3 {
                            bail!("--service format: SERVICE_NAME:PORT:TARGET_PORT");
                        }
                        let port: u16 = parts[1].parse().context("Invalid port")?;
                        let target_port: u16 = parts[2].parse().context("Invalid target port")?;
                        services.push((parts[0].to_string(), port, target_port));
                    }
                    _ => bail!("Unknown option: {}", opt),
                }
            }

            let uid = uid.ok_or_else(|| anyhow!("--uid is required"))?;
            let name = name.ok_or_else(|| anyhow!("--name is required"))?;
            let namespace = namespace.ok_or_else(|| anyhow!("--namespace is required"))?;
            let service_account = service_account.ok_or_else(|| anyhow!("--sa is required"))?;

            if workload_ips.is_empty() {
                bail!("At least one --ip is required");
            }

            Ok(Command::Config {
                subcommand: ConfigSubcommand::AddWorkload {
                    config_path,
                    uid,
                    name,
                    namespace,
                    service_account,
                    workload_ips,
                    protocol,
                    node,
                    network,
                    services,
                },
            })
        }
        "remove-workload" => {
            let config_path = PathBuf::from(
                args.next()
                    .ok_or_else(|| anyhow!("config remove-workload requires CONFIG_PATH"))?,
            );

            let mut uid = None;
            while let Some(opt) = args.next() {
                match opt.as_str() {
                    "--uid" => {
                        uid = Some(
                            args.next()
                                .ok_or_else(|| anyhow!("--uid requires a value"))?,
                        )
                    }
                    _ => bail!("Unknown option: {}", opt),
                }
            }

            let uid = uid.ok_or_else(|| anyhow!("--uid is required"))?;

            Ok(Command::Config {
                subcommand: ConfigSubcommand::RemoveWorkload { config_path, uid },
            })
        }
        _ => bail!("Unknown config subcommand: {}", subcommand),
    }
}

fn parse_send_command<I>(args: &mut std::iter::Peekable<I>) -> Result<Command>
where
    I: Iterator<Item = String>,
{
    let mut control_socket = PathBuf::from("/var/run/ztunnel/control.sock");
    let mut command_parts = Vec::new();

    while let Some(opt) = args.next() {
        match opt.as_str() {
            "--control-socket" | "-c" => {
                control_socket = PathBuf::from(
                    args.next()
                        .ok_or_else(|| anyhow!("--control-socket requires a path"))?,
                );
            }
            _ => {
                // Everything else is part of the command
                command_parts.push(opt);
                // Collect remaining args
                while let Some(arg) = args.next() {
                    command_parts.push(arg);
                }
                break;
            }
        }
    }

    if command_parts.is_empty() {
        bail!("send requires a command. Use 'zds-client send --help' for usage.");
    }

    let command = command_parts.join(" ");

    Ok(Command::Send {
        control_socket,
        command,
    })
}

fn parse_wds_command<I>(args: &mut std::iter::Peekable<I>) -> Result<Command>
where
    I: Iterator<Item = String>,
{
    let subcommand = args
        .next()
        .ok_or_else(|| anyhow!("wds requires a subcommand (list, get)"))?;

    match subcommand.as_str() {
        "list" => {
            let mut address = "localhost:15010".to_string();
            let mut tls = false;
            let mut node_id =
                "ztunnel~127.0.0.1~test.default~default.svc.cluster.local".to_string();
            let mut timeout_secs = 10u64;
            let mut format = "table".to_string();
            let mut namespace: Option<String> = None;

            while let Some(opt) = args.next() {
                match opt.as_str() {
                    "--address" | "-a" => {
                        address = args
                            .next()
                            .ok_or_else(|| anyhow!("--address requires a value"))?;
                    }
                    "--tls" => {
                        tls = true;
                    }
                    "--node-id" => {
                        node_id = args
                            .next()
                            .ok_or_else(|| anyhow!("--node-id requires a value"))?;
                    }
                    "--timeout" => {
                        timeout_secs = args
                            .next()
                            .ok_or_else(|| anyhow!("--timeout requires a value"))?
                            .parse()
                            .context("--timeout must be a number")?;
                    }
                    "--format" | "-f" => {
                        format = args
                            .next()
                            .ok_or_else(|| anyhow!("--format requires a value"))?;
                    }
                    "--namespace" | "--ns" => {
                        namespace = Some(
                            args.next()
                                .ok_or_else(|| anyhow!("--namespace requires a value"))?,
                        );
                    }
                    _ => bail!("Unknown option for wds list: {}", opt),
                }
            }

            Ok(Command::Wds {
                subcommand: WdsSubcommand::List {
                    address,
                    tls,
                    node_id,
                    timeout_secs,
                    format,
                    namespace,
                },
            })
        }
        "get" => {
            let mut address = "localhost:15010".to_string();
            let mut tls = false;
            let mut node_id =
                "ztunnel~127.0.0.1~test.default~default.svc.cluster.local".to_string();
            let mut format = "yaml".to_string();
            let mut uid: Option<String> = None;

            while let Some(opt) = args.next() {
                match opt.as_str() {
                    "--address" | "-a" => {
                        address = args
                            .next()
                            .ok_or_else(|| anyhow!("--address requires a value"))?;
                    }
                    "--tls" => {
                        tls = true;
                    }
                    "--node-id" => {
                        node_id = args
                            .next()
                            .ok_or_else(|| anyhow!("--node-id requires a value"))?;
                    }
                    "--format" | "-f" => {
                        format = args
                            .next()
                            .ok_or_else(|| anyhow!("--format requires a value"))?;
                    }
                    "--uid" => {
                        uid = Some(
                            args.next()
                                .ok_or_else(|| anyhow!("--uid requires a value"))?,
                        );
                    }
                    _ => bail!("Unknown option for wds get: {}", opt),
                }
            }

            let uid = uid.ok_or_else(|| anyhow!("--uid is required for wds get"))?;

            Ok(Command::Wds {
                subcommand: WdsSubcommand::Get {
                    address,
                    tls,
                    node_id,
                    uid,
                    format,
                },
            })
        }
        _ => bail!(
            "Unknown wds subcommand: {}. Use 'list' or 'get'.",
            subcommand
        ),
    }
}

struct ZdsClient {
    fd: OwnedFd,
}

impl ZdsClient {
    fn connect(socket_path: &PathBuf) -> Result<Self> {
        eprintln!("Connecting to ZDS socket: {:?}", socket_path);

        // Create a Unix seqpacket socket
        let fd = socket::socket(
            AddressFamily::Unix,
            SockType::SeqPacket,
            SockFlag::SOCK_CLOEXEC,
            None,
        )
        .context("Failed to create socket")?;

        let addr = socket::UnixAddr::new(socket_path).context("Invalid socket path")?;
        socket::connect(fd.as_raw_fd(), &addr).context("Failed to connect to ZDS socket")?;

        eprintln!("Connected!");
        Ok(ZdsClient { fd })
    }

    fn recv_hello(&self) -> Result<ZdsHello> {
        let mut buf = vec![0u8; 1024];
        let bytes = {
            let mut iov = [IoSliceMut::new(&mut buf)];
            let msg = socket::recvmsg::<()>(self.fd.as_raw_fd(), &mut iov, None, MsgFlags::empty())
                .context("Failed to receive hello")?;
            msg.bytes
        };

        let hello = ZdsHello::decode(&buf[..bytes]).context("Failed to decode hello")?;
        eprintln!("Received hello: version={:?}", hello.version);
        Ok(hello)
    }

    fn recv_ack(&self) -> Result<Ack> {
        let mut buf = vec![0u8; 1024];
        let bytes = {
            let mut iov = [IoSliceMut::new(&mut buf)];
            let msg = socket::recvmsg::<()>(self.fd.as_raw_fd(), &mut iov, None, MsgFlags::empty())
                .context("Failed to receive ack")?;
            msg.bytes
        };

        let response =
            WorkloadResponse::decode(&buf[..bytes]).context("Failed to decode response")?;

        match response.payload {
            Some(ztunnel::inpod::istio::zds::workload_response::Payload::Ack(ack)) => {
                if ack.error.is_empty() {
                    eprintln!("Received ACK (success)");
                } else {
                    eprintln!("Received NACK: {}", ack.error);
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
    ) -> Result<()> {
        eprintln!(
            "Sending AddWorkload: uid={}, name={}, namespace={}, sa={}",
            uid, name, namespace, service_account
        );

        let request = WorkloadRequest {
            payload: Some(ztunnel::inpod::istio::zds::workload_request::Payload::Add(
                AddWorkload {
                    uid: uid.to_string(),
                    workload_info: Some(WorkloadInfo {
                        name: name.to_string(),
                        namespace: namespace.to_string(),
                        service_account: service_account.to_string(),
                    }),
                },
            )),
        };

        let data = request.encode_to_vec();
        let iov = [IoSlice::new(&data)];

        // Send with SCM_RIGHTS to pass the netns file descriptor
        let fds = [netns_fd];
        let cmsg = [socket::ControlMessage::ScmRights(&fds)];

        socket::sendmsg::<()>(self.fd.as_raw_fd(), &iov, &cmsg, MsgFlags::empty(), None)
            .context("Failed to send AddWorkload")?;

        eprintln!("Sent AddWorkload with netns fd={}", netns_fd);
        Ok(())
    }

    fn send_del_workload(&self, uid: &str) -> Result<()> {
        eprintln!("Sending DelWorkload: uid={}", uid);

        let request = WorkloadRequest {
            payload: Some(ztunnel::inpod::istio::zds::workload_request::Payload::Del(
                DelWorkload {
                    uid: uid.to_string(),
                },
            )),
        };

        let data = request.encode_to_vec();
        let iov = [IoSlice::new(&data)];

        socket::sendmsg::<()>(self.fd.as_raw_fd(), &iov, &[], MsgFlags::empty(), None)
            .context("Failed to send DelWorkload")?;

        eprintln!("Sent DelWorkload");
        Ok(())
    }

    fn send_snapshot_sent(&self) -> Result<()> {
        eprintln!("Sending SnapshotSent");

        let request = WorkloadRequest {
            payload: Some(
                ztunnel::inpod::istio::zds::workload_request::Payload::SnapshotSent(
                    SnapshotSent {},
                ),
            ),
        };

        let data = request.encode_to_vec();
        let iov = [IoSlice::new(&data)];

        socket::sendmsg::<()>(self.fd.as_raw_fd(), &iov, &[], MsgFlags::empty(), None)
            .context("Failed to send SnapshotSent")?;

        eprintln!("Sent SnapshotSent");
        Ok(())
    }
}

fn run_interactive(client: &ZdsClient) -> Result<()> {
    use std::io::{BufRead, Write};

    println!("ZDS Client Interactive Mode");
    println!("Commands:");
    println!("  add <uid> <name> <namespace> <service_account> <netns_path>");
    println!("  del <uid>");
    println!("  snapshot");
    println!("  quit");
    println!();

    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();

    loop {
        print!("> ");
        stdout.flush()?;

        let mut line = String::new();
        if stdin.lock().read_line(&mut line)? == 0 {
            break;
        }

        let parts: Vec<&str> = line.trim().split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        match parts[0] {
            "add" => {
                if parts.len() != 6 {
                    eprintln!("Usage: add <uid> <name> <namespace> <service_account> <netns_path>");
                    continue;
                }
                let netns_file = File::open(parts[5]).context("Failed to open netns file")?;
                client.send_add_workload(
                    parts[1],
                    parts[2],
                    parts[3],
                    parts[4],
                    netns_file.as_raw_fd(),
                )?;
                client.recv_ack()?;
            }
            "del" => {
                if parts.len() != 2 {
                    eprintln!("Usage: del <uid>");
                    continue;
                }
                client.send_del_workload(parts[1])?;
                client.recv_ack()?;
            }
            "snapshot" => {
                client.send_snapshot_sent()?;
                client.recv_ack()?;
            }
            "quit" | "exit" => {
                break;
            }
            _ => {
                eprintln!("Unknown command: {}", parts[0]);
            }
        }
    }

    Ok(())
}

// ============================================================================
// Config Management Functions (for LOCAL_XDS)
// ============================================================================

fn load_config(path: &PathBuf) -> Result<LocalConfig> {
    if path.exists() {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {:?}", path))?;
        serde_yaml::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {:?}", path))
    } else {
        Ok(LocalConfig::default())
    }
}

fn save_config(path: &PathBuf, config: &LocalConfig) -> Result<()> {
    let content = serde_yaml::to_string(config).context("Failed to serialize config")?;
    std::fs::write(path, content)
        .with_context(|| format!("Failed to write config file: {:?}", path))
}

fn run_config_init(config_path: &PathBuf) -> Result<()> {
    if config_path.exists() {
        bail!("Config file already exists: {:?}", config_path);
    }

    let config = LocalConfig::default();
    save_config(config_path, &config)?;
    eprintln!("Initialized empty config at {:?}", config_path);
    Ok(())
}

fn run_config_show(config_path: &PathBuf) -> Result<()> {
    let config = load_config(config_path)?;
    let content = serde_yaml::to_string(&config).context("Failed to serialize config")?;
    println!("{}", content);
    Ok(())
}

fn run_config_add_workload(
    config_path: &PathBuf,
    uid: String,
    name: String,
    namespace: String,
    service_account: String,
    workload_ips: Vec<IpAddr>,
    protocol: String,
    node: Option<String>,
    network: Option<String>,
    services: Vec<(String, u16, u16)>,
) -> Result<()> {
    let mut config = load_config(config_path)?;

    // Check if workload already exists
    if config
        .workloads
        .iter()
        .any(|w| w.workload.uid.as_str() == uid)
    {
        bail!("Workload with uid '{}' already exists", uid);
    }

    // Parse protocol
    let inbound_protocol = match protocol.to_uppercase().as_str() {
        "HBONE" => InboundProtocol::HBONE,
        "TCP" => InboundProtocol::TCP,
        _ => bail!("Invalid protocol: {}. Use HBONE or TCP", protocol),
    };

    // Build services map
    let services_map: HashMap<String, HashMap<u16, u16>> = services
        .into_iter()
        .map(|(svc_name, port, target_port)| {
            let mut port_map = HashMap::new();
            port_map.insert(port, target_port);
            (svc_name, port_map)
        })
        .fold(HashMap::new(), |mut acc, (svc_name, port_map)| {
            acc.entry(svc_name)
                .or_insert_with(HashMap::new)
                .extend(port_map);
            acc
        });

    // Create workload with all fields explicitly set
    let workload = Workload {
        workload_ips,
        waypoint: None,
        network_gateway: None,
        protocol: inbound_protocol,
        network_mode: NetworkMode::Standard,
        uid: Strng::from(uid.as_str()),
        name: Strng::from(name.as_str()),
        namespace: Strng::from(namespace.as_str()),
        trust_domain: Strng::default(),
        service_account: Strng::from(service_account.as_str()),
        network: Strng::from(network.unwrap_or_default().as_str()),
        workload_name: Strng::default(),
        workload_type: Strng::default(),
        canonical_name: Strng::default(),
        canonical_revision: Strng::default(),
        hostname: Strng::default(),
        node: Strng::from(node.unwrap_or_default().as_str()),
        native_tunnel: false,
        application_tunnel: None,
        authorization_policies: Vec::new(),
        status: HealthStatus::Healthy,
        cluster_id: Strng::default(),
        locality: Locality::default(),
        services: Vec::new(),
        capacity: 1,
    };

    let local_workload = LocalWorkload {
        workload,
        services: services_map,
    };

    config.workloads.push(local_workload);
    save_config(config_path, &config)?;

    eprintln!("Added workload '{}' to {:?}", uid, config_path);
    Ok(())
}

fn run_config_remove_workload(config_path: &PathBuf, uid: &str) -> Result<()> {
    let mut config = load_config(config_path)?;

    let original_len = config.workloads.len();
    config.workloads.retain(|w| w.workload.uid.as_str() != uid);

    if config.workloads.len() == original_len {
        bail!("Workload with uid '{}' not found", uid);
    }

    save_config(config_path, &config)?;
    eprintln!("Removed workload '{}' from {:?}", uid, config_path);
    Ok(())
}

fn run_send_command(control_socket: &PathBuf, command: &str) -> Result<()> {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;

    eprintln!("Connecting to control socket: {:?}", control_socket);

    let mut stream = UnixStream::connect(control_socket)
        .with_context(|| format!("Failed to connect to control socket: {:?}", control_socket))?;

    eprintln!("Connected! Sending: {}", command);

    // Send the command
    writeln!(stream, "{}", command).context("Failed to send command")?;
    stream.flush()?;

    // Read response
    let mut reader = BufReader::new(&stream);
    let mut response = String::new();
    reader
        .read_line(&mut response)
        .context("Failed to read response")?;

    let response = response.trim();
    if response.starts_with("ERROR:") {
        eprintln!("{}", response);
        std::process::exit(1);
    } else {
        println!("{}", response);
    }

    Ok(())
}

// ============================================================================
// WDS (Workload Discovery Service) Functions
// ============================================================================

fn run_wds_command(subcommand: WdsSubcommand) -> Result<()> {
    // Create a tokio runtime for async operations
    let rt = Runtime::new().context("Failed to create tokio runtime")?;
    rt.block_on(async {
        match subcommand {
            WdsSubcommand::List {
                address,
                tls,
                node_id,
                timeout_secs,
                format,
                namespace,
            } => {
                run_wds_list(
                    &address,
                    tls,
                    &node_id,
                    timeout_secs,
                    &format,
                    namespace.as_deref(),
                )
                .await
            }
            WdsSubcommand::Get {
                address,
                tls,
                node_id,
                uid,
                format,
            } => run_wds_get(&address, tls, &node_id, &uid, &format).await,
        }
    })
}

async fn create_xds_channel(address: &str, tls: bool) -> Result<Channel> {
    if tls {
        bail!("TLS is not supported in this build. Use plaintext connection (default port 15010)");
    }

    let uri: Uri = format!("http://{}", address)
        .parse()
        .context("Invalid address")?;

    let endpoint = Channel::builder(uri)
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(30));

    endpoint
        .connect()
        .await
        .context("Failed to connect to XDS server")
}

async fn run_wds_list(
    address: &str,
    tls: bool,
    node_id: &str,
    timeout_secs: u64,
    format: &str,
    namespace_filter: Option<&str>,
) -> Result<()> {
    eprintln!("Connecting to istiod at {} (TLS: {})...", address, tls);

    let channel = create_xds_channel(address, tls).await?;
    let mut client = AggregatedDiscoveryServiceClient::new(channel);

    eprintln!("Connected! Subscribing to workload resources...");

    // Create the initial discovery request
    let initial_request = DeltaDiscoveryRequest {
        type_url: ADDRESS_TYPE.to_string(),
        node: Some(ztunnel::xds::service::discovery::v3::Node {
            id: node_id.to_string(),
            ..Default::default()
        }),
        resource_names_subscribe: vec!["*".to_string()], // Subscribe to all
        ..Default::default()
    };

    // Create a stream
    let (tx, rx) = tokio::sync::mpsc::channel(32);
    tx.send(initial_request)
        .await
        .context("Failed to send initial request")?;

    let request_stream = tokio_stream::wrappers::ReceiverStream::new(rx);

    let mut response_stream = client
        .delta_aggregated_resources(request_stream)
        .await
        .context("Failed to start delta stream")?
        .into_inner();

    // Collect workloads with timeout
    let mut workloads: Vec<XdsAddress> = Vec::new();
    let timeout = tokio::time::timeout(Duration::from_secs(timeout_secs), async {
        while let Some(response) = response_stream.next().await {
            match response {
                Ok(resp) => {
                    eprintln!("Received {} resources", resp.resources.len());
                    for resource in &resp.resources {
                        match XdsAddress::decode(
                            resource
                                .resource
                                .as_ref()
                                .map(|r| r.value.as_slice())
                                .unwrap_or(&[]),
                        ) {
                            Ok(addr) => workloads.push(addr),
                            Err(e) => {
                                eprintln!("Failed to decode resource {}: {}", resource.name, e)
                            }
                        }
                    }
                    // After receiving the first batch, we can stop
                    if !resp.resources.is_empty() {
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("Stream error: {}", e);
                    break;
                }
            }
        }
    });

    let _ = timeout.await;

    // Filter by namespace if specified
    let workloads: Vec<_> = workloads
        .into_iter()
        .filter(|addr| {
            if let Some(ns_filter) = namespace_filter {
                match &addr.r#type {
                    Some(ztunnel::xds::istio::workload::address::Type::Workload(w)) => {
                        w.namespace == ns_filter
                    }
                    _ => true,
                }
            } else {
                true
            }
        })
        .collect();

    // Display results
    display_workloads(&workloads, format)?;

    Ok(())
}

async fn run_wds_get(
    address: &str,
    tls: bool,
    node_id: &str,
    uid: &str,
    format: &str,
) -> Result<()> {
    eprintln!("Connecting to istiod at {} (TLS: {})...", address, tls);

    let channel = create_xds_channel(address, tls).await?;
    let mut client = AggregatedDiscoveryServiceClient::new(channel);

    eprintln!("Connected! Requesting workload: {}", uid);

    // Create the discovery request for specific resource
    let initial_request = DeltaDiscoveryRequest {
        type_url: ADDRESS_TYPE.to_string(),
        node: Some(ztunnel::xds::service::discovery::v3::Node {
            id: node_id.to_string(),
            ..Default::default()
        }),
        resource_names_subscribe: vec![uid.to_string()],
        ..Default::default()
    };

    let (tx, rx) = tokio::sync::mpsc::channel(32);
    tx.send(initial_request)
        .await
        .context("Failed to send initial request")?;

    let request_stream = tokio_stream::wrappers::ReceiverStream::new(rx);

    let mut response_stream = client
        .delta_aggregated_resources(request_stream)
        .await
        .context("Failed to start delta stream")?
        .into_inner();

    // Wait for the response
    let timeout = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(response) = response_stream.next().await {
            match response {
                Ok(resp) => {
                    for resource in &resp.resources {
                        if resource.name == uid || resp.resources.len() == 1 {
                            match XdsAddress::decode(
                                resource
                                    .resource
                                    .as_ref()
                                    .map(|r| r.value.as_slice())
                                    .unwrap_or(&[]),
                            ) {
                                Ok(addr) => {
                                    display_workloads(&[addr], format)?;
                                    return Ok(());
                                }
                                Err(e) => return Err(anyhow!("Failed to decode resource: {}", e)),
                            }
                        }
                    }
                    // Check removed resources
                    if resp.removed_resources.contains(&uid.to_string()) {
                        return Err(anyhow!("Workload {} was removed", uid));
                    }
                }
                Err(e) => return Err(anyhow!("Stream error: {}", e)),
            }
        }
        Err(anyhow!("No response received for workload {}", uid))
    });

    match timeout.await {
        Ok(result) => result,
        Err(_) => Err(anyhow!("Timeout waiting for workload {}", uid)),
    }
}

fn display_workloads(addresses: &[XdsAddress], format: &str) -> Result<()> {
    match format {
        "json" => {
            // Convert to JSON-serializable format
            let json_data: Vec<_> = addresses
                .iter()
                .filter_map(|addr| extract_workload_info(addr))
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&json_data).context("Failed to serialize to JSON")?
            );
        }
        "yaml" => {
            let yaml_data: Vec<_> = addresses
                .iter()
                .filter_map(|addr| extract_workload_info(addr))
                .collect();
            println!(
                "{}",
                serde_yaml::to_string(&yaml_data).context("Failed to serialize to YAML")?
            );
        }
        "table" | _ => {
            // Table format
            println!(
                "{:<50} {:<15} {:<15} {:<20} {:<15}",
                "UID", "NAME", "NAMESPACE", "SERVICE_ACCOUNT", "IPS"
            );
            println!("{}", "-".repeat(115));

            for addr in addresses {
                if let Some(info) = extract_workload_info(addr) {
                    let ips_str = info.ips.join(", ");
                    println!(
                        "{:<50} {:<15} {:<15} {:<20} {:<15}",
                        truncate(&info.uid, 50),
                        truncate(&info.name, 15),
                        truncate(&info.namespace, 15),
                        truncate(&info.service_account, 20),
                        truncate(&ips_str, 15)
                    );
                }
            }

            println!(
                "\nTotal: {} workloads",
                addresses
                    .iter()
                    .filter(|a| matches!(
                        &a.r#type,
                        Some(ztunnel::xds::istio::workload::address::Type::Workload(_))
                    ))
                    .count()
            );
        }
    }

    Ok(())
}

#[derive(serde::Serialize)]
struct WorkloadDisplayInfo {
    uid: String,
    name: String,
    namespace: String,
    service_account: String,
    ips: Vec<String>,
    node: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    waypoint: Option<String>,
    protocol: String,
    status: String,
}

fn extract_workload_info(addr: &XdsAddress) -> Option<WorkloadDisplayInfo> {
    match &addr.r#type {
        Some(ztunnel::xds::istio::workload::address::Type::Workload(w)) => {
            let ips: Vec<String> =
                w.addresses
                    .iter()
                    .map(|bytes| match bytes.len() {
                        4 => std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])
                            .to_string(),
                        16 => {
                            let arr: [u8; 16] = <[u8; 16]>::try_from(&bytes[..]).unwrap_or([0; 16]);
                            std::net::Ipv6Addr::from(arr).to_string()
                        }
                        _ => format!("invalid({} bytes)", bytes.len()),
                    })
                    .collect();

            let waypoint = w.waypoint.as_ref().map(|gw| format!("{:?}", gw));

            let protocol = match w.tunnel_protocol() {
                ztunnel::xds::istio::workload::TunnelProtocol::None => "NONE",
                ztunnel::xds::istio::workload::TunnelProtocol::Hbone => "HBONE",
            }
            .to_string();

            let status = match w.status() {
                ztunnel::xds::istio::workload::WorkloadStatus::Healthy => "Healthy",
                ztunnel::xds::istio::workload::WorkloadStatus::Unhealthy => "Unhealthy",
            }
            .to_string();

            Some(WorkloadDisplayInfo {
                uid: w.uid.clone(),
                name: w.name.clone(),
                namespace: w.namespace.clone(),
                service_account: w.service_account.clone(),
                ips,
                node: w.node.clone(),
                waypoint,
                protocol,
                status,
            })
        }
        _ => None,
    }
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}

fn main() -> Result<()> {
    let args = match parse_args() {
        Ok(args) => args,
        Err(e) => {
            eprintln!("Error: {}", e);
            print_help();
            std::process::exit(1);
        }
    };

    match args.command {
        Command::Help => {
            print_help();
            return Ok(());
        }
        Command::Config { subcommand } => {
            // Handle config commands (no ZDS socket needed)
            return match subcommand {
                ConfigSubcommand::Init { config_path } => run_config_init(&config_path),
                ConfigSubcommand::Show { config_path } => run_config_show(&config_path),
                ConfigSubcommand::AddWorkload {
                    config_path,
                    uid,
                    name,
                    namespace,
                    service_account,
                    workload_ips,
                    protocol,
                    node,
                    network,
                    services,
                } => run_config_add_workload(
                    &config_path,
                    uid,
                    name,
                    namespace,
                    service_account,
                    workload_ips,
                    protocol,
                    node,
                    network,
                    services,
                ),
                ConfigSubcommand::RemoveWorkload { config_path, uid } => {
                    run_config_remove_workload(&config_path, &uid)
                }
            };
        }
        Command::Send {
            control_socket,
            command,
        } => {
            return run_send_command(&control_socket, &command);
        }
        Command::Wds { subcommand } => {
            return run_wds_command(subcommand);
        }
        _ => {}
    }

    // ZDS commands require socket connection
    let client = ZdsClient::connect(&args.socket_path)?;

    // Always receive hello first
    client.recv_hello()?;

    match args.command {
        Command::Add {
            uid,
            name,
            namespace,
            service_account,
            netns_path,
        } => {
            let netns_file = File::open(&netns_path)
                .with_context(|| format!("Failed to open netns file: {:?}", netns_path))?;
            client.send_add_workload(
                &uid,
                &name,
                &namespace,
                &service_account,
                netns_file.as_raw_fd(),
            )?;
            client.recv_ack()?;
        }
        Command::Del { uid } => {
            client.send_del_workload(&uid)?;
            client.recv_ack()?;
        }
        Command::Snapshot => {
            client.send_snapshot_sent()?;
            client.recv_ack()?;
        }
        Command::Interactive => {
            run_interactive(&client)?;
        }
        Command::Help | Command::Config { .. } | Command::Send { .. } | Command::Wds { .. } => {
            unreachable!()
        }
    }

    Ok(())
}
