//! `tun` inbound: a userspace TCP/IP stack (smoltcp) running over a virtual
//! TUN device, instead of routing through the host OS's own TCP/IP stack.
//!
//! Both TCP and UDP are implemented. TCP flows work the way a transparent
//! proxy normally does: one dedicated listening socket per new SYN's exact
//! 4-tuple. UDP is connectionless, so instead one smoltcp UDP socket is
//! bound per distinct destination port seen (accepting datagrams from any
//! peer on that port, the way a real kernel UDP socket bound to `0.0.0.0`
//! would), and this module demultiplexes datagrams arriving on it by their
//! source 4-tuple into their own outbound flow -- see [`udp_flow_key`] and
//! [`service_udp`].
//!
//! Device creation and the raw ioctl dance are handled by
//! `smoltcp::phy::TunTapInterface`; everything downstream of that (address
//! assignment, routing, transparent per-flow TCP interception, and bridging
//! each accepted flow into the existing [`crate::outbound::Connector`]) is
//! implemented here.
//!
//! # How new connections are accepted
//!
//! smoltcp's TCP sockets each `listen()` on one specific port; there is no
//! "accept any destination port" primitive. Since a transparent proxy must
//! accept arbitrary destination ports (whatever the local app dialled), this
//! module reads each raw packet off the device itself (bypassing
//! `TunTapInterface`'s own `Device` impl, which does not allow peeking
//! before smoltcp consumes a packet), and for every *new* outbound SYN (a
//! `(src, sport, dst, dport)` 4-tuple not already known) it allocates a
//! fresh listening TCP socket bound to that exact destination port before
//! handing the packet to `Interface::poll`. That socket then accepts
//! exactly that flow and only that flow; a second connection to the same
//! destination port (a different source port) triggers another fresh
//! listening socket the same way.
//!
//! # Bridging to the rest of the proxy
//!
//! smoltcp's `Interface`/`SocketSet`/`TunTapInterface` are not `Send` and
//! are not async; they run their own poll loop on a dedicated OS thread.
//! Once a flow reaches the `Established` state, that thread spawns a normal
//! async task (via a captured `tokio::runtime::Handle`) that calls
//! [`crate::outbound::Connector::connect`] exactly like the SOCKS/HTTP
//! inbounds do, and relays through a small `AsyncRead`/`AsyncWrite` adapter
//! backed by two unbounded channels connecting it back to the thread.

use std::collections::HashMap;
use std::net::IpAddr;
use std::os::fd::{AsRawFd, RawFd};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context as TaskContext, Poll};

use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, Medium};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint, IpProtocol, Ipv4Packet,
    Ipv6Packet, TcpPacket, UdpPacket,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

use crate::config::Tun as TunConfig;
use crate::error::{Error, Result};
use crate::logging::{Level, Logger};
use crate::outbound::{Connector, UdpOutbound};
use crate::tunnel::Target;

/// TCP receive/transmit buffer size per flow.
const SOCKET_BUFFER: usize = 128 * 1024;
/// Number of in-flight datagrams buffered per direction for one UDP-bound
/// port's smoltcp socket (shared by every peer currently using that port).
const UDP_PACKET_SLOTS: usize = 32;
/// Payload bytes buffered per direction for one UDP-bound port's socket.
const UDP_SOCKET_BUFFER: usize = 64 * 1024;
/// Largest single UDP datagram this module will relay.
const MAX_UDP_PAYLOAD: usize = 65_507;
/// Upper bound on how long we wait for device readability before running a
/// `poll()` cycle anyway, so smoltcp's own timers (retransmits, timeouts)
/// keep firing even on an idle device.
const MAX_POLL_WAIT_MS: i32 = 250;

/// Validates the parts of `tun` this module actually implements, starts the
/// userspace stack on a dedicated OS thread, and resolves when it stops
/// (normally only on error). Matches the shape of
/// `inbound::{socks,http}::serve`, so it can be spawned into the same
/// `JoinSet` as the other inbounds.
pub async fn run(config: TunConfig, connector: Connector, logger: Logger) -> Result<()> {
    if !config.auto
        && config
            .include
            .as_ref()
            .is_none_or(|routes| routes.is_empty())
    {
        return Err(Error::Config(
            "tun requires at least one include route when auto is false".to_owned(),
        ));
    }

    let runtime = tokio::runtime::Handle::current();
    let stop = Arc::new(AtomicBool::new(false));
    let _stop_on_drop = StopOnDrop(stop.clone());
    tokio::task::spawn_blocking(move || run_blocking(config, connector, logger, runtime, stop))
        .await
        .map_err(|error| Error::Runtime(format!("tun task failed: {error}")))?
}

/// Cancels the blocking smoltcp loop when its async owner is dropped.
struct StopOnDrop(Arc<AtomicBool>);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

fn run_blocking(
    config: TunConfig,
    connector: Connector,
    logger: Logger,
    runtime: tokio::runtime::Handle,
    stop: Arc<AtomicBool>,
) -> Result<()> {
    let interface_existed = interface_exists(&config.name);
    let device_medium = Medium::Ip;
    let mut device = if let Some(descriptor) = config.descriptor {
        smoltcp::phy::TunTapInterface::from_fd(descriptor, device_medium, config.mtu as usize)
            .map_err(|error| Error::Interface(format!("cannot attach tun descriptor: {error}")))?
    } else {
        smoltcp::phy::TunTapInterface::new(&config.name, device_medium).map_err(|error| {
            Error::Interface(format!("cannot create tun device {}: {error}", config.name))
        })?
    };
    let raw_fd = device.as_raw_fd();

    let _network_cleanup = configure_interface(&config, !interface_existed)?;
    logger.record(Level::Debug, &format!("tun device {} is up", config.name));

    let mut iface_config = IfaceConfig::new(HardwareAddress::Ip);
    iface_config.random_seed = {
        let mut seed = [0_u8; 8];
        let _ = getrandom::fill(&mut seed);
        u64::from_ne_bytes(seed)
    };
    let now = SmolInstant::now();
    let mut iface = Interface::new(iface_config, &mut device, now);
    iface.update_ip_addrs(|addrs| {
        for network in &config.address {
            let _ = addrs.push(to_smol_cidr(*network));
        }
    });
    iface.set_any_ip(true);
    for network in &config.address {
        if let IpAddr::V4(address) = network.addr() {
            let _ = iface.routes_mut().add_default_ipv4_route(address);
            break;
        }
    }

    // Bypass TunTapInterface's own Device impl for actual I/O: we need to
    // peek raw packets ourselves (to detect new SYNs and allocate a
    // listening socket) before smoltcp consumes them, which the built-in
    // impl does not allow.
    set_nonblocking(raw_fd)?;
    let mut peek_device = PeekDevice {
        fd: raw_fd,
        mtu: config.mtu as usize,
        pending: None,
    };

    let mut sockets = SocketSet::new(Vec::new());
    let mut flows: HashMap<FlowKey, Flow> = HashMap::new();
    let mut udp_ports: HashMap<u16, SocketHandle> = HashMap::new();
    let mut udp_flows: HashMap<FlowKey, UdpFlow> = HashMap::new();

    while !stop.load(Ordering::Acquire) {
        let timeout_ms = iface
            .poll_delay(SmolInstant::now(), &sockets)
            .map(|delay| delay.total_millis().min(MAX_POLL_WAIT_MS as u64) as i32)
            .unwrap_or(MAX_POLL_WAIT_MS);
        wait_readable(raw_fd, timeout_ms.max(1));

        if let Some(raw) = read_packet(raw_fd, config.mtu as usize) {
            if let Some(key) = detect_new_syn(&raw)
                && !flows.contains_key(&key)
            {
                let socket = tcp::Socket::new(
                    tcp::SocketBuffer::new(vec![0_u8; SOCKET_BUFFER]),
                    tcp::SocketBuffer::new(vec![0_u8; SOCKET_BUFFER]),
                );
                let mut socket = socket;
                if socket.listen(key.dst_port).is_ok() {
                    let handle = sockets.add(socket);
                    flows.insert(
                        key,
                        Flow {
                            handle,
                            bridge: None,
                        },
                    );
                }
            }
            if let Some(dst_port) = detect_new_udp_port(&raw)
                && !udp_ports.contains_key(&dst_port)
            {
                let socket = udp::Socket::new(
                    udp::PacketBuffer::new(
                        vec![udp::PacketMetadata::EMPTY; UDP_PACKET_SLOTS],
                        vec![0_u8; UDP_SOCKET_BUFFER],
                    ),
                    udp::PacketBuffer::new(
                        vec![udp::PacketMetadata::EMPTY; UDP_PACKET_SLOTS],
                        vec![0_u8; UDP_SOCKET_BUFFER],
                    ),
                );
                let mut socket = socket;
                if socket
                    .bind(IpListenEndpoint {
                        addr: None,
                        port: dst_port,
                    })
                    .is_ok()
                {
                    udp_ports.insert(dst_port, sockets.add(socket));
                }
            }
            peek_device.pending = Some(raw);
        }

        let now = SmolInstant::now();
        iface.poll(now, &mut peek_device, &mut sockets);

        service_flows(&mut sockets, &mut flows, &connector, &runtime, &logger);
        service_udp(
            &mut sockets,
            &udp_ports,
            &mut udp_flows,
            &connector,
            &runtime,
            &logger,
        );
    }

    Ok(())
}

/// One iteration's worth of flow bookkeeping: promote newly established
/// listening sockets to bridged relay tasks, pump bytes for already-bridged
/// flows, and drop closed/abandoned ones.
///
/// `sockets` and `flows` are two independent collections (a `SocketSet` and
/// a `HashMap`), so borrowing one mutably while iterating the other is not
/// a conflict; each loop iteration takes its own short-lived borrow of the
/// one socket it needs via `flow.handle`.
fn service_flows(
    sockets: &mut SocketSet<'static>,
    flows: &mut HashMap<FlowKey, Flow>,
    connector: &Connector,
    runtime: &tokio::runtime::Handle,
    logger: &Logger,
) {
    let mut finished = Vec::new();

    for (key, flow) in flows.iter_mut() {
        let socket = sockets.get_mut::<tcp::Socket>(flow.handle);

        if socket.state() == tcp::State::Closed {
            sockets.remove(flow.handle);
            finished.push(*key);
            continue;
        }

        let Some(bridge) = &mut flow.bridge else {
            // Still listening: bridge it once past the handshake.
            if matches!(socket.state(), tcp::State::Listen | tcp::State::SynReceived) {
                continue;
            }
            logger.record(
                Level::Debug,
                &format!(
                    "tun: flow {key:?} left handshake, state={:?}",
                    socket.state()
                ),
            );
            let (app_to_dest_tx, app_to_dest_rx) = mpsc::unbounded_channel::<Vec<u8>>();
            let (dest_to_app_tx, dest_to_app_rx) = mpsc::unbounded_channel::<Vec<u8>>();
            let target = match Target::ip(key.dst_addr, key.dst_port) {
                Ok(target) => target,
                Err(_) => {
                    socket.abort();
                    continue;
                }
            };
            let connector = connector.clone();
            let logger = logger.clone();
            let debug_target = target.clone();
            runtime.spawn(async move {
                let stream = FlowStream {
                    read_rx: app_to_dest_rx,
                    write_tx: Some(dest_to_app_tx),
                    read_buf: Vec::new(),
                    read_pos: 0,
                };
                logger.record(
                    Level::Debug,
                    &format!("tun: connecting to {debug_target:?}"),
                );
                let outcome = async {
                    let outbound = connector.connect(&target).await?;
                    logger.record(Level::Debug, "tun: connector.connect succeeded, relaying");
                    outbound.relay(stream).await
                }
                .await;
                logger.record(
                    Level::Debug,
                    &format!("tun: relay for {debug_target:?} ended: {outcome:?}"),
                );
            });
            flow.bridge = Some(Bridge {
                app_to_dest: app_to_dest_tx,
                dest_to_app: dest_to_app_rx,
                leftover: Vec::new(),
            });
            continue;
        };

        // App -> destination: drain everything the socket has received.
        while socket.can_recv() {
            let mut chunk = [0_u8; 4096];
            match socket.recv_slice(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(length) => {
                    if bridge.app_to_dest.send(chunk[..length].to_vec()).is_err() {
                        socket.close();
                        break;
                    }
                }
            }
        }

        // Destination -> app: forward the leftover from last time first, then
        // pull more from the channel while there is room in the socket.
        loop {
            if bridge.leftover.is_empty() {
                match bridge.dest_to_app.try_recv() {
                    Ok(chunk) => bridge.leftover = chunk,
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        socket.close();
                        break;
                    }
                }
            }
            if bridge.leftover.is_empty() {
                continue;
            }
            if !socket.can_send() {
                break;
            }
            match socket.send_slice(&bridge.leftover) {
                Ok(sent) if sent > 0 => {
                    bridge.leftover.drain(..sent);
                }
                _ => break,
            }
        }
    }

    for key in finished {
        flows.remove(&key);
    }
}

/// One iteration's worth of UDP demultiplexing: every distinct destination
/// port has exactly one smoltcp socket (bound to `None` address, i.e. any
/// peer may reach it, mirroring a real kernel UDP socket bound to
/// `0.0.0.0`); every distinct 4-tuple seen on it gets its own outbound flow
/// the first time it appears, exactly like a new TCP SYN does. Unlike TCP,
/// there is no handshake or close signal, so a flow starts bridged
/// immediately and only ends when its outbound task exits (the connector
/// failed, or a `Proxy` stream was closed by the remote side).
fn service_udp(
    sockets: &mut SocketSet<'static>,
    udp_ports: &HashMap<u16, SocketHandle>,
    flows: &mut HashMap<FlowKey, UdpFlow>,
    connector: &Connector,
    runtime: &tokio::runtime::Handle,
    logger: &Logger,
) {
    for &handle in udp_ports.values() {
        let socket = sockets.get_mut::<udp::Socket>(handle);
        while socket.can_recv() {
            let Ok((payload, metadata)) = socket.recv() else {
                break;
            };
            let Some(key) = udp_flow_key(handle, udp_ports, &metadata) else {
                continue;
            };
            let payload = payload.to_vec();
            let flow = flows
                .entry(key)
                .or_insert_with(|| spawn_udp_flow(key, connector.clone(), runtime, logger.clone()));
            let _ = flow.app_to_dest.send(payload);
        }
    }

    let mut finished = Vec::new();
    for (key, flow) in flows.iter_mut() {
        let Some(handle) = udp_ports.get(&key.dst_port) else {
            finished.push(*key);
            continue;
        };
        let socket = sockets.get_mut::<udp::Socket>(*handle);
        loop {
            match flow.dest_to_app.try_recv() {
                Ok(payload) => {
                    let meta = udp::UdpMetadata {
                        endpoint: IpEndpoint::new(to_smol_address(key.src_addr), key.src_port),
                        local_address: Some(to_smol_address(key.dst_addr)),
                        meta: smoltcp::phy::PacketMeta::default(),
                    };
                    // Best-effort: a full transmit buffer just drops this
                    // one datagram, the same as it would on a lossy link.
                    let _ = socket.send_slice(&payload, meta);
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    finished.push(*key);
                    break;
                }
            }
        }
    }
    for key in finished {
        flows.remove(&key);
    }
}

/// Derives a UDP flow's 4-tuple from a just-received datagram's metadata:
/// its peer is the source, and the destination is this module's own
/// records (the socket's bound port, joined with the metadata's
/// `local_address` -- the specific local address the datagram actually
/// arrived on, which can vary under `set_any_ip(true)`).
fn udp_flow_key(
    handle: SocketHandle,
    udp_ports: &HashMap<u16, SocketHandle>,
    metadata: &udp::UdpMetadata,
) -> Option<FlowKey> {
    let dst_port = *udp_ports
        .iter()
        .find(|&(_, &value)| value == handle)
        .map(|(port, _)| port)?;
    Some(FlowKey {
        src_addr: from_smol_address(metadata.endpoint.addr),
        src_port: metadata.endpoint.port,
        dst_addr: from_smol_address(metadata.local_address?),
        dst_port,
    })
}

struct UdpFlow {
    app_to_dest: mpsc::UnboundedSender<Vec<u8>>,
    dest_to_app: mpsc::UnboundedReceiver<Vec<u8>>,
}

/// Spawns the async task that owns one UDP flow's outbound connection
/// (direct socket or tunnel `Udp` stream, chosen by the connector's own
/// routing rules) and pumps datagrams between it and the smoltcp-side
/// channels returned here.
fn spawn_udp_flow(
    key: FlowKey,
    connector: Connector,
    runtime: &tokio::runtime::Handle,
    logger: Logger,
) -> UdpFlow {
    let (app_to_dest_tx, mut app_to_dest_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (dest_to_app_tx, dest_to_app_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    runtime.spawn(async move {
        let Ok(target) = Target::ip(key.dst_addr, key.dst_port) else {
            return;
        };
        let debug_target = target.clone();
        let outbound = match connector.connect_udp(&target).await {
            Ok(outbound) => outbound,
            Err(error) => {
                logger.record(
                    Level::Debug,
                    &format!("tun: udp connect to {debug_target:?} failed: {error}"),
                );
                return;
            }
        };
        logger.record(
            Level::Debug,
            &format!("tun: udp flow {key:?} bridged to {debug_target:?}"),
        );
        match outbound {
            UdpOutbound::Direct(socket) => {
                let socket = Arc::new(socket);
                let receiver = {
                    let socket = socket.clone();
                    let dest_to_app_tx = dest_to_app_tx.clone();
                    tokio::spawn(async move {
                        let mut buffer = vec![0_u8; MAX_UDP_PAYLOAD];
                        loop {
                            let Ok(length) = socket.recv(&mut buffer).await else {
                                return;
                            };
                            if dest_to_app_tx.send(buffer[..length].to_vec()).is_err() {
                                return;
                            }
                        }
                    })
                };
                while let Some(payload) = app_to_dest_rx.recv().await {
                    if socket.send(&payload).await.is_err() {
                        break;
                    }
                }
                receiver.abort();
            }
            UdpOutbound::Proxy(mut protected) => {
                loop {
                    tokio::select! {
                        outbound_payload = app_to_dest_rx.recv() => {
                            match outbound_payload {
                                Some(payload) => {
                                    if protected.send(&payload).await.is_err() {
                                        break;
                                    }
                                }
                                None => break,
                            }
                        }
                        inbound = protected.recv() => {
                            match inbound {
                                Ok(Some(payload)) => {
                                    if dest_to_app_tx.send(payload).is_err() {
                                        break;
                                    }
                                }
                                Ok(None) | Err(_) => break,
                            }
                        }
                    }
                }
                let _ = protected.close().await;
            }
        }
    });
    UdpFlow {
        app_to_dest: app_to_dest_tx,
        dest_to_app: dest_to_app_rx,
    }
}

fn to_smol_address(address: IpAddr) -> IpAddress {
    match address {
        IpAddr::V4(address) => IpAddress::Ipv4(address),
        IpAddr::V6(address) => IpAddress::Ipv6(address),
    }
}

fn from_smol_address(address: IpAddress) -> IpAddr {
    match address {
        IpAddress::Ipv4(address) => IpAddr::V4(address),
        IpAddress::Ipv6(address) => IpAddr::V6(address),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
struct FlowKey {
    src_addr: IpAddr,
    src_port: u16,
    dst_addr: IpAddr,
    dst_port: u16,
}

struct Flow {
    handle: smoltcp::iface::SocketHandle,
    /// `None` until the handshake completes; `Some` once bridged to an
    /// async relay task.
    bridge: Option<Bridge>,
}

struct Bridge {
    app_to_dest: mpsc::UnboundedSender<Vec<u8>>,
    dest_to_app: mpsc::UnboundedReceiver<Vec<u8>>,
    /// Bytes already pulled from `dest_to_app` but not yet fully accepted
    /// by the socket's transmit buffer.
    leftover: Vec<u8>,
}

struct FlowStream {
    read_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    write_tx: Option<mpsc::UnboundedSender<Vec<u8>>>,
    read_buf: Vec<u8>,
    read_pos: usize,
}

impl AsyncRead for FlowStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            if self.read_pos < self.read_buf.len() {
                let available = self.read_buf.len() - self.read_pos;
                let take = available.min(buf.remaining());
                buf.put_slice(&self.read_buf[self.read_pos..self.read_pos + take]);
                self.read_pos += take;
                return Poll::Ready(Ok(()));
            }
            match self.read_rx.poll_recv(cx) {
                Poll::Ready(Some(chunk)) => {
                    self.read_buf = chunk;
                    self.read_pos = 0;
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for FlowStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &self.write_tx {
            Some(sender) => match sender.send(buf.to_vec()) {
                Ok(()) => Poll::Ready(Ok(buf.len())),
                Err(_) => Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "tun flow closed",
                ))),
            },
            None => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "tun flow already shut down",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        _cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.write_tx = None;
        Poll::Ready(Ok(()))
    }
}

/// Dedicated routing table for `include` prefixes, kept separate from
/// `main` so a policy rule can steer only *other* processes' traffic into
/// it (see [`crate::outbound::DIRECT_SOCKET_MARK`]).
const ROUTE_TABLE: &str = "7734";
/// Priority for the policy rule that sends unmarked traffic into
/// `ROUTE_TABLE`. Low enough to run before the default rules.
const RULE_PRIORITY: &str = "100";

#[cfg(target_os = "linux")]
const RP_FILTER_PATH: &str = "/proc/sys/net/ipv4/conf/all/rp_filter";

/// Address ranges that most real networks rely on for local link services
/// (mDNS, DHCP, NDP, SSDP...) and would break if silently swallowed by a
/// catch-all tun route. `strict_route: false` (the default) keeps these on
/// the host's normal routing by adding `throw` routes for them ahead of the
/// tun capture; `strict_route: true` omits that carve-out, so the tun
/// device really does see every packet, matching the flag's meaning in
/// other transparent-proxy implementations this config shape is modelled
/// on (e.g. sing-box).
const NON_STRICT_BYPASS_V4: &[&str] = &["224.0.0.0/4", "255.255.255.255/32", "169.254.0.0/16"];
const NON_STRICT_BYPASS_V6: &[&str] = &["ff00::/8", "fe80::/10"];

fn configure_interface(config: &TunConfig, owns_interface: bool) -> Result<NetworkCleanup> {
    let mut cleanup = NetworkCleanup {
        name: config.name.clone(),
        owns_interface,
        addresses: Vec::new(),
        routes: Vec::new(),
        throws: Vec::new(),
        rule: false,
        previous_rp_filter: None,
    };
    run_ip(&["link", "set", &config.name, "up"])?;
    for network in &config.address {
        run_ip(&["addr", "add", &network.to_string(), "dev", &config.name])?;
        cleanup.addresses.push(*network);
    }

    cleanup.previous_rp_filter = ensure_loose_rp_filter()?;

    if config.auto {
        // Capture everything by default: a default route in the
        // tun-specific table for both address families.
        for default in ["0.0.0.0/0", "::/0"] {
            run_ip(&[
                "route",
                "add",
                default,
                "dev",
                &config.name,
                "table",
                ROUTE_TABLE,
            ])?;
            cleanup
                .routes
                .push(default.parse().expect("valid default prefix"));
        }
    } else {
        for network in config.include.as_deref().unwrap_or(&[]) {
            run_ip(&[
                "route",
                "add",
                &network.to_string(),
                "dev",
                &config.name,
                "table",
                ROUTE_TABLE,
            ])?;
            cleanup.routes.push(*network);
        }
    }

    // `throw` routes make the kernel stop searching `ROUTE_TABLE` for a
    // matching prefix and fall through to the next, lower-priority rule
    // (ending up at the host's normal `main` table) -- exactly "exclude
    // this destination from the tun capture".
    if !config.strict_route {
        // `Tun::validate` already requires both address families, so both
        // bypass lists always apply.
        for prefix in NON_STRICT_BYPASS_V4.iter().chain(NON_STRICT_BYPASS_V6) {
            run_ip(&["route", "add", "throw", prefix, "table", ROUTE_TABLE])?;
            cleanup.throws.push((*prefix).to_owned());
        }
    }
    for network in config.exclude.as_deref().unwrap_or(&[]) {
        let prefix = network.to_string();
        run_ip(&["route", "add", "throw", &prefix, "table", ROUTE_TABLE])?;
        cleanup.throws.push(prefix);
    }

    // Only *unmarked* traffic is routed via the tun-specific table.
    // snolc's own direct-outbound sockets carry DIRECT_SOCKET_MARK and
    // therefore fall through to the normal `main` table instead, which
    // is what stops the process from capturing its own connection
    // attempts back into the tun device (an otherwise infinite loop:
    // connect out -> re-intercepted as a new inbound flow -> connect
    // out again).
    run_ip(&[
        "rule",
        "add",
        "not",
        "fwmark",
        &crate::outbound::DIRECT_SOCKET_MARK.to_string(),
        "lookup",
        ROUTE_TABLE,
        "priority",
        RULE_PRIORITY,
    ])?;
    cleanup.rule = true;

    Ok(cleanup)
}

struct NetworkCleanup {
    name: String,
    owns_interface: bool,
    addresses: Vec<ipnet::IpNet>,
    routes: Vec<ipnet::IpNet>,
    throws: Vec<String>,
    rule: bool,
    previous_rp_filter: Option<String>,
}

impl Drop for NetworkCleanup {
    fn drop(&mut self) {
        if self.rule {
            run_ip_quiet(&[
                "rule",
                "del",
                "not",
                "fwmark",
                &crate::outbound::DIRECT_SOCKET_MARK.to_string(),
                "lookup",
                ROUTE_TABLE,
                "priority",
                RULE_PRIORITY,
            ]);
        }
        for prefix in self.throws.iter().rev() {
            run_ip_quiet(&["route", "del", "throw", prefix, "table", ROUTE_TABLE]);
        }
        for network in self.routes.iter().rev() {
            run_ip_quiet(&[
                "route",
                "del",
                &network.to_string(),
                "dev",
                &self.name,
                "table",
                ROUTE_TABLE,
            ]);
        }
        for network in self.addresses.iter().rev() {
            run_ip_quiet(&["addr", "del", &network.to_string(), "dev", &self.name]);
        }
        if self.owns_interface {
            run_ip_quiet(&["link", "del", &self.name]);
        }
        restore_rp_filter(self.previous_rp_filter.take());
    }
}

#[cfg(target_os = "linux")]
fn interface_exists(name: &str) -> bool {
    std::path::Path::new("/sys/class/net").join(name).exists()
}

#[cfg(not(target_os = "linux"))]
fn interface_exists(_name: &str) -> bool {
    false
}

#[cfg(target_os = "linux")]
fn ensure_loose_rp_filter() -> Result<Option<String>> {
    let previous = std::fs::read_to_string(RP_FILTER_PATH)
        .map_err(|error| Error::Interface(format!("cannot read {RP_FILTER_PATH}: {error}")))?;
    if previous.trim() == "2" {
        return Ok(None);
    }
    std::fs::write(RP_FILTER_PATH, "2\n").map_err(|error| {
        Error::Interface(format!("cannot set loose reverse-path filtering: {error}"))
    })?;
    Ok(Some(previous))
}

#[cfg(not(target_os = "linux"))]
fn ensure_loose_rp_filter() -> Result<Option<String>> {
    Ok(None)
}

#[cfg(target_os = "linux")]
fn restore_rp_filter(previous: Option<String>) {
    let Some(previous) = previous else {
        return;
    };
    // Do not overwrite an administrator's concurrent change.
    if std::fs::read_to_string(RP_FILTER_PATH).is_ok_and(|current| current.trim() == "2") {
        let _ = std::fs::write(RP_FILTER_PATH, previous);
    }
}

#[cfg(not(target_os = "linux"))]
fn restore_rp_filter(_previous: Option<String>) {}

fn run_ip(args: &[&str]) -> Result<()> {
    let status = std::process::Command::new("ip")
        .args(args)
        .status()
        .map_err(|error| Error::Interface(format!("cannot run ip {args:?}: {error}")))?;
    if !status.success() {
        return Err(Error::Interface(format!("ip {args:?} failed")));
    }
    Ok(())
}

fn run_ip_quiet(args: &[&str]) {
    let _ = std::process::Command::new("ip")
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

fn to_smol_cidr(network: ipnet::IpNet) -> IpCidr {
    match network.addr() {
        IpAddr::V4(address) => IpCidr::new(IpAddress::Ipv4(address), network.prefix_len()),
        IpAddr::V6(address) => IpCidr::new(IpAddress::Ipv6(address), network.prefix_len()),
    }
}

fn detect_new_syn(raw: &[u8]) -> Option<FlowKey> {
    let version = raw.first()? >> 4;
    let (src_addr, dst_addr, protocol, payload) = match version {
        4 => {
            let packet = Ipv4Packet::new_checked(raw).ok()?;
            if packet.next_header() != IpProtocol::Tcp {
                return None;
            }
            let src = IpAddr::V4(packet.src_addr());
            let dst = IpAddr::V4(packet.dst_addr());
            (src, dst, packet.next_header(), packet.payload().to_vec())
        }
        6 => {
            let packet = Ipv6Packet::new_checked(raw).ok()?;
            if packet.next_header() != IpProtocol::Tcp {
                return None;
            }
            let src = IpAddr::V6(packet.src_addr());
            let dst = IpAddr::V6(packet.dst_addr());
            (src, dst, packet.next_header(), packet.payload().to_vec())
        }
        _ => return None,
    };
    let _ = protocol;
    let tcp = TcpPacket::new_checked(&payload[..]).ok()?;
    if tcp.syn() && !tcp.ack() {
        Some(FlowKey {
            src_addr,
            src_port: tcp.src_port(),
            dst_addr,
            dst_port: tcp.dst_port(),
        })
    } else {
        None
    }
}

/// Extracts the destination port of a UDP packet, so the caller can ensure
/// a listening socket exists for it. Unlike [`detect_new_syn`], every UDP
/// packet is a candidate (there is no handshake flag to filter on); the
/// caller is responsible for treating an already-bound port as a no-op.
fn detect_new_udp_port(raw: &[u8]) -> Option<u16> {
    let version = raw.first()? >> 4;
    let payload = match version {
        4 => {
            let packet = Ipv4Packet::new_checked(raw).ok()?;
            if packet.next_header() != IpProtocol::Udp {
                return None;
            }
            packet.payload().to_vec()
        }
        6 => {
            let packet = Ipv6Packet::new_checked(raw).ok()?;
            if packet.next_header() != IpProtocol::Udp {
                return None;
            }
            packet.payload().to_vec()
        }
        _ => return None,
    };
    let udp = UdpPacket::new_checked(&payload[..]).ok()?;
    Some(udp.dst_port())
}

struct PeekDevice {
    fd: RawFd,
    mtu: usize,
    pending: Option<Vec<u8>>,
}

impl phy::Device for PeekDevice {
    type RxToken<'a> = RawRxToken;
    type TxToken<'a> = RawTxToken;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.pending
            .take()
            .map(|buf| (RawRxToken(buf), RawTxToken(self.fd)))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(RawTxToken(self.fd))
    }

    fn capabilities(&self) -> phy::DeviceCapabilities {
        let mut capabilities = phy::DeviceCapabilities::default();
        capabilities.max_transmission_unit = self.mtu;
        capabilities.medium = Medium::Ip;
        capabilities
    }
}

struct RawRxToken(Vec<u8>);
impl phy::RxToken for RawRxToken {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

struct RawTxToken(RawFd);
impl phy::TxToken for RawTxToken {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buffer = vec![0_u8; len];
        let result = f(&mut buffer);
        // Best-effort: a dropped packet here just means the app retransmits,
        // same as it would over a lossy real link.
        unsafe {
            libc::write(self.0, buffer.as_ptr().cast(), buffer.len());
        }
        result
    }
}

fn set_nonblocking(fd: RawFd) -> Result<()> {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 {
            return Err(Error::Interface("fcntl(F_GETFL) failed".to_owned()));
        }
        if libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(Error::Interface("fcntl(F_SETFL) failed".to_owned()));
        }
    }
    Ok(())
}

fn wait_readable(fd: RawFd, timeout_ms: i32) {
    let mut poll_fd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    unsafe {
        libc::poll(&mut poll_fd, 1, timeout_ms);
    }
}

fn read_packet(fd: RawFd, mtu: usize) -> Option<Vec<u8>> {
    let mut buffer = vec![0_u8; mtu.max(2048)];
    let read = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
    if read > 0 {
        buffer.truncate(read as usize);
        Some(buffer)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use smoltcp::phy::ChecksumCapabilities;
    use smoltcp::wire::{Ipv4Address, Ipv4Repr, TcpControl, TcpRepr, TcpSeqNumber};

    use super::*;

    /// Builds a real, checksum-correct IPv4+TCP packet using smoltcp's own
    /// wire representations, so this test exercises `detect_new_syn`
    /// against exactly the byte layout the real device would deliver.
    fn build_ipv4_tcp(
        src: (u8, u8, u8, u8),
        sport: u16,
        dst: (u8, u8, u8, u8),
        dport: u16,
        syn: bool,
        ack: bool,
    ) -> Vec<u8> {
        let tcp_repr = TcpRepr {
            src_port: sport,
            dst_port: dport,
            control: if syn {
                TcpControl::Syn
            } else {
                TcpControl::None
            },
            seq_number: TcpSeqNumber(0),
            ack_number: if ack { Some(TcpSeqNumber(0)) } else { None },
            window_len: 65535,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            timestamp: None,
            payload: &[],
        };
        let src_addr = Ipv4Address::new(src.0, src.1, src.2, src.3);
        let dst_addr = Ipv4Address::new(dst.0, dst.1, dst.2, dst.3);
        let ip_repr = Ipv4Repr {
            src_addr,
            dst_addr,
            next_header: IpProtocol::Tcp,
            payload_len: tcp_repr.buffer_len(),
            hop_limit: 64,
        };

        let mut buffer = vec![0_u8; ip_repr.buffer_len() + tcp_repr.buffer_len()];
        let mut ip_packet = Ipv4Packet::new_unchecked(&mut buffer[..ip_repr.buffer_len()]);
        ip_repr.emit(&mut ip_packet, &ChecksumCapabilities::default());
        let ip_header_len = ip_repr.buffer_len();
        {
            let mut tcp_packet = TcpPacket::new_unchecked(&mut buffer[ip_header_len..]);
            tcp_repr.emit(
                &mut tcp_packet,
                &src_addr.into(),
                &dst_addr.into(),
                &ChecksumCapabilities::default(),
            );
        }
        buffer
    }

    #[test]
    fn recognizes_a_fresh_outbound_syn() {
        let packet = build_ipv4_tcp((172, 19, 0, 2), 51000, (93, 95, 228, 248), 443, true, false);
        let key = detect_new_syn(&packet).expect("a SYN-only packet must be recognized");
        assert_eq!(key.src_addr, "172.19.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(key.src_port, 51000);
        assert_eq!(key.dst_addr, "93.95.228.248".parse::<IpAddr>().unwrap());
        assert_eq!(key.dst_port, 443);
    }

    #[test]
    fn a_syn_ack_is_not_a_new_connection() {
        let packet = build_ipv4_tcp((172, 19, 0, 2), 51000, (93, 95, 228, 248), 443, true, true);
        assert!(detect_new_syn(&packet).is_none());
    }

    #[test]
    fn a_pure_ack_is_not_a_new_connection() {
        let packet = build_ipv4_tcp((172, 19, 0, 2), 51000, (93, 95, 228, 248), 443, false, true);
        assert!(detect_new_syn(&packet).is_none());
    }

    #[test]
    fn garbage_bytes_are_rejected_without_panicking() {
        assert!(detect_new_syn(&[]).is_none());
        assert!(detect_new_syn(&[0xFF; 4]).is_none());
        assert!(detect_new_syn(&[0x45, 0, 0, 0]).is_none());
    }

    /// Builds a real, checksum-correct IPv4+UDP packet, mirroring
    /// `build_ipv4_tcp` above.
    fn build_ipv4_udp(
        src: (u8, u8, u8, u8),
        sport: u16,
        dst: (u8, u8, u8, u8),
        dport: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        use smoltcp::wire::{UdpPacket, UdpRepr};

        let udp_repr = UdpRepr {
            src_port: sport,
            dst_port: dport,
        };
        let src_addr = Ipv4Address::new(src.0, src.1, src.2, src.3);
        let dst_addr = Ipv4Address::new(dst.0, dst.1, dst.2, dst.3);
        let ip_repr = Ipv4Repr {
            src_addr,
            dst_addr,
            next_header: IpProtocol::Udp,
            payload_len: udp_repr.header_len() + payload.len(),
            hop_limit: 64,
        };

        let mut buffer = vec![0_u8; ip_repr.buffer_len() + udp_repr.header_len() + payload.len()];
        let mut ip_packet = Ipv4Packet::new_unchecked(&mut buffer[..ip_repr.buffer_len()]);
        ip_repr.emit(&mut ip_packet, &ChecksumCapabilities::default());
        let ip_header_len = ip_repr.buffer_len();
        {
            let mut udp_packet = UdpPacket::new_unchecked(&mut buffer[ip_header_len..]);
            udp_repr.emit(
                &mut udp_packet,
                &src_addr.into(),
                &dst_addr.into(),
                payload.len(),
                |data| data.copy_from_slice(payload),
                &ChecksumCapabilities::default(),
            );
        }
        buffer
    }

    #[test]
    fn recognizes_a_udp_packets_destination_port() {
        let packet = build_ipv4_udp((172, 19, 0, 2), 51000, (93, 95, 228, 248), 53, b"query");
        assert_eq!(detect_new_udp_port(&packet), Some(53));
    }

    #[test]
    fn a_tcp_packet_is_not_a_udp_destination_port() {
        let packet = build_ipv4_tcp((172, 19, 0, 2), 51000, (93, 95, 228, 248), 443, true, false);
        assert!(detect_new_udp_port(&packet).is_none());
    }

    #[test]
    fn udp_garbage_bytes_are_rejected_without_panicking() {
        assert!(detect_new_udp_port(&[]).is_none());
        assert!(detect_new_udp_port(&[0xFF; 4]).is_none());
    }
}
