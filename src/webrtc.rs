//! WebRTC carrier backed by real ICE, DTLS, SCTP, and a reliable data
//! channel from `webrtc-rs`.
//!
//! SDP offer/answer signaling uses small retransmitted UDP datagrams on the
//! configured `bind`/`remote` endpoint. ICE itself binds separate ephemeral
//! UDP sockets advertised in SDP; those sockets carry the tunnel after setup.

use std::collections::HashMap;
use std::fmt::Debug;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ::webrtc::data_channel::{DataChannel, DataChannelEvent};
use ::webrtc::peer_connection::{
    PeerConnection, PeerConnectionBuilder, PeerConnectionEventHandler, RTCConfigurationBuilder,
    RTCIceGatheringState, RTCIceServer, RTCPeerConnectionState, RTCSessionDescription,
};
use ::webrtc::runtime::{
    AsyncInterval, AsyncTcpListener, AsyncTcpStream, AsyncUdpSocket, JoinHandle, Runtime,
    TokioRuntime,
};
use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::task::JoinHandle as TokioJoinHandle;

use crate::carrier::BoxedStream;
use crate::error::{Error, Result};
use crate::logging::{Level, Logger};

const DATA_CHANNEL_LABEL: &str = "data";
const DATA_CHUNK: usize = 16 * 1024;
const STREAM_BUFFER: usize = 256 * 1024;
const DATA_CHANNEL_SEND_BUFFER: usize = 4 * 1024 * 1024;
const GATHER_TIMEOUT: Duration = Duration::from_secs(8);
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(20);
const SIGNAL_RETRY: Duration = Duration::from_millis(300);
const SIGNAL_ATTEMPTS: usize = 67;
const SIGNAL_TTL: Duration = Duration::from_secs(60);
const MAX_SEEN_SIGNALS: usize = 4096;
const MAX_SIGNAL_SDP: usize = 60 * 1024;
const SIGNAL_MAGIC: &[u8; 8] = b"SNLCWRTC";
const SIGNAL_OFFER: u8 = 1;
const SIGNAL_ANSWER: u8 = 2;
const SIGNAL_HEADER: usize = SIGNAL_MAGIC.len() + 1 + 16;
const STUN_HEADER: usize = 20;
const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_BINDING_SUCCESS: u16 = 0x0101;
const STUN_MAGIC_COOKIE: u32 = 0x2112_a442;
const STUN_XOR_MAPPED_ADDRESS: u16 = 0x0020;

pub struct Accepted {
    pub stream: BoxedStream,
    pub peer: SocketAddr,
    pub permit: OwnedSemaphorePermit,
}

pub struct Listener {
    address: SocketAddr,
    incoming: mpsc::Receiver<Accepted>,
    task: TokioJoinHandle<()>,
}

impl Listener {
    pub async fn bind(bind: &str, connections: usize, logger: Logger) -> Result<Self> {
        let address = resolve_endpoint(bind).await?;
        let socket = Arc::new(bind_udp(address)?);
        let address = socket.local_addr()?;
        let (incoming_tx, incoming) = mpsc::channel(connections.max(1));
        let semaphore = Arc::new(Semaphore::new(connections));
        let task = tokio::spawn(receive_offers(socket, semaphore, incoming_tx, logger));
        Ok(Self {
            address,
            incoming,
            task,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.address
    }

    pub async fn accept(&mut self) -> Result<Accepted> {
        self.incoming
            .recv()
            .await
            .ok_or_else(|| Error::Carrier("WebRTC signaling listener stopped".to_owned()))
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub async fn connect(remote: &str) -> Result<BoxedStream> {
    let remote = resolve_endpoint(remote).await?;
    let (gather_tx, mut gather_rx) = mpsc::channel(1);
    let (failed_tx, _failed_rx) = mpsc::channel(1);
    let peer = build_peer(
        Events {
            gather_tx,
            failed_tx,
            data_channel_tx: None,
        },
        client_ice_servers(remote),
    )
    .await?;
    let data_channel = peer
        .create_data_channel(DATA_CHANNEL_LABEL, None)
        .await
        .map_err(|error| rtc_error("cannot create data channel", error))?;

    let offer = peer
        .create_offer(None)
        .await
        .map_err(|error| rtc_error("cannot create offer", error))?;
    peer.set_local_description(offer)
        .await
        .map_err(|error| rtc_error("cannot set local offer", error))?;
    let _ = tokio::time::timeout(GATHER_TIMEOUT, gather_rx.recv()).await;
    let offer = peer
        .local_description()
        .await
        .ok_or_else(|| Error::Carrier("WebRTC local offer is missing".to_owned()))?;

    let mut request_id = [0_u8; 16];
    getrandom::fill(&mut request_id)
        .map_err(|error| Error::Carrier(format!("cannot create signaling id: {error}")))?;
    let request = encode_signal(SIGNAL_OFFER, request_id, &offer.sdp)?;
    let socket = bind_udp(if remote.is_ipv4() {
        "0.0.0.0:0".parse().expect("valid IPv4 wildcard")
    } else {
        "[::]:0".parse().expect("valid IPv6 wildcard")
    })?;
    socket.connect(remote).await?;

    let answer = exchange_offer(&socket, request_id, &request).await?;
    let answer = RTCSessionDescription::answer(answer)
        .map_err(|error| rtc_error("invalid answer", error))?;
    peer.set_remote_description(answer)
        .await
        .map_err(|error| rtc_error("cannot set remote answer", error))?;

    wait_for_open(&data_channel).await?;
    Ok(channel_stream(data_channel, peer))
}

async fn receive_offers(
    socket: Arc<UdpSocket>,
    semaphore: Arc<Semaphore>,
    incoming: mpsc::Sender<Accepted>,
    logger: Logger,
) {
    let mut packet = vec![0_u8; u16::MAX as usize];
    let mut seen = HashMap::<[u8; 16], Instant>::new();
    loop {
        let (length, source) = match socket.recv_from(&mut packet).await {
            Ok(received) => received,
            Err(error) => {
                logger.record(
                    Level::Error,
                    &format!("WebRTC signaling receive failed: {error}"),
                );
                return;
            }
        };
        if let Some(response) = stun_binding_response(&packet[..length], source) {
            let _ = socket.send_to(&response, source).await;
            continue;
        }
        let Some((kind, request_id, sdp)) = decode_signal(&packet[..length]) else {
            continue;
        };
        if kind != SIGNAL_OFFER {
            continue;
        }
        seen.retain(|_, created| created.elapsed() < SIGNAL_TTL);
        if seen.contains_key(&request_id) || seen.len() >= MAX_SEEN_SIGNALS {
            continue;
        }
        let Ok(permit) = semaphore.clone().try_acquire_owned() else {
            continue;
        };
        seen.insert(request_id, Instant::now());

        let socket = socket.clone();
        let incoming = incoming.clone();
        let logger = logger.clone();
        tokio::spawn(async move {
            match answer_offer(socket, source, request_id, sdp, permit).await {
                Ok(accepted) => {
                    let _ = incoming.send(accepted).await;
                }
                Err(error) => logger.record(
                    Level::Debug,
                    &format!("WebRTC setup from {source} failed: {error}"),
                ),
            }
        });
    }
}

async fn answer_offer(
    socket: Arc<UdpSocket>,
    source: SocketAddr,
    request_id: [u8; 16],
    offer: String,
    permit: OwnedSemaphorePermit,
) -> Result<Accepted> {
    let (gather_tx, mut gather_rx) = mpsc::channel(1);
    let (failed_tx, mut failed_rx) = mpsc::channel(1);
    let (data_channel_tx, mut data_channel_rx) = mpsc::channel(1);
    let peer = build_peer(
        Events {
            gather_tx,
            failed_tx,
            data_channel_tx: Some(data_channel_tx),
        },
        server_ice_servers(),
    )
    .await?;

    let offer =
        RTCSessionDescription::offer(offer).map_err(|error| rtc_error("invalid offer", error))?;
    peer.set_remote_description(offer)
        .await
        .map_err(|error| rtc_error("cannot set remote offer", error))?;
    let answer = peer
        .create_answer(None)
        .await
        .map_err(|error| rtc_error("cannot create answer", error))?;
    peer.set_local_description(answer)
        .await
        .map_err(|error| rtc_error("cannot set local answer", error))?;
    let _ = tokio::time::timeout(GATHER_TIMEOUT, gather_rx.recv()).await;
    let answer = peer
        .local_description()
        .await
        .ok_or_else(|| Error::Carrier("WebRTC local answer is missing".to_owned()))?;
    let response = encode_signal(SIGNAL_ANSWER, request_id, &answer.sdp)?;

    let answer_socket = socket.clone();
    let sender = tokio::spawn(async move {
        for _ in 0..SIGNAL_ATTEMPTS {
            if answer_socket.send_to(&response, source).await.is_err() {
                break;
            }
            tokio::time::sleep(SIGNAL_RETRY).await;
        }
    });
    let channel = tokio::time::timeout(CONNECTION_TIMEOUT, async {
        tokio::select! {
            channel = data_channel_rx.recv() => channel,
            _ = failed_rx.recv() => None,
        }
    })
    .await
    .ok()
    .flatten();
    sender.abort();
    let channel = channel.ok_or_else(|| {
        Error::Carrier("WebRTC connection failed before opening a data channel".to_owned())
    })?;
    if channel
        .label()
        .await
        .map_err(|error| rtc_error("cannot read data channel label", error))?
        != DATA_CHANNEL_LABEL
    {
        return Err(Error::Carrier(
            "WebRTC peer opened an unexpected data channel".to_owned(),
        ));
    }
    wait_for_open(&channel).await?;
    Ok(Accepted {
        stream: channel_stream(channel, peer),
        peer: source,
        permit,
    })
}

async fn exchange_offer(
    socket: &UdpSocket,
    request_id: [u8; 16],
    request: &[u8],
) -> Result<String> {
    let mut response = vec![0_u8; u16::MAX as usize];
    for _ in 0..SIGNAL_ATTEMPTS {
        socket.send(request).await?;
        match tokio::time::timeout(SIGNAL_RETRY, socket.recv(&mut response)).await {
            Ok(Ok(length)) => {
                if let Some((SIGNAL_ANSWER, answer_id, sdp)) = decode_signal(&response[..length])
                    && answer_id == request_id
                {
                    return Ok(sdp);
                }
            }
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => {}
        }
    }
    Err(Error::Carrier("WebRTC signaling timed out".to_owned()))
}

#[derive(Clone)]
struct Events {
    gather_tx: mpsc::Sender<()>,
    failed_tx: mpsc::Sender<()>,
    data_channel_tx: Option<mpsc::Sender<Arc<dyn DataChannel>>>,
}

#[async_trait::async_trait]
impl PeerConnectionEventHandler for Events {
    async fn on_ice_gathering_state_change(&self, state: RTCIceGatheringState) {
        if state == RTCIceGatheringState::Complete {
            let _ = self.gather_tx.try_send(());
        }
    }

    async fn on_connection_state_change(&self, state: RTCPeerConnectionState) {
        if matches!(
            state,
            RTCPeerConnectionState::Failed | RTCPeerConnectionState::Closed
        ) {
            let _ = self.failed_tx.try_send(());
        }
    }

    async fn on_data_channel(&self, channel: Arc<dyn DataChannel>) {
        if let Some(sender) = &self.data_channel_tx {
            let _ = sender.try_send(channel);
        }
    }
}

async fn build_peer(
    events: Events,
    ice_servers: Vec<RTCIceServer>,
) -> Result<Arc<dyn PeerConnection>> {
    let configuration = RTCConfigurationBuilder::new()
        .with_ice_servers(ice_servers)
        .build();
    let peer = PeerConnectionBuilder::new()
        .with_configuration(configuration)
        .with_handler(Arc::new(events))
        .with_runtime(Arc::new(EscapingRuntime(TokioRuntime)))
        .with_udp_addrs(ice_bind_addresses())
        .with_data_channel_send_buffer_limit(DATA_CHANNEL_SEND_BUFFER)
        .build()
        .await
        .map_err(|error| rtc_error("cannot build peer connection", error))?;
    Ok(Arc::new(peer))
}

#[cfg(not(test))]
fn client_ice_servers(remote: SocketAddr) -> Vec<RTCIceServer> {
    vec![RTCIceServer {
        urls: vec![format!("stun:{remote}")],
        ..Default::default()
    }]
}

#[cfg(test)]
fn client_ice_servers(_remote: SocketAddr) -> Vec<RTCIceServer> {
    Vec::new()
}

#[cfg(not(test))]
fn server_ice_servers() -> Vec<RTCIceServer> {
    vec![RTCIceServer {
        urls: vec!["stun:stun.l.google.com:19302".to_owned()],
        ..Default::default()
    }]
}

#[cfg(test)]
fn server_ice_servers() -> Vec<RTCIceServer> {
    Vec::new()
}

#[cfg(not(test))]
fn ice_bind_addresses() -> Vec<String> {
    vec!["0.0.0.0:0".to_owned(), "[::]:0".to_owned()]
}

#[cfg(test)]
fn ice_bind_addresses() -> Vec<String> {
    vec!["127.0.0.1:0".to_owned()]
}

async fn wait_for_open(channel: &Arc<dyn DataChannel>) -> Result<()> {
    tokio::time::timeout(CONNECTION_TIMEOUT, async {
        loop {
            match channel.poll().await {
                Some(DataChannelEvent::OnOpen) => return Ok(()),
                Some(DataChannelEvent::OnError)
                | Some(DataChannelEvent::OnClosing)
                | Some(DataChannelEvent::OnClose)
                | None => {
                    return Err(Error::Carrier(
                        "WebRTC data channel closed during setup".to_owned(),
                    ));
                }
                _ => {}
            }
        }
    })
    .await
    .map_err(|_| Error::Carrier("WebRTC data channel open timed out".to_owned()))?
}

fn channel_stream(channel: Arc<dyn DataChannel>, peer: Arc<dyn PeerConnection>) -> BoxedStream {
    let (application, bridge) = tokio::io::duplex(STREAM_BUFFER);
    tokio::spawn(async move {
        let (mut from_application, mut to_application) = tokio::io::split(bridge);
        let send_channel = channel.clone();
        let send = async move {
            let mut buffer = vec![0_u8; DATA_CHUNK];
            loop {
                let length = from_application.read(&mut buffer).await?;
                if length == 0 {
                    break;
                }
                send_channel
                    .send(BytesMut::from(&buffer[..length]))
                    .await
                    .map_err(io::Error::other)?;
            }
            Ok::<(), io::Error>(())
        };
        let receive = async {
            loop {
                match channel.poll().await {
                    Some(DataChannelEvent::OnMessage(message)) => {
                        to_application.write_all(&message.data).await?;
                    }
                    Some(DataChannelEvent::OnClosing)
                    | Some(DataChannelEvent::OnClose)
                    | Some(DataChannelEvent::OnError)
                    | None => break,
                    _ => {}
                }
            }
            let _ = to_application.shutdown().await;
            Ok::<(), io::Error>(())
        };
        tokio::select! {
            _ = send => {}
            _ = receive => {}
        }
        let _ = channel.close().await;
        let _ = peer.close().await;
    });
    Box::new(application)
}

fn encode_signal(kind: u8, request_id: [u8; 16], sdp: &str) -> Result<Vec<u8>> {
    if sdp.len() > MAX_SIGNAL_SDP {
        return Err(Error::Carrier("WebRTC SDP is too large".to_owned()));
    }
    let mut packet = Vec::with_capacity(SIGNAL_HEADER + sdp.len());
    packet.extend_from_slice(SIGNAL_MAGIC);
    packet.push(kind);
    packet.extend_from_slice(&request_id);
    packet.extend_from_slice(sdp.as_bytes());
    Ok(packet)
}

fn decode_signal(packet: &[u8]) -> Option<(u8, [u8; 16], String)> {
    if packet.len() < SIGNAL_HEADER || &packet[..SIGNAL_MAGIC.len()] != SIGNAL_MAGIC {
        return None;
    }
    let kind = packet[SIGNAL_MAGIC.len()];
    let request_id = packet[SIGNAL_MAGIC.len() + 1..SIGNAL_HEADER]
        .try_into()
        .ok()?;
    let sdp = std::str::from_utf8(&packet[SIGNAL_HEADER..])
        .ok()?
        .to_owned();
    Some((kind, request_id, sdp))
}

/// Handles unauthenticated STUN Binding requests on the signaling socket.
/// This gives clients a server-reflexive ICE candidate even on networks
/// where public third-party STUN services are blocked.
fn stun_binding_response(packet: &[u8], source: SocketAddr) -> Option<Vec<u8>> {
    if packet.len() < STUN_HEADER
        || u16::from_be_bytes(packet[..2].try_into().ok()?) != STUN_BINDING_REQUEST
        || u32::from_be_bytes(packet[4..8].try_into().ok()?) != STUN_MAGIC_COOKIE
    {
        return None;
    }
    let attributes = u16::from_be_bytes(packet[2..4].try_into().ok()?) as usize;
    if packet.len() < STUN_HEADER + attributes {
        return None;
    }

    let value_length = if source.is_ipv4() { 8_u16 } else { 20_u16 };
    let message_length = value_length + 4;
    let mut response = Vec::with_capacity(STUN_HEADER + message_length as usize);
    response.extend_from_slice(&STUN_BINDING_SUCCESS.to_be_bytes());
    response.extend_from_slice(&message_length.to_be_bytes());
    response.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    response.extend_from_slice(&packet[8..20]);
    response.extend_from_slice(&STUN_XOR_MAPPED_ADDRESS.to_be_bytes());
    response.extend_from_slice(&value_length.to_be_bytes());
    response.push(0);
    response.push(if source.is_ipv4() { 1 } else { 2 });
    response.extend_from_slice(&(source.port() ^ (STUN_MAGIC_COOKIE >> 16) as u16).to_be_bytes());
    match source.ip() {
        std::net::IpAddr::V4(address) => {
            let encoded = u32::from_be_bytes(address.octets()) ^ STUN_MAGIC_COOKIE;
            response.extend_from_slice(&encoded.to_be_bytes());
        }
        std::net::IpAddr::V6(address) => {
            let mut mask = [0_u8; 16];
            mask[..4].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
            mask[4..].copy_from_slice(&packet[8..20]);
            for (byte, mask) in address.octets().iter().zip(mask) {
                response.push(byte ^ mask);
            }
        }
    }
    Some(response)
}

async fn resolve_endpoint(endpoint: &str) -> Result<SocketAddr> {
    tokio::net::lookup_host(endpoint)
        .await?
        .next()
        .ok_or_else(|| Error::Carrier(format!("{endpoint} did not resolve to an address")))
}

fn bind_udp(address: SocketAddr) -> Result<UdpSocket> {
    let socket = std::net::UdpSocket::bind(address)?;
    crate::outbound::prepare_udp_socket(&socket)?;
    socket.set_nonblocking(true)?;
    Ok(UdpSocket::from_std(socket)?)
}

fn rtc_error(context: &str, error: impl std::fmt::Display) -> Error {
    Error::Carrier(format!("WebRTC {context}: {error}"))
}

/// Delegates to webrtc-rs's Tokio runtime while applying snolc's socket
/// escape policy before the WebRTC driver starts using each ICE socket.
#[derive(Debug)]
struct EscapingRuntime(TokioRuntime);

impl Runtime for EscapingRuntime {
    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) -> Box<dyn JoinHandle> {
        self.0.spawn(future)
    }

    fn spawn_reactor(
        &self,
        reactor_pool_size: usize,
        future: Pin<Box<dyn Future<Output = ()> + Send>>,
    ) -> Box<dyn JoinHandle> {
        self.0.spawn_reactor(reactor_pool_size, future)
    }

    fn wrap_udp_socket(&self, socket: std::net::UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        crate::outbound::prepare_udp_socket(&socket).map_err(io::Error::other)?;
        self.0.wrap_udp_socket(socket)
    }

    fn wrap_tcp_listener(
        &self,
        listener: std::net::TcpListener,
    ) -> io::Result<Arc<dyn AsyncTcpListener>> {
        self.0.wrap_tcp_listener(listener)
    }

    fn connect_tcp<'a>(
        &'a self,
        remote_addr: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<Arc<dyn AsyncTcpStream>>> + Send + 'a>> {
        Box::pin(async move {
            let stream = crate::outbound::connect_tcp(remote_addr)
                .await
                .map_err(io::Error::other)?;
            let local_addr = stream.local_addr()?;
            let peer_addr = stream.peer_addr()?;
            let (read_half, write_half) = stream.into_split();
            Ok(Arc::new(EscapingTcpStream {
                read_half,
                write_half,
                local_addr,
                peer_addr,
            }) as Arc<dyn AsyncTcpStream>)
        })
    }

    fn resolve_host<'a>(
        &'a self,
        host: &'a str,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send + 'a>> {
        self.0.resolve_host(host)
    }

    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        self.0.sleep(duration)
    }

    fn interval(&self, period: Duration) -> Box<dyn AsyncInterval> {
        self.0.interval(period)
    }

    fn block_on(&self, future: Pin<Box<dyn Future<Output = ()> + '_>>) {
        self.0.block_on(future);
    }

    fn yield_now(&self) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        self.0.yield_now()
    }

    fn name(&self) -> &'static str {
        "tokio-escaping"
    }
}

#[derive(Debug)]
struct EscapingTcpStream {
    read_half: tokio::net::tcp::OwnedReadHalf,
    write_half: tokio::net::tcp::OwnedWriteHalf,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
}

impl AsyncTcpStream for EscapingTcpStream {
    fn read<'a, 'b>(
        &'a self,
        buffer: &'b mut [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'b>>
    where
        'a: 'b,
    {
        Box::pin(async move {
            loop {
                self.read_half.readable().await?;
                match self.read_half.try_read(buffer) {
                    Ok(length) => return Ok(length),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(error) => return Err(error),
                }
            }
        })
    }

    fn write_all<'a, 'b>(
        &'a self,
        buffer: &'b [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'b>>
    where
        'a: 'b,
    {
        Box::pin(async move {
            let mut remaining = buffer;
            while !remaining.is_empty() {
                self.write_half.writable().await?;
                match self.write_half.try_write(remaining) {
                    Ok(0) => {
                        return Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "failed to write any bytes",
                        ));
                    }
                    Ok(length) => remaining = &remaining[length..],
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(error) => return Err(error),
                }
            }
            Ok(())
        })
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.peer_addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signaling_round_trip_preserves_binary_id_and_sdp() {
        let request_id = [0xa5; 16];
        let packet = encode_signal(SIGNAL_OFFER, request_id, "v=0\r\ns=-\r\n").unwrap();
        let decoded = decode_signal(&packet).unwrap();
        assert_eq!(
            decoded,
            (SIGNAL_OFFER, request_id, "v=0\r\ns=-\r\n".to_owned())
        );
        assert!(decode_signal(b"not-webrtc").is_none());
    }

    #[test]
    fn stun_binding_response_contains_the_xored_public_address() {
        let transaction = [0x5a; 12];
        let mut request = Vec::from(STUN_BINDING_REQUEST.to_be_bytes());
        request.extend_from_slice(&0_u16.to_be_bytes());
        request.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        request.extend_from_slice(&transaction);
        let source: SocketAddr = "203.0.113.9:45678".parse().unwrap();
        let response = stun_binding_response(&request, source).unwrap();

        assert_eq!(
            u16::from_be_bytes(response[..2].try_into().unwrap()),
            STUN_BINDING_SUCCESS
        );
        assert_eq!(&response[8..20], &transaction);
        assert_eq!(
            u16::from_be_bytes(response[20..22].try_into().unwrap()),
            STUN_XOR_MAPPED_ADDRESS
        );
        let port = u16::from_be_bytes(response[26..28].try_into().unwrap())
            ^ (STUN_MAGIC_COOKIE >> 16) as u16;
        let address = u32::from_be_bytes(response[28..32].try_into().unwrap()) ^ STUN_MAGIC_COOKIE;
        assert_eq!(port, source.port());
        assert_eq!(std::net::Ipv4Addr::from(address), source.ip());
    }

    #[tokio::test]
    async fn real_ice_dtls_sctp_channel_behaves_as_a_stream() {
        let mut listener = Listener::bind("127.0.0.1:0", 1, Logger::disabled())
            .await
            .unwrap();
        let remote = listener.local_addr().to_string();
        let client = tokio::spawn(async move { connect(&remote).await.unwrap() });
        let accepted = tokio::time::timeout(Duration::from_secs(15), listener.accept())
            .await
            .unwrap()
            .unwrap();
        let mut server_stream = accepted.stream;
        let mut client_stream = client.await.unwrap();

        client_stream.write_all(b"through-webrtc").await.unwrap();
        let mut request = [0_u8; 14];
        server_stream.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"through-webrtc");

        server_stream.write_all(b"reply").await.unwrap();
        let mut response = [0_u8; 5];
        client_stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"reply");
    }
}
