use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio::time::{MissedTickBehavior, interval, timeout};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::frame::{Frame, FrameType};
use crate::handshake::{ClientHandshake, accept_client};
use crate::identity::Identity;
use crate::mux::{MuxHandle, MuxStream};
use crate::protection::{ProtectionMode, SESSION_KEY_LEN, Side, StreamProtector};
use crate::wire_io::{read_frame, write_frame};

const RELAY_BUFFER: usize = 16 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone)]
pub struct ClientSession {
    mux: MuxHandle,
    master: Arc<Zeroizing<[u8; SESSION_KEY_LEN]>>,
    mode: ProtectionMode,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Target {
    pub host: TargetHost,
    pub port: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TargetHost {
    Ip(IpAddr),
    Domain(String),
}

pub struct ProtectedStream {
    stream: MuxStream,
    protector: StreamProtector,
}

pub struct ServerEstablished {
    pub master: Zeroizing<[u8; SESSION_KEY_LEN]>,
    pub identity: [u8; 32],
}

enum OpenRequest {
    Control,
    Tcp(Target),
    Udp(Target),
}

impl Target {
    pub fn new(host: TargetHost, port: u16) -> Result<Self> {
        if port == 0 {
            return Err(Error::Protocol("target port cannot be zero".to_owned()));
        }
        if let TargetHost::Domain(domain) = &host {
            validate_domain(domain)?;
        }
        Ok(Self { host, port })
    }

    pub fn domain(domain: impl Into<String>, port: u16) -> Result<Self> {
        Self::new(TargetHost::Domain(domain.into()), port)
    }

    pub fn ip(ip: IpAddr, port: u16) -> Result<Self> {
        Self::new(TargetHost::Ip(ip), port)
    }

    pub fn domain_name(&self) -> Option<&str> {
        match &self.host {
            TargetHost::Domain(domain) => Some(domain),
            TargetHost::Ip(_) => None,
        }
    }

    pub fn ip_address(&self) -> Option<IpAddr> {
        match self.host {
            TargetHost::Ip(ip) => Some(ip),
            TargetHost::Domain(_) => None,
        }
    }
}

impl ClientSession {
    pub fn new(
        mux: MuxHandle,
        master: Zeroizing<[u8; SESSION_KEY_LEN]>,
        mode: ProtectionMode,
    ) -> Self {
        Self {
            mux,
            master: Arc::new(master),
            mode,
        }
    }

    pub async fn open_tcp(&self, target: &Target) -> Result<ProtectedStream> {
        let request = encode_open(&OpenRequest::Tcp(target.clone()))?;
        self.open(request).await
    }

    async fn open_control(&self) -> Result<ProtectedStream> {
        self.open(encode_open(&OpenRequest::Control)?).await
    }

    async fn open(&self, request: Vec<u8>) -> Result<ProtectedStream> {
        let mut stream = self.mux.open().await?;
        let mut protector = StreamProtector::new(&self.master, stream.id, Side::Client, self.mode)?;
        let frame = protector.seal(FrameType::Open, 0, &request)?;
        write_frame(&mut stream.io, &frame, self.mode.tag_len()).await?;
        let response = read_frame(&mut stream.io, self.mode.tag_len()).await?;
        let kind = response.kind;
        let payload = protector.open(response)?;
        match kind {
            FrameType::OpenOk if payload.is_empty() => Ok(ProtectedStream { stream, protector }),
            FrameType::Error => Err(Error::Carrier(
                "remote endpoint rejected the stream".to_owned(),
            )),
            _ => Err(Error::Protocol(
                "unexpected stream-open response".to_owned(),
            )),
        }
    }

    pub async fn monitor_heartbeat(&self, period: Duration) -> Result<()> {
        if period.is_zero() {
            return Err(Error::Config("heartbeat cannot be zero".to_owned()));
        }
        let mut control = self.open_control().await?;
        let mut ticker = interval(period);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let frame = control.protector.seal(FrameType::Heartbeat, 0, &[])?;
            write_frame(&mut control.stream.io, &frame, self.mode.tag_len()).await?;
            let response = timeout(
                period,
                read_frame(&mut control.stream.io, self.mode.tag_len()),
            )
            .await
            .map_err(|_| Error::Carrier("heartbeat timed out".to_owned()))??;
            let kind = response.kind;
            let payload = control.protector.open(response)?;
            if kind != FrameType::Heartbeat || !payload.is_empty() {
                return Err(Error::Protocol("invalid heartbeat response".to_owned()));
            }
        }
    }

    pub async fn abort(&self) {
        self.mux.abort().await;
    }

    pub async fn wait_closed(&self) {
        self.mux.wait_closed().await;
    }
}

impl ProtectedStream {
    pub async fn send(&mut self, payload: &[u8]) -> Result<()> {
        let frame = self.protector.seal(FrameType::Data, 0, payload)?;
        write_frame(&mut self.stream.io, &frame, self.protector.tag_len()).await
    }

    pub async fn relay<L>(mut self, local: L) -> Result<()>
    where
        L: AsyncRead + AsyncWrite + Unpin,
    {
        let tag_len = self.protector.tag_len();
        let (mut local_reader, mut local_writer) = tokio::io::split(local);
        let (mut tunnel_reader, mut tunnel_writer) = tokio::io::split(self.stream.io);
        let mut local_open = true;
        let mut remote_open = true;
        let mut buffer = vec![0_u8; RELAY_BUFFER];

        while local_open || remote_open {
            enum Event {
                Local(std::io::Result<usize>),
                Remote(Result<Frame>),
            }

            let event = tokio::select! {
                read = local_reader.read(&mut buffer), if local_open => Event::Local(read),
                frame = read_frame(&mut tunnel_reader, tag_len), if remote_open => {
                    Event::Remote(frame)
                }
            };

            match event {
                Event::Local(Ok(0)) => {
                    let close = self.protector.seal(FrameType::Close, 0, &[])?;
                    write_frame(&mut tunnel_writer, &close, tag_len).await?;
                    tunnel_writer.shutdown().await?;
                    local_open = false;
                }
                Event::Local(Ok(length)) => {
                    let data = self.protector.seal(FrameType::Data, 0, &buffer[..length])?;
                    write_frame(&mut tunnel_writer, &data, tag_len).await?;
                }
                Event::Local(Err(error)) => return Err(error.into()),
                Event::Remote(Ok(frame)) => {
                    let kind = frame.kind;
                    let payload = self.protector.open(frame)?;
                    match kind {
                        FrameType::Data => local_writer.write_all(&payload).await?,
                        FrameType::Close if payload.is_empty() => {
                            local_writer.shutdown().await?;
                            remote_open = false;
                        }
                        FrameType::Error => {
                            return Err(Error::Carrier("remote stream failed".to_owned()));
                        }
                        _ => return Err(Error::Protocol("unexpected relay frame".to_owned())),
                    }
                }
                Event::Remote(Err(error)) => return Err(error),
            }
        }
        Ok(())
    }
}

pub async fn client_handshake<S>(
    stream: &mut S,
    identity: &Identity,
    mode: ProtectionMode,
) -> Result<Zeroizing<[u8; SESSION_KEY_LEN]>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (handshake, hello) = ClientHandshake::start(identity, mode)?;
    write_frame(stream, &plain_frame(FrameType::ClientHello, hello), 0).await?;
    let response = read_frame(stream, 0).await?;
    validate_plain_handshake(&response, FrameType::ServerHello)?;
    let established = handshake.complete(&response.payload)?;
    write_frame(
        stream,
        &plain_frame(FrameType::ClientFinish, established.finish.to_vec()),
        0,
    )
    .await?;
    Ok(established.master)
}

pub async fn server_handshake<S>(
    stream: &mut S,
    mode: ProtectionMode,
    allowed: &[[u8; 32]],
) -> Result<ServerEstablished>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let hello = read_client_hello(stream).await?;
    server_handshake_with_hello(stream, hello, mode, allowed).await
}

/// Reads a raw, unauthenticated `ClientHello` frame off the wire.
///
/// This is split out from [`server_handshake`] so callers can inspect the
/// client's identity (see [`crate::handshake::peek_client_identity`]) before
/// deciding whether to run the full handshake or a fallback response for an
/// unrecognized client.
pub async fn read_client_hello<S>(stream: &mut S) -> Result<Frame>
where
    S: AsyncRead + Unpin,
{
    let hello = read_frame(stream, 0).await?;
    validate_plain_handshake(&hello, FrameType::ClientHello)?;
    Ok(hello)
}

pub async fn server_handshake_with_hello<S>(
    stream: &mut S,
    hello: Frame,
    mode: ProtectionMode,
    allowed: &[[u8; 32]],
) -> Result<ServerEstablished>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (response, pending) = accept_client(&hello.payload, mode, allowed)?;
    let identity = pending.identity();
    write_frame(stream, &plain_frame(FrameType::ServerHello, response), 0).await?;
    let finish = read_frame(stream, 0).await?;
    validate_plain_handshake(&finish, FrameType::ClientFinish)?;
    Ok(ServerEstablished {
        master: pending.finish(&finish.payload)?,
        identity,
    })
}

/// Re-encodes a previously decoded, unprotected frame back into wire bytes.
/// Used to forward the exact bytes of an unrecognized client's hello to a
/// fallback backend.
pub fn encode_plain_frame(frame: &Frame) -> Result<Vec<u8>> {
    frame.encode(0)
}

pub fn decode_public_keys(values: impl IntoIterator<Item = String>) -> Result<Vec<[u8; 32]>> {
    values
        .into_iter()
        .map(|value| {
            let bytes = STANDARD
                .decode(value)
                .map_err(|_| Error::Config("client public key is not base64".to_owned()))?;
            bytes
                .try_into()
                .map_err(|_| Error::Config("client public key must contain 32 bytes".to_owned()))
        })
        .collect()
}

pub async fn serve_session(
    mut incoming: mpsc::Receiver<MuxStream>,
    mux: MuxHandle,
    master: Zeroizing<[u8; SESSION_KEY_LEN]>,
    mode: ProtectionMode,
    heartbeat: Duration,
) -> Result<()> {
    let master = Arc::new(master);
    let control_active = Arc::new(AtomicBool::new(false));
    let mut streams = JoinSet::new();

    loop {
        tokio::select! {
            incoming_stream = incoming.recv() => match incoming_stream {
                Some(stream) => {
                    let master = master.clone();
                    let mux = mux.clone();
                    let control_active = control_active.clone();
                    streams.spawn(async move {
                        serve_stream(stream, master, mode, heartbeat, mux, control_active).await
                    });
                }
                None => break,
            },
            result = streams.join_next(), if !streams.is_empty() => {
                if let Some(Err(error)) = result {
                    return Err(Error::Runtime(format!("server stream task failed: {error}")));
                }
            }
            () = mux.wait_closed() => break,
        }
    }
    streams.abort_all();
    Ok(())
}

async fn serve_stream(
    mut stream: MuxStream,
    master: Arc<Zeroizing<[u8; SESSION_KEY_LEN]>>,
    mode: ProtectionMode,
    heartbeat: Duration,
    mux: MuxHandle,
    control_active: Arc<AtomicBool>,
) -> Result<()> {
    let mut protector = StreamProtector::new(&master, stream.id, Side::Server, mode)?;
    let open = timeout(heartbeat, read_frame(&mut stream.io, mode.tag_len()))
        .await
        .map_err(|_| Error::Protocol("stream open timed out".to_owned()))??;
    let kind = open.kind;
    let payload = protector.open(open)?;
    if kind != FrameType::Open {
        return Err(Error::Protocol(
            "stream does not start with open".to_owned(),
        ));
    }

    match decode_open(&payload)? {
        OpenRequest::Control => {
            if control_active.swap(true, Ordering::AcqRel) {
                send_open_error(&mut stream, &mut protector, mode).await?;
                return Err(Error::Protocol("duplicate control stream".to_owned()));
            }
            send_open_ok(&mut stream, &mut protector, mode).await?;
            let result = serve_control(stream, protector, mode, heartbeat).await;
            control_active.store(false, Ordering::Release);
            if result.is_err() {
                mux.abort().await;
            }
            result
        }
        OpenRequest::Tcp(target) => {
            let remote = match timeout(CONNECT_TIMEOUT, connect_target(&target)).await {
                Ok(Ok(remote)) => remote,
                Ok(Err(error)) => {
                    send_open_error(&mut stream, &mut protector, mode).await?;
                    return Err(error);
                }
                Err(_) => {
                    send_open_error(&mut stream, &mut protector, mode).await?;
                    return Err(Error::Carrier("target connection timed out".to_owned()));
                }
            };
            send_open_ok(&mut stream, &mut protector, mode).await?;
            ProtectedStream { stream, protector }.relay(remote).await
        }
        OpenRequest::Udp(_) => {
            send_open_error(&mut stream, &mut protector, mode).await?;
            Err(Error::Carrier(
                "UDP streams are not connected yet".to_owned(),
            ))
        }
    }
}

async fn serve_control(
    mut stream: MuxStream,
    mut protector: StreamProtector,
    mode: ProtectionMode,
    heartbeat: Duration,
) -> Result<()> {
    let deadline = heartbeat
        .checked_mul(2)
        .ok_or_else(|| Error::Config("heartbeat duration overflow".to_owned()))?;
    loop {
        let frame = timeout(deadline, read_frame(&mut stream.io, mode.tag_len()))
            .await
            .map_err(|_| Error::Carrier("client heartbeat timed out".to_owned()))??;
        let kind = frame.kind;
        let payload = protector.open(frame)?;
        if kind != FrameType::Heartbeat || !payload.is_empty() {
            return Err(Error::Protocol("invalid control frame".to_owned()));
        }
        let response = protector.seal(FrameType::Heartbeat, 0, &[])?;
        write_frame(&mut stream.io, &response, mode.tag_len()).await?;
    }
}

async fn send_open_ok(
    stream: &mut MuxStream,
    protector: &mut StreamProtector,
    mode: ProtectionMode,
) -> Result<()> {
    let response = protector.seal(FrameType::OpenOk, 0, &[])?;
    write_frame(&mut stream.io, &response, mode.tag_len()).await
}

async fn send_open_error(
    stream: &mut MuxStream,
    protector: &mut StreamProtector,
    mode: ProtectionMode,
) -> Result<()> {
    let response = protector.seal(FrameType::Error, 0, &[1])?;
    write_frame(&mut stream.io, &response, mode.tag_len()).await
}

async fn connect_target(target: &Target) -> Result<TcpStream> {
    let stream = match &target.host {
        TargetHost::Ip(ip) => TcpStream::connect(SocketAddr::new(*ip, target.port)).await?,
        TargetHost::Domain(domain) => TcpStream::connect((domain.as_str(), target.port)).await?,
    };
    stream.set_nodelay(true)?;
    Ok(stream)
}

fn plain_frame(kind: FrameType, payload: Vec<u8>) -> Frame {
    Frame {
        kind,
        flags: 0,
        sequence: 0,
        payload,
        tag: Vec::new(),
    }
}

fn validate_plain_handshake(frame: &Frame, expected: FrameType) -> Result<()> {
    if frame.kind != expected || frame.flags != 0 || frame.sequence != 0 || !frame.tag.is_empty() {
        return Err(Error::Protocol("invalid handshake frame".to_owned()));
    }
    Ok(())
}

fn encode_open(request: &OpenRequest) -> Result<Vec<u8>> {
    match request {
        OpenRequest::Control => Ok(vec![0]),
        OpenRequest::Tcp(target) => encode_target(1, target),
        OpenRequest::Udp(target) => encode_target(2, target),
    }
}

fn encode_target(protocol: u8, target: &Target) -> Result<Vec<u8>> {
    let mut output = vec![protocol];
    match &target.host {
        TargetHost::Ip(IpAddr::V4(ip)) => {
            output.push(1);
            output.extend_from_slice(&ip.octets());
        }
        TargetHost::Ip(IpAddr::V6(ip)) => {
            output.push(2);
            output.extend_from_slice(&ip.octets());
        }
        TargetHost::Domain(domain) => {
            validate_domain(domain)?;
            let length = u8::try_from(domain.len())
                .map_err(|_| Error::Protocol("target domain is too long".to_owned()))?;
            output.push(3);
            output.push(length);
            output.extend_from_slice(domain.as_bytes());
        }
    }
    output.extend_from_slice(&target.port.to_be_bytes());
    Ok(output)
}

fn decode_open(input: &[u8]) -> Result<OpenRequest> {
    let Some(protocol) = input.first().copied() else {
        return Err(Error::Protocol("empty stream-open request".to_owned()));
    };
    if protocol == 0 {
        if input.len() != 1 {
            return Err(Error::Protocol("invalid control-open request".to_owned()));
        }
        return Ok(OpenRequest::Control);
    }
    if protocol != 1 && protocol != 2 {
        return Err(Error::Protocol("unknown stream protocol".to_owned()));
    }
    if input.len() < 4 {
        return Err(Error::Protocol("truncated stream-open request".to_owned()));
    }
    let (host, offset) = match input[1] {
        1 if input.len() >= 8 => (
            TargetHost::Ip(IpAddr::from(
                <[u8; 4]>::try_from(&input[2..6]).expect("IPv4 length"),
            )),
            6,
        ),
        2 if input.len() >= 20 => (
            TargetHost::Ip(IpAddr::from(
                <[u8; 16]>::try_from(&input[2..18]).expect("IPv6 length"),
            )),
            18,
        ),
        3 => {
            let length = input[2] as usize;
            let end = 3_usize
                .checked_add(length)
                .ok_or_else(|| Error::Protocol("target domain length overflow".to_owned()))?;
            if input.len() < end + 2 {
                return Err(Error::Protocol("truncated target domain".to_owned()));
            }
            let domain = std::str::from_utf8(&input[3..end])
                .map_err(|_| Error::Protocol("target domain is not UTF-8".to_owned()))?
                .to_owned();
            (TargetHost::Domain(domain), end)
        }
        _ => return Err(Error::Protocol("invalid target address type".to_owned())),
    };
    if input.len() != offset + 2 {
        return Err(Error::Protocol("stream-open length mismatch".to_owned()));
    }
    let port = u16::from_be_bytes(
        input[offset..]
            .try_into()
            .map_err(|_| Error::Protocol("invalid target port".to_owned()))?,
    );
    let target = Target::new(host, port)?;
    if protocol == 1 {
        Ok(OpenRequest::Tcp(target))
    } else {
        Ok(OpenRequest::Udp(target))
    }
}

fn validate_domain(domain: &str) -> Result<()> {
    let domain = domain.strip_suffix('.').unwrap_or(domain);
    if domain.is_empty() || domain.len() > 253 {
        return Err(Error::Protocol("invalid target domain".to_owned()));
    }
    for label in domain.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(Error::Protocol("invalid target domain".to_owned()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use yamux::Mode;

    use super::*;
    use crate::mux;

    #[test]
    fn target_codec_round_trips_ipv4_ipv6_and_domains() {
        let targets = [
            Target::ip("127.0.0.1".parse().unwrap(), 80).unwrap(),
            Target::ip("::1".parse().unwrap(), 443).unwrap(),
            Target::domain("example.com", 53).unwrap(),
        ];
        for target in targets {
            let encoded = encode_open(&OpenRequest::Tcp(target.clone())).unwrap();
            let OpenRequest::Tcp(decoded) = decode_open(&encoded).unwrap() else {
                panic!("decoded wrong protocol");
            };
            assert_eq!(decoded, target);
        }
    }

    #[tokio::test]
    async fn handshake_then_protected_yamux_stream_reaches_a_real_tcp_target() {
        let destination = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination_address = destination.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut stream, _) = destination.accept().await.unwrap();
            let mut data = [0_u8; 4];
            stream.read_exact(&mut data).await.unwrap();
            stream.write_all(&data).await.unwrap();
        });

        let identity = Identity::generate().unwrap();
        let public = identity.public();
        let (mut client_io, mut server_io) = tokio::io::duplex(128 * 1024);
        let server_handshake_task = tokio::spawn(async move {
            server_handshake(&mut server_io, ProtectionMode::ChaChaPoly, &[public])
                .await
                .map(|established| (server_io, established))
        });
        let client_master = client_handshake(&mut client_io, &identity, ProtectionMode::ChaChaPoly)
            .await
            .unwrap();
        let (server_io, server) = server_handshake_task.await.unwrap().unwrap();

        let window = 8 * yamux::DEFAULT_CREDIT as usize;
        let (client_mux, _) = mux::spawn(client_io, Mode::Client, 8, window).unwrap();
        let (server_mux, incoming) = mux::spawn(server_io, Mode::Server, 8, window).unwrap();
        let server_session = tokio::spawn(serve_session(
            incoming,
            server_mux,
            server.master,
            ProtectionMode::ChaChaPoly,
            Duration::from_secs(2),
        ));
        let client = ClientSession::new(client_mux, client_master, ProtectionMode::ChaChaPoly);
        let protected = client
            .open_tcp(&Target::ip(destination_address.ip(), destination_address.port()).unwrap())
            .await
            .unwrap();
        let (mut application, relay_side) = tokio::io::duplex(1024);
        let relay = tokio::spawn(protected.relay(relay_side));
        application.write_all(b"ping").await.unwrap();
        let mut response = [0_u8; 4];
        application.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ping");
        drop(application);
        relay.await.unwrap().unwrap();
        client.abort().await;
        server_session.await.unwrap().unwrap();
        echo.await.unwrap();
    }
}
