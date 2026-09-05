use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, ToSocketAddrs, UdpSocket};
use tokio::sync::watch;
use tokio::time::timeout;

use crate::error::{Error, Result};
use crate::routing::{Action, RuleSet};
use crate::tunnel::{ClientSession, ProtectedStream, Target, TargetHost};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// A fixed `SO_MARK` value (Linux-only) applied to every direct outbound
/// socket this process opens. Without it, a `tun` inbound whose `include`
/// routes happen to cover a direct-routed destination would capture this
/// very socket's own outbound packets right back into the tun device --
/// snolc trying to reach the real destination, having that attempt
/// re-intercepted as a new inbound flow, spawning another attempt, forever.
/// `tun::configure_interface` installs a policy-routing rule that sends
/// marked traffic through the normal routing table, bypassing tun, which is
/// the same technique real transparent proxies (sing-box, clash, etc.) use.
/// The value is intentionally distinctive to reduce the chance of colliding
/// with marks installed by unrelated routing software on the host.
pub const DIRECT_SOCKET_MARK: u32 = 0x734e_4c43; // b"sNLC" as a big-endian u32

#[derive(Clone)]
pub struct Connector {
    sessions: watch::Receiver<Option<ClientSession>>,
    routing: Option<Arc<RuleSet>>,
}

pub enum Outbound {
    Direct(TcpStream),
    Proxy(ProtectedStream),
}

/// The UDP counterpart of [`Outbound`]: either a connected local socket
/// (routed direct) or a datagram-relaying stream opened on the tunnel.
pub enum UdpOutbound {
    Direct(UdpSocket),
    Proxy(ProtectedStream),
}

impl Connector {
    pub fn new(
        sessions: watch::Receiver<Option<ClientSession>>,
        routing: Option<Arc<RuleSet>>,
    ) -> Self {
        Self { sessions, routing }
    }

    pub async fn connect(&self, target: &Target) -> Result<Outbound> {
        let action = match &self.routing {
            Some(routing) => routing.decide(target.domain_name(), target.ip_address())?,
            None => Action::Proxy,
        };
        match action {
            Action::Direct => {
                let stream = timeout(CONNECT_TIMEOUT, connect_direct(target))
                    .await
                    .map_err(|_| Error::Carrier("direct connection timed out".to_owned()))??;
                Ok(Outbound::Direct(stream))
            }
            Action::Proxy => {
                let session = self
                    .sessions
                    .borrow()
                    .clone()
                    .ok_or_else(|| Error::Carrier("no active server connection".to_owned()))?;
                Ok(Outbound::Proxy(session.open_tcp(target).await?))
            }
        }
    }

    pub async fn connect_udp(&self, target: &Target) -> Result<UdpOutbound> {
        let action = match &self.routing {
            Some(routing) => routing.decide(target.domain_name(), target.ip_address())?,
            None => Action::Proxy,
        };
        match action {
            Action::Direct => {
                let socket = timeout(CONNECT_TIMEOUT, connect_udp(target))
                    .await
                    .map_err(|_| Error::Carrier("direct connection timed out".to_owned()))??;
                Ok(UdpOutbound::Direct(socket))
            }
            Action::Proxy => {
                let session = self
                    .sessions
                    .borrow()
                    .clone()
                    .ok_or_else(|| Error::Carrier("no active server connection".to_owned()))?;
                Ok(UdpOutbound::Proxy(session.open_udp(target).await?))
            }
        }
    }
}

impl Outbound {
    pub async fn send(&mut self, payload: &[u8]) -> Result<()> {
        match self {
            Self::Direct(stream) => {
                use tokio::io::AsyncWriteExt;
                stream.write_all(payload).await?;
                stream.flush().await?;
                Ok(())
            }
            Self::Proxy(stream) => stream.send(payload).await,
        }
    }

    pub async fn relay<L>(self, mut local: L) -> Result<()>
    where
        L: AsyncRead + AsyncWrite + Unpin,
    {
        match self {
            Self::Direct(mut remote) => {
                tokio::io::copy_bidirectional(&mut local, &mut remote).await?;
                Ok(())
            }
            Self::Proxy(remote) => remote.relay(local).await,
        }
    }
}

async fn connect_direct(target: &Target) -> Result<TcpStream> {
    match &target.host {
        TargetHost::Ip(ip) => connect_tcp(std::net::SocketAddr::new(*ip, target.port)).await,
        TargetHost::Domain(domain) => connect_tcp((domain.as_str(), target.port)).await,
    }
}

/// Opens a TCP connection on a socket prepared to escape the process TUN.
/// Every external connection created by snolc should use this helper so broad
/// TUN routes cannot capture carrier, mirror, or server-target traffic. Linux
/// uses `SO_MARK`; an embedding application can additionally install a socket
/// protector (Android's `VpnService.protect`, for example).
pub(crate) async fn connect_tcp(address: impl ToSocketAddrs) -> Result<TcpStream> {
    let mut last_error = None;
    for address in tokio::net::lookup_host(address).await? {
        let socket = if address.is_ipv4() {
            tokio::net::TcpSocket::new_v4()?
        } else {
            tokio::net::TcpSocket::new_v6()?
        };
        prepare_tcp_socket(&socket)?;
        match socket.connect(address).await {
            Ok(stream) => {
                stream.set_nodelay(true)?;
                return Ok(stream);
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error
        .map(Error::from)
        .unwrap_or_else(|| Error::Carrier("target did not resolve to an address".to_owned())))
}

/// Opens a UDP socket "connected" to `target`, carrying the same escape
/// policy as [`connect_tcp`] so its traffic bypasses a broad TUN route owned
/// by this process. A connected UDP socket restricts `send`/`recv` to that
/// one peer, giving UDP the same per-destination lifetime as a TCP stream.
pub(crate) async fn connect_udp(target: &Target) -> Result<UdpSocket> {
    let address = match &target.host {
        TargetHost::Ip(ip) => std::net::SocketAddr::new(*ip, target.port),
        TargetHost::Domain(domain) => tokio::net::lookup_host((domain.as_str(), target.port))
            .await?
            .next()
            .ok_or_else(|| Error::Carrier("target did not resolve to an address".to_owned()))?,
    };
    let bind_address: std::net::SocketAddr = if address.is_ipv4() {
        "0.0.0.0:0".parse().expect("valid bind address")
    } else {
        "[::]:0".parse().expect("valid bind address")
    };
    let std_socket = std::net::UdpSocket::bind(bind_address)?;
    std_socket.set_nonblocking(true)?;
    prepare_udp_socket(&std_socket)?;
    let socket = UdpSocket::from_std(std_socket)?;
    socket.connect(address).await?;
    Ok(socket)
}

pub(crate) fn prepare_tcp_socket(socket: &tokio::net::TcpSocket) -> Result<()> {
    prepare_socket(socket.as_raw_fd())
}

/// Prepares UDP sockets created by the WebRTC stack so their ICE traffic also
/// bypasses a broad TUN route owned by this process.
pub(crate) fn prepare_udp_socket(socket: &std::net::UdpSocket) -> Result<()> {
    prepare_socket(socket.as_raw_fd())
}

fn prepare_socket(descriptor: std::os::fd::RawFd) -> Result<()> {
    crate::vpn::protect_socket(descriptor)?;
    #[cfg(target_os = "linux")]
    mark_fd(descriptor);
    Ok(())
}

#[cfg(target_os = "linux")]
fn mark_fd(fd: std::os::fd::RawFd) {
    let mark: libc::c_int = DIRECT_SOCKET_MARK as libc::c_int;
    let _ = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            (&raw const mark).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    // Failure is non-fatal: only the tun inbound depends on this mark, and
    // creating that interface already requires the same CAP_NET_ADMIN.
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd;
    use std::sync::Mutex;
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::routing::Rule;
    use crate::vpn::{self, SocketProtector};

    #[tokio::test]
    async fn socket_protector_runs_before_tcp_connect() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let observations = Arc::new(Mutex::new(Vec::new()));
        let callback_observations = observations.clone();
        let protector: SocketProtector = Arc::new(move |descriptor| {
            let mut peer = std::mem::MaybeUninit::<libc::sockaddr_storage>::uninit();
            let mut length = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            let connected = unsafe {
                libc::getpeername(descriptor, peer.as_mut_ptr().cast(), &mut length) == 0
            };
            callback_observations
                .lock()
                .unwrap()
                .push((descriptor, connected));
            Ok(())
        });
        let previous = vpn::set_socket_protector(Some(protector));

        let stream = connect_tcp(listener.local_addr().unwrap()).await.unwrap();
        let descriptor = stream.as_raw_fd();
        vpn::set_socket_protector(previous);

        let observations = observations.lock().unwrap();
        assert_eq!(
            observations
                .iter()
                .find(|(observed, _)| *observed == descriptor)
                .map(|(_, connected)| *connected),
            Some(false)
        );
    }

    #[tokio::test]
    async fn direct_rule_bypasses_an_absent_proxy_session() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let byte = stream.read_u8().await.unwrap();
            stream.write_u8(byte + 1).await.unwrap();
        });
        let mut rules = RuleSet {
            rules: vec![
                Rule::Ip {
                    value: "127.0.0.0/8".parse().unwrap(),
                    action: Action::Direct,
                },
                Rule::Any {
                    action: Action::Proxy,
                },
            ],
        };
        rules.normalize_and_validate().unwrap();
        let (_sessions_tx, sessions_rx) = watch::channel(None);
        let connector = Connector::new(sessions_rx, Some(Arc::new(rules)));
        let target = Target::ip(address.ip(), address.port()).unwrap();
        let outbound = connector.connect(&target).await.unwrap();
        let (mut application, relay_side) = tokio::io::duplex(64);
        let relay = tokio::spawn(outbound.relay(relay_side));
        application.write_u8(7).await.unwrap();
        assert_eq!(application.read_u8().await.unwrap(), 8);
        drop(application);
        timeout(Duration::from_secs(1), relay)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        server.await.unwrap();
    }
}
