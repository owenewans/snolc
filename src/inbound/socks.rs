use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::Mutex;

use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;

use crate::config::Socks;
use crate::error::{Error, Result};
use crate::logging::{Level, Logger};
use crate::outbound::{Connector, UdpOutbound};
use crate::tunnel::{Target, TargetHost};

const MAX_TEXT_FIELD: usize = 255;
/// Ceiling on a single relayed UDP payload, matching
/// [`crate::tunnel`]'s own datagram limit.
const MAX_UDP_DATAGRAM: usize = 65_507;

pub async fn serve(config: Socks, connector: Connector, logger: Logger) -> Result<()> {
    let listener = TcpListener::bind((config.host, config.port)).await?;
    loop {
        let (stream, peer) = listener.accept().await?;
        stream.set_nodelay(true)?;
        let config = config.clone();
        let connector = connector.clone();
        let logger = logger.clone();
        tokio::spawn(async move {
            if let Err(error) = handle(stream, &config, &connector).await {
                logger.record(Level::Debug, &format!("SOCKS client {peer}: {error}"));
            }
        });
    }
}

async fn handle<S>(mut stream: S, config: &Socks, connector: &Connector) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match stream.read_u8().await? {
        4 => handle_v4(stream, config, connector).await,
        5 => handle_v5(stream, config, connector).await,
        _ => Err(Error::Protocol("unknown SOCKS version".to_owned())),
    }
}

async fn handle_v5<S>(mut stream: S, config: &Socks, connector: &Connector) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let methods_len = stream.read_u8().await? as usize;
    if methods_len == 0 {
        return Err(Error::Protocol("SOCKS5 method list is empty".to_owned()));
    }
    let mut methods = vec![0_u8; methods_len];
    stream.read_exact(&mut methods).await?;
    let method = if config.user.is_some() { 2 } else { 0 };
    if !methods.contains(&method) {
        stream.write_all(&[5, 0xff]).await?;
        return Err(Error::Authentication(
            "SOCKS5 client offered no acceptable authentication".to_owned(),
        ));
    }
    stream.write_all(&[5, method]).await?;
    stream.flush().await?;

    if method == 2 {
        authenticate_v5(&mut stream, config).await?;
    }

    if stream.read_u8().await? != 5 {
        return Err(Error::Protocol("invalid SOCKS5 request version".to_owned()));
    }
    let command = stream.read_u8().await?;
    let reserved = stream.read_u8().await?;
    if reserved != 0 {
        write_v5_reply(&mut stream, 1).await?;
        return Err(Error::Protocol("invalid SOCKS5 reserved byte".to_owned()));
    }
    match command {
        1 => handle_v5_connect(stream, connector).await,
        3 => handle_v5_udp_associate(stream, config, connector).await,
        _ => {
            write_v5_reply(&mut stream, 7).await?;
            Err(Error::Protocol(
                "SOCKS5 supports only CONNECT and UDP ASSOCIATE".to_owned(),
            ))
        }
    }
}

async fn handle_v5_connect<S>(mut stream: S, connector: &Connector) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let target = match read_v5_target(&mut stream).await {
        Ok(target) => target,
        Err(error) => {
            write_v5_reply(&mut stream, 8).await?;
            return Err(error);
        }
    };
    let outbound = match connector.connect(&target).await {
        Ok(outbound) => outbound,
        Err(error) => {
            write_v5_reply(&mut stream, 1).await?;
            return Err(error);
        }
    };
    write_v5_reply(&mut stream, 0).await?;
    outbound.relay(stream).await
}

/// Implements SOCKS5 `UDP ASSOCIATE` (RFC 1928 section 7): the client keeps
/// this TCP connection open for the lifetime of the association and sends
/// its datagrams, each wrapped in a small SOCKS5 UDP header carrying the
/// real destination, to a dedicated relay socket whose address is returned
/// in this reply. One destination gets its own outbound flow (direct
/// socket or tunnel `Udp` stream, chosen by the same routing rules as
/// `CONNECT`), the same way a `tun` flow is per 4-tuple.
async fn handle_v5_udp_associate<S>(
    mut stream: S,
    config: &Socks,
    connector: &Connector,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // The client's own advertised source address is advisory only (many
    // clients send 0.0.0.0:0 since their outbound NAT address is unknown in
    // advance); read and discard it without requiring a non-zero port.
    if let Err(error) = skip_v5_address(&mut stream).await {
        write_v5_reply(&mut stream, 1).await?;
        return Err(error);
    }

    let relay = match UdpSocket::bind((config.host, 0)).await {
        Ok(relay) => relay,
        Err(error) => {
            write_v5_reply(&mut stream, 1).await?;
            return Err(error.into());
        }
    };
    let relay_port = relay.local_addr()?.port();
    write_v5_reply_addr(&mut stream, 0, config.host, relay_port).await?;

    let relay = Arc::new(relay);
    let mut flows: HashMap<Target, mpsc::UnboundedSender<(SocketAddr, Vec<u8>)>> = HashMap::new();
    let mut buffer = vec![0_u8; MAX_UDP_DATAGRAM];

    // The association lives exactly as long as this TCP connection: block
    // on it going idle-to-EOF/error while servicing datagrams, per RFC 1928.
    let mut control = [0_u8; 1];
    loop {
        tokio::select! {
            received = relay.recv_from(&mut buffer) => {
                let (length, app_addr) = received?;
                let Some((target, payload)) = parse_v5_udp_datagram(&buffer[..length]) else {
                    continue;
                };
                let key = target.clone();
                let sender = flows.entry(key.clone()).or_insert_with(|| {
                    spawn_udp_flow(connector.clone(), target, relay.clone())
                });
                if sender.send((app_addr, payload.to_vec())).is_err() {
                    flows.remove(&key);
                }
            }
            result = stream.read(&mut control) => {
                match result {
                    Ok(0) | Err(_) => return Ok(()),
                    Ok(_) => continue,
                }
            }
        }
    }
}

/// Spawns the task that owns one destination's outbound flow (direct UDP
/// socket or tunnel `Udp` stream) and pumps datagrams in both directions,
/// writing replies back through the shared relay socket wrapped in a
/// SOCKS5 UDP reply header.
fn spawn_udp_flow(
    connector: Connector,
    target: Target,
    relay: Arc<UdpSocket>,
) -> mpsc::UnboundedSender<(SocketAddr, Vec<u8>)> {
    let (tx, mut rx) = mpsc::unbounded_channel::<(SocketAddr, Vec<u8>)>();
    tokio::spawn(async move {
        let outbound = match connector.connect_udp(&target).await {
            Ok(outbound) => outbound,
            Err(_) => return,
        };
        let last_app_addr: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
        match outbound {
            UdpOutbound::Direct(socket) => {
                let socket = Arc::new(socket);
                let reply_relay = relay.clone();
                let reply_target = target.clone();
                let reply_app_addr = last_app_addr.clone();
                let reply_socket = socket.clone();
                let replies = tokio::spawn(async move {
                    let mut buffer = vec![0_u8; MAX_UDP_DATAGRAM];
                    loop {
                        let Ok(length) = reply_socket.recv(&mut buffer).await else {
                            return;
                        };
                        let Some(app_addr) = *reply_app_addr.lock().unwrap() else {
                            continue;
                        };
                        if let Ok(datagram) =
                            build_v5_udp_datagram(&reply_target, &buffer[..length])
                        {
                            let _ = reply_relay.send_to(&datagram, app_addr).await;
                        }
                    }
                });
                while let Some((app_addr, payload)) = rx.recv().await {
                    *last_app_addr.lock().unwrap() = Some(app_addr);
                    if socket.send(&payload).await.is_err() {
                        break;
                    }
                }
                replies.abort();
            }
            UdpOutbound::Proxy(mut protected) => {
                loop {
                    tokio::select! {
                        outbound = rx.recv() => {
                            match outbound {
                                Some((app_addr, payload)) => {
                                    *last_app_addr.lock().unwrap() = Some(app_addr);
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
                                    let Some(app_addr) = *last_app_addr.lock().unwrap() else {
                                        continue;
                                    };
                                    if let Ok(datagram) = build_v5_udp_datagram(&target, &payload) {
                                        let _ = relay.send_to(&datagram, app_addr).await;
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
    tx
}

/// Consumes and discards a SOCKS5 address+port pair (the format used by
/// both `read_v5_target` and the UDP ASSOCIATE request), without requiring
/// a non-zero port the way [`Target::new`] does.
async fn skip_v5_address<S>(stream: &mut S) -> Result<()>
where
    S: AsyncRead + Unpin,
{
    match stream.read_u8().await? {
        1 => {
            let mut octets = [0_u8; 4];
            stream.read_exact(&mut octets).await?;
        }
        3 => {
            let length = stream.read_u8().await? as usize;
            let mut domain = vec![0_u8; length];
            stream.read_exact(&mut domain).await?;
        }
        4 => {
            let mut octets = [0_u8; 16];
            stream.read_exact(&mut octets).await?;
        }
        _ => return Err(Error::Protocol("unknown SOCKS5 address type".to_owned())),
    }
    stream.read_u16().await?;
    Ok(())
}

/// Parses one client-sent SOCKS5 UDP datagram (RSV/FRAG/ATYP/ADDR/PORT/DATA)
/// into its destination [`Target`] and remaining payload. Fragmented
/// datagrams (`FRAG != 0`) are not supported and are dropped, matching most
/// minimal SOCKS5 UDP relay implementations.
fn parse_v5_udp_datagram(data: &[u8]) -> Option<(Target, &[u8])> {
    if data.len() < 4 || data[0] != 0 || data[1] != 0 || data[2] != 0 {
        return None;
    }
    let (host, offset) = match data[3] {
        1 if data.len() >= 10 => (
            TargetHost::Ip(IpAddr::V4(Ipv4Addr::from(
                <[u8; 4]>::try_from(&data[4..8]).ok()?,
            ))),
            8,
        ),
        4 if data.len() >= 22 => (
            TargetHost::Ip(IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&data[4..20]).ok()?,
            ))),
            20,
        ),
        3 if data.len() >= 5 => {
            let length = data[4] as usize;
            let end = 5_usize.checked_add(length)?;
            if data.len() < end + 2 {
                return None;
            }
            let domain = std::str::from_utf8(&data[5..end]).ok()?.to_owned();
            (TargetHost::Domain(domain), end)
        }
        _ => return None,
    };
    let port = u16::from_be_bytes(data.get(offset..offset + 2)?.try_into().ok()?);
    let target = Target::new(host, port.max(1)).ok()?;
    Some((target, data.get(offset + 2..)?))
}

/// Builds one server-to-client SOCKS5 UDP reply datagram carrying `payload`
/// and reporting `target` as its origin.
fn build_v5_udp_datagram(target: &Target, payload: &[u8]) -> Result<Vec<u8>> {
    let mut datagram = vec![0_u8, 0, 0];
    match &target.host {
        TargetHost::Ip(IpAddr::V4(ip)) => {
            datagram.push(1);
            datagram.extend_from_slice(&ip.octets());
        }
        TargetHost::Ip(IpAddr::V6(ip)) => {
            datagram.push(4);
            datagram.extend_from_slice(&ip.octets());
        }
        TargetHost::Domain(domain) => {
            let length = u8::try_from(domain.len())
                .map_err(|_| Error::Protocol("target domain is too long".to_owned()))?;
            datagram.push(3);
            datagram.push(length);
            datagram.extend_from_slice(domain.as_bytes());
        }
    }
    datagram.extend_from_slice(&target.port.to_be_bytes());
    datagram.extend_from_slice(payload);
    Ok(datagram)
}

async fn write_v5_reply_addr<S>(stream: &mut S, status: u8, host: IpAddr, port: u16) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut reply = vec![5, status, 0];
    match host {
        IpAddr::V4(ip) => {
            reply.push(1);
            reply.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            reply.push(4);
            reply.extend_from_slice(&ip.octets());
        }
    }
    reply.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&reply).await?;
    stream.flush().await?;
    Ok(())
}

async fn authenticate_v5<S>(stream: &mut S, config: &Socks) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if stream.read_u8().await? != 1 {
        return Err(Error::Authentication(
            "invalid SOCKS5 authentication version".to_owned(),
        ));
    }
    let user_len = stream.read_u8().await? as usize;
    let mut user = vec![0_u8; user_len];
    stream.read_exact(&mut user).await?;
    let pass_len = stream.read_u8().await? as usize;
    let mut pass = vec![0_u8; pass_len];
    stream.read_exact(&mut pass).await?;
    let valid = credentials_match(config.user.as_deref().unwrap_or_default(), &user)
        & credentials_match(config.pass.as_deref().unwrap_or_default(), &pass);
    stream.write_all(&[1, u8::from(!valid)]).await?;
    stream.flush().await?;
    if !valid {
        return Err(Error::Authentication(
            "invalid SOCKS5 credentials".to_owned(),
        ));
    }
    Ok(())
}

async fn read_v5_target<S>(stream: &mut S) -> Result<Target>
where
    S: AsyncRead + Unpin,
{
    let host = match stream.read_u8().await? {
        1 => {
            let mut octets = [0_u8; 4];
            stream.read_exact(&mut octets).await?;
            TargetHost::Ip(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        3 => {
            let length = stream.read_u8().await? as usize;
            if length == 0 {
                return Err(Error::Protocol("empty SOCKS5 domain".to_owned()));
            }
            let mut domain = vec![0_u8; length];
            stream.read_exact(&mut domain).await?;
            TargetHost::Domain(
                String::from_utf8(domain)
                    .map_err(|_| Error::Protocol("SOCKS5 domain is not UTF-8".to_owned()))?,
            )
        }
        4 => {
            let mut octets = [0_u8; 16];
            stream.read_exact(&mut octets).await?;
            TargetHost::Ip(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => return Err(Error::Protocol("unknown SOCKS5 address type".to_owned())),
    };
    Target::new(host, stream.read_u16().await?)
}

async fn write_v5_reply<S>(stream: &mut S, status: u8) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream
        .write_all(&[5, status, 0, 1, 0, 0, 0, 0, 0, 0])
        .await?;
    stream.flush().await?;
    Ok(())
}

async fn handle_v4<S>(mut stream: S, config: &Socks, connector: &Connector) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let command = stream.read_u8().await?;
    let port = stream.read_u16().await?;
    let mut address = [0_u8; 4];
    stream.read_exact(&mut address).await?;
    let _user = read_cstring(&mut stream).await?;
    if command != 1 || config.user.is_some() {
        write_v4_reply(&mut stream, 91, port, address).await?;
        return Err(Error::Protocol(
            "SOCKS4 request or authentication is unsupported".to_owned(),
        ));
    }
    let host = if address[..3] == [0, 0, 0] && address[3] != 0 {
        let domain = read_cstring(&mut stream).await?;
        TargetHost::Domain(
            String::from_utf8(domain)
                .map_err(|_| Error::Protocol("SOCKS4a domain is not UTF-8".to_owned()))?,
        )
    } else {
        TargetHost::Ip(IpAddr::V4(Ipv4Addr::from(address)))
    };
    let target = Target::new(host, port)?;
    let outbound = match connector.connect(&target).await {
        Ok(outbound) => outbound,
        Err(error) => {
            write_v4_reply(&mut stream, 91, port, address).await?;
            return Err(error);
        }
    };
    write_v4_reply(&mut stream, 90, port, address).await?;
    outbound.relay(stream).await
}

async fn read_cstring<S>(stream: &mut S) -> Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut value = Vec::new();
    loop {
        let byte = stream.read_u8().await?;
        if byte == 0 {
            return Ok(value);
        }
        if value.len() == MAX_TEXT_FIELD {
            return Err(Error::Protocol("SOCKS4 field is too long".to_owned()));
        }
        value.push(byte);
    }
}

async fn write_v4_reply<S>(stream: &mut S, status: u8, port: u16, address: [u8; 4]) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut reply = [0_u8; 8];
    reply[1] = status;
    reply[2..4].copy_from_slice(&port.to_be_bytes());
    reply[4..].copy_from_slice(&address);
    stream.write_all(&reply).await?;
    stream.flush().await?;
    Ok(())
}

fn credentials_match(expected: &str, actual: &[u8]) -> bool {
    expected.len() == actual.len() && bool::from(expected.as_bytes().ct_eq(actual))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::sync::watch;

    use super::*;
    use crate::routing::{Action, Rule, RuleSet};

    fn direct_connector() -> Connector {
        let mut rules = RuleSet {
            rules: vec![Rule::Any {
                action: Action::Direct,
            }],
        };
        rules.normalize_and_validate().unwrap();
        let (_, sessions) = watch::channel(None);
        Connector::new(sessions, Some(Arc::new(rules)))
    }

    fn config() -> Socks {
        Socks {
            pass: None,
            user: None,
            host: "127.0.0.1".parse().unwrap(),
            port: 1080,
            listen: true,
        }
    }

    #[tokio::test]
    async fn detects_and_proxies_socks5_connect() {
        let destination = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = destination.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut stream, _) = destination.accept().await.unwrap();
            let value = stream.read_u8().await.unwrap();
            stream.write_u8(value + 1).await.unwrap();
        });
        let (mut client, server) = tokio::io::duplex(1024);
        let handler =
            tokio::spawn(async move { handle(server, &config(), &direct_connector()).await });
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0_u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);
        let mut request = vec![5, 1, 0, 1];
        request.extend_from_slice(&match address.ip() {
            IpAddr::V4(ip) => ip.octets(),
            IpAddr::V6(_) => unreachable!(),
        });
        request.extend_from_slice(&address.port().to_be_bytes());
        client.write_all(&request).await.unwrap();
        let mut reply = [0_u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0);
        client.write_u8(4).await.unwrap();
        assert_eq!(client.read_u8().await.unwrap(), 5);
        drop(client);
        handler.await.unwrap().unwrap();
        echo.await.unwrap();
    }

    #[tokio::test]
    async fn detects_and_proxies_socks4_connect() {
        let destination = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = destination.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut stream, _) = destination.accept().await.unwrap();
            stream.write_u8(9).await.unwrap();
        });
        let (mut client, server) = tokio::io::duplex(1024);
        let handler =
            tokio::spawn(async move { handle(server, &config(), &direct_connector()).await });
        let mut request = vec![4, 1];
        request.extend_from_slice(&address.port().to_be_bytes());
        request.extend_from_slice(&[127, 0, 0, 1, 0]);
        client.write_all(&request).await.unwrap();
        let mut reply = [0_u8; 8];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 90);
        assert_eq!(client.read_u8().await.unwrap(), 9);
        drop(client);
        handler.await.unwrap().unwrap();
        echo.await.unwrap();
    }

    #[tokio::test]
    async fn socks5_udp_associate_relays_a_datagram_round_trip() {
        let destination = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let destination_address = destination.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let mut buffer = [0_u8; 64];
            let (length, peer) = destination.recv_from(&mut buffer).await.unwrap();
            destination.send_to(&buffer[..length], peer).await.unwrap();
        });

        let (mut client, server) = tokio::io::duplex(1024);
        let handler =
            tokio::spawn(async move { handle(server, &config(), &direct_connector()).await });

        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0_u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);

        // UDP ASSOCIATE, advertising the conventional "unknown yet" address.
        client
            .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut reply_header = [0_u8; 4];
        client.read_exact(&mut reply_header).await.unwrap();
        assert_eq!(reply_header[..2], [5, 0]);
        assert_eq!(reply_header[3], 1, "IPv4 BND.ADDR expected");
        let mut reply_addr = [0_u8; 6];
        client.read_exact(&mut reply_addr).await.unwrap();
        let relay_port = u16::from_be_bytes([reply_addr[4], reply_addr[5]]);
        let relay_address: SocketAddr = ([127, 0, 0, 1], relay_port).into();

        let app = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut datagram = vec![0_u8, 0, 0, 1];
        datagram.extend_from_slice(&match destination_address.ip() {
            IpAddr::V4(ip) => ip.octets(),
            IpAddr::V6(_) => unreachable!(),
        });
        datagram.extend_from_slice(&destination_address.port().to_be_bytes());
        datagram.extend_from_slice(b"hello");
        app.send_to(&datagram, relay_address).await.unwrap();

        let mut buffer = [0_u8; 64];
        let (length, from) =
            tokio::time::timeout(Duration::from_secs(2), app.recv_from(&mut buffer))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(from, relay_address);
        let (target, payload) = parse_v5_udp_datagram(&buffer[..length]).unwrap();
        assert_eq!(target.port, destination_address.port());
        assert_eq!(payload, b"hello");

        drop(client);
        handler.await.unwrap().unwrap();
        echo.await.unwrap();
    }
}
