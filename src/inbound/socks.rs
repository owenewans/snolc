use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::config::Socks;
use crate::error::{Error, Result};
use crate::logging::{Level, Logger};
use crate::outbound::Connector;
use crate::tunnel::{Target, TargetHost};

const MAX_TEXT_FIELD: usize = 255;

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
    if command != 1 || reserved != 0 {
        write_v5_reply(&mut stream, 7).await?;
        return Err(Error::Protocol(
            "SOCKS5 supports only CONNECT at this point".to_owned(),
        ));
    }
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
}
