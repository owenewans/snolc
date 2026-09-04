use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::config::Http;
use crate::error::{Error, Result};
use crate::logging::{Level, Logger};
use crate::outbound::Connector;
use crate::tunnel::{Target, TargetHost};

const MAX_HEADER: usize = 64 * 1024;

pub async fn serve(config: Http, connector: Connector, logger: Logger) -> Result<()> {
    if config.tls.as_ref().is_some_and(|tls| tls.enabled) {
        return Err(Error::Carrier(
            "HTTP inbound TLS is not available in this build".to_owned(),
        ));
    }
    let listener = TcpListener::bind((config.host, config.port)).await?;
    loop {
        let (stream, peer) = listener.accept().await?;
        stream.set_nodelay(true)?;
        let config = config.clone();
        let connector = connector.clone();
        let logger = logger.clone();
        tokio::spawn(async move {
            if let Err(error) = handle(stream, &config, &connector).await {
                logger.record(Level::Debug, &format!("HTTP client {peer}: {error}"));
            }
        });
    }
}

async fn handle<S>(mut stream: S, config: &Http, connector: &Connector) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let header = read_header(&mut stream).await?;
    let request = match Request::parse(&header) {
        Ok(request) => request,
        Err(error) => {
            write_response(&mut stream, 400, "Bad Request").await?;
            return Err(error);
        }
    };
    if !request.authenticated(config) {
        stream
            .write_all(
                b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"snolc\"\r\nContent-Length: 0\r\n\r\n",
            )
            .await?;
        stream.flush().await?;
        return Err(Error::Authentication(
            "invalid HTTP proxy credentials".to_owned(),
        ));
    }

    let (target, forward) = match request.destination() {
        Ok(value) => value,
        Err(error) => {
            write_response(&mut stream, 400, "Bad Request").await?;
            return Err(error);
        }
    };
    let mut outbound = match connector.connect(&target).await {
        Ok(outbound) => outbound,
        Err(error) => {
            write_response(&mut stream, 502, "Bad Gateway").await?;
            return Err(error);
        }
    };

    if request.method.eq_ignore_ascii_case("CONNECT") {
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        stream.flush().await?;
    } else {
        outbound.send(&forward).await?;
    }
    outbound.relay(stream).await
}

struct Request<'a> {
    method: &'a str,
    target: &'a str,
    version: &'a str,
    headers: Vec<(&'a str, &'a str)>,
}

impl<'a> Request<'a> {
    fn parse(source: &'a str) -> Result<Self> {
        let mut lines = source
            .strip_suffix("\r\n\r\n")
            .ok_or_else(|| Error::Protocol("incomplete HTTP header".to_owned()))?
            .split("\r\n");
        let request_line = lines
            .next()
            .ok_or_else(|| Error::Protocol("missing HTTP request line".to_owned()))?;
        let mut parts = request_line.split(' ');
        let method = parts
            .next()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| Error::Protocol("missing HTTP method".to_owned()))?;
        let target = parts
            .next()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| Error::Protocol("missing HTTP target".to_owned()))?;
        let version = parts
            .next()
            .filter(|value| matches!(*value, "HTTP/1.0" | "HTTP/1.1"))
            .ok_or_else(|| Error::Protocol("unsupported HTTP version".to_owned()))?;
        if parts.next().is_some() {
            return Err(Error::Protocol("invalid HTTP request line".to_owned()));
        }

        let headers = lines
            .map(|line| {
                let (name, value) = line
                    .split_once(':')
                    .ok_or_else(|| Error::Protocol("invalid HTTP header".to_owned()))?;
                if name.is_empty()
                    || !name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
                {
                    return Err(Error::Protocol("invalid HTTP header name".to_owned()));
                }
                Ok((name, value.trim()))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            method,
            target,
            version,
            headers,
        })
    }

    fn authenticated(&self, config: &Http) -> bool {
        let (Some(user), Some(pass)) = (&config.user, &config.pass) else {
            return true;
        };
        let expected = STANDARD.encode(format!("{user}:{pass}"));
        self.header("proxy-authorization")
            .and_then(|value| value.split_once(' '))
            .is_some_and(|(scheme, actual)| {
                scheme.eq_ignore_ascii_case("basic")
                    && expected.len() == actual.len()
                    && bool::from(expected.as_bytes().ct_eq(actual.as_bytes()))
            })
    }

    fn destination(&self) -> Result<(Target, Vec<u8>)> {
        if self.method.eq_ignore_ascii_case("CONNECT") {
            return Ok((parse_authority(self.target, None)?, Vec::new()));
        }

        let (authority, path) = if let Some(rest) = self.target.strip_prefix("http://") {
            match rest.find('/') {
                Some(index) => (&rest[..index], &rest[index..]),
                None => (rest, "/"),
            }
        } else if self.target.starts_with('/') {
            (
                self.header("host")
                    .ok_or_else(|| Error::Protocol("HTTP request has no Host".to_owned()))?,
                self.target,
            )
        } else {
            return Err(Error::Protocol(
                "HTTP proxy target must be absolute or origin-form".to_owned(),
            ));
        };
        let target = parse_authority(authority, Some(80))?;
        let mut forward = format!("{} {path} {}\r\n", self.method, self.version);
        for (name, value) in &self.headers {
            if name.eq_ignore_ascii_case("proxy-authorization")
                || name.eq_ignore_ascii_case("proxy-connection")
            {
                continue;
            }
            forward.push_str(name);
            forward.push_str(": ");
            forward.push_str(value);
            forward.push_str("\r\n");
        }
        forward.push_str("\r\n");
        Ok((target, forward.into_bytes()))
    }

    fn header(&self, wanted: &str) -> Option<&'a str> {
        self.headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(wanted))
            .map(|(_, value)| *value)
    }
}

fn parse_authority(authority: &str, default_port: Option<u16>) -> Result<Target> {
    if authority.is_empty() || authority.contains('@') {
        return Err(Error::Protocol("invalid HTTP authority".to_owned()));
    }
    let (host, port) = if authority.starts_with('[') {
        let closing = authority
            .find(']')
            .ok_or_else(|| Error::Protocol("invalid bracketed IPv6 authority".to_owned()))?;
        let host = &authority[1..closing];
        let tail = &authority[closing + 1..];
        let port = if tail.is_empty() {
            default_port.ok_or_else(|| Error::Protocol("HTTP authority has no port".to_owned()))?
        } else {
            tail.strip_prefix(':')
                .ok_or_else(|| Error::Protocol("invalid HTTP authority suffix".to_owned()))?
                .parse::<u16>()
                .map_err(|_| Error::Protocol("invalid HTTP authority port".to_owned()))?
        };
        (host, port)
    } else if authority.matches(':').count() == 1 {
        let (host, port) = authority
            .rsplit_once(':')
            .ok_or_else(|| Error::Protocol("invalid HTTP authority".to_owned()))?;
        let port = port
            .parse::<u16>()
            .map_err(|_| Error::Protocol("invalid HTTP authority port".to_owned()))?;
        (host, port)
    } else if authority.contains(':') {
        return Err(Error::Protocol(
            "IPv6 HTTP authority must use brackets".to_owned(),
        ));
    } else {
        (
            authority,
            default_port.ok_or_else(|| Error::Protocol("HTTP authority has no port".to_owned()))?,
        )
    };
    let host = match host.parse() {
        Ok(ip) => TargetHost::Ip(ip),
        Err(_) => TargetHost::Domain(host.to_owned()),
    };
    Target::new(host, port)
}

async fn read_header<S>(stream: &mut S) -> Result<String>
where
    S: AsyncRead + Unpin,
{
    let mut header = Vec::with_capacity(1024);
    while header.len() < MAX_HEADER {
        header.push(stream.read_u8().await?);
        if header.ends_with(b"\r\n\r\n") {
            return String::from_utf8(header)
                .map_err(|_| Error::Protocol("HTTP header is not UTF-8".to_owned()));
        }
    }
    Err(Error::Protocol("HTTP header is too large".to_owned()))
}

async fn write_response<S>(stream: &mut S, status: u16, reason: &str) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream
        .write_all(format!("HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\n\r\n").as_bytes())
        .await?;
    stream.flush().await?;
    Ok(())
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

    fn config() -> Http {
        Http {
            pass: None,
            user: None,
            host: "127.0.0.1".parse().unwrap(),
            port: 8080,
            tls: None,
            listen: true,
        }
    }

    #[tokio::test]
    async fn connect_opens_a_bidirectional_tunnel() {
        let destination = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = destination.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut stream, _) = destination.accept().await.unwrap();
            let value = stream.read_u8().await.unwrap();
            stream.write_u8(value + 1).await.unwrap();
        });
        let (mut client, server) = tokio::io::duplex(4096);
        let handler =
            tokio::spawn(async move { handle(server, &config(), &direct_connector()).await });
        client
            .write_all(format!("CONNECT {address} HTTP/1.1\r\nHost: {address}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let response = read_header(&mut client).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 200"));
        client.write_u8(10).await.unwrap();
        assert_eq!(client.read_u8().await.unwrap(), 11);
        drop(client);
        handler.await.unwrap().unwrap();
        echo.await.unwrap();
    }

    #[tokio::test]
    async fn absolute_form_is_rewritten_before_forwarding() {
        let destination = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = destination.local_addr().unwrap();
        let origin = tokio::spawn(async move {
            let (mut stream, _) = destination.accept().await.unwrap();
            let request = read_header(&mut stream).await.unwrap();
            assert!(request.starts_with("GET /resource HTTP/1.1\r\n"));
            assert!(!request.to_ascii_lowercase().contains("proxy-connection"));
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });
        let (mut client, server) = tokio::io::duplex(4096);
        let handler =
            tokio::spawn(async move { handle(server, &config(), &direct_connector()).await });
        client
            .write_all(
                format!(
                    "GET http://{address}/resource HTTP/1.1\r\nHost: {address}\r\nProxy-Connection: keep-alive\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let response = read_header(&mut client).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 204"));
        drop(client);
        handler.await.unwrap().unwrap();
        origin.await.unwrap();
    }
}
