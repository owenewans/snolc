use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::config::{Carrier, CarrierTls};
use crate::error::{Error, Result};
use crate::logging::{Level, Logger};
use crate::mirror;
use crate::{acme, steal};

const MAX_HTTP_HEADER: usize = 16 * 1024;

/// A carrier connection regardless of its concrete transport: plain TCP
/// (camouflaged with an HTTP CONNECT preface), a steal-mode TCP connection
/// (camouflaged by a one-shot fake TLS ClientHello), or a real TLS
/// connection in "self"/acme mode.
pub trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Duplex for T {}
pub type BoxedStream = Box<dyn Duplex>;

/// The outcome of accepting one inbound connection on the carrier's port.
pub enum Accepted {
    /// A connection that should proceed to the snolc handshake.
    Tunnel(BoxedStream),
    /// The connection was fully handled here (an ACME challenge response, or
    /// a mirror splice to a donor/fallback target) and is already closed;
    /// there is nothing more for the caller to do.
    Handled,
}

/// Long-lived, carrier-specific state built once at startup and reused for
/// every connection: the ACME certificate resolver (self mode) and the
/// mirror response cache (steal mode's donor fallback), if applicable.
pub struct CarrierRuntime {
    config: Carrier,
    acme: Option<Arc<acme::AcmeAcceptor>>,
    mirror_cache: Option<Arc<mirror::Cache>>,
    logger: Logger,
}

impl CarrierRuntime {
    pub fn client(config: Carrier) -> Self {
        Self {
            config,
            acme: None,
            mirror_cache: None,
            logger: Logger::disabled(),
        }
    }

    pub async fn server(config: Carrier, logger: Logger) -> Result<Self> {
        let acme = match config.tls() {
            Some(CarrierTls::Acme { domain, cache, .. }) => Some(Arc::new(
                acme::AcmeAcceptor::start(domain.clone(), cache.clone(), logger.clone()),
            )),
            _ => None,
        };
        let mirror_cache = match config.tls() {
            Some(CarrierTls::Steal { mirror, .. }) if mirror.cache => Some(Arc::new(
                mirror::Cache::new(Duration::from_secs(mirror.ttl)),
            )),
            _ => None,
        };
        Ok(Self {
            config,
            acme,
            mirror_cache,
            logger,
        })
    }

    pub async fn connect(&self, remote: &str) -> Result<BoxedStream> {
        match &self.config {
            Carrier::Http {
                host,
                path,
                tls: None,
                ..
            } => {
                let mut stream = TcpStream::connect(remote).await?;
                stream.set_nodelay(true)?;
                client_http_preface(&mut stream, host, path).await?;
                Ok(Box::new(stream))
            }
            Carrier::Http {
                tls: Some(CarrierTls::Acme { domain, .. }),
                ..
            } => {
                let stream = TcpStream::connect(remote).await?;
                stream.set_nodelay(true)?;
                acme::connect(stream, domain).await
            }
            Carrier::Http {
                tls: Some(CarrierTls::Steal { donor, secret, .. }),
                ..
            } => {
                let mut stream = TcpStream::connect(remote).await?;
                stream.set_nodelay(true)?;
                let secret = decode_secret(secret)?;
                let hello = steal::client_hello(donor, &secret)?;
                stream.write_all(&hello).await?;
                stream.flush().await?;
                Ok(Box::new(stream))
            }
            Carrier::Ssh { .. } => {
                let stream = TcpStream::connect(remote).await?;
                stream.set_nodelay(true)?;
                crate::ssh::connect(stream).await
            }
            Carrier::Webrtc { .. } => Err(Error::Carrier(
                "WebRTC carrier is not available in this build".to_owned(),
            )),
            Carrier::Socks { .. } => Err(Error::Carrier(
                "SOCKS carrier is not available in this build".to_owned(),
            )),
        }
    }

    pub async fn accept(&self, mut stream: TcpStream) -> Result<Accepted> {
        match &self.config {
            Carrier::Http {
                host,
                path,
                tls: None,
                ..
            } => {
                server_http_preface(&mut stream, host, path).await?;
                Ok(Accepted::Tunnel(Box::new(stream)))
            }
            Carrier::Http {
                tls: Some(CarrierTls::Acme { .. }),
                ..
            } => {
                let acceptor = self
                    .acme
                    .as_ref()
                    .expect("acme carrier always builds an acceptor in CarrierRuntime::server");
                match acceptor.accept(stream).await? {
                    Some(tls) => Ok(Accepted::Tunnel(tls)),
                    None => Ok(Accepted::Handled),
                }
            }
            Carrier::Http {
                tls: Some(CarrierTls::Steal { donor, secret, .. }),
                ..
            } => {
                let secret = decode_secret(secret)?;
                // The donor is always contacted over TLS on 443; the
                // hostname alone (as validated in the config) is not a
                // dialable address.
                let target = format!("{donor}:443");
                let outcome = steal::accept(&mut stream, &secret, donor).await?;
                match outcome {
                    steal::Accept::Authenticated => {
                        self.logger.record(Level::Debug, "steal: authenticated");
                        Ok(Accepted::Tunnel(Box::new(stream)))
                    }
                    // A complete ClientHello record was captured: safe to
                    // treat as one request and, if configured, cache its
                    // response.
                    steal::Accept::Unauthenticated {
                        prefix,
                        complete: true,
                    } => {
                        self.logger.record(
                            Level::Debug,
                            &format!("steal: mirroring an unrecognized client to {target}"),
                        );
                        mirror::serve(stream, &target, &prefix, self.mirror_cache.as_deref())
                            .await?;
                        Ok(Accepted::Handled)
                    }
                    // Only a partial read: relay live, uncached, so nothing
                    // waits on a request that was never fully forwarded.
                    steal::Accept::Unauthenticated {
                        prefix,
                        complete: false,
                    } => {
                        self.logger.record(
                            Level::Debug,
                            &format!("steal: mirroring a non-TLS-shaped connection to {target}"),
                        );
                        mirror::splice(stream, &target, &prefix).await?;
                        Ok(Accepted::Handled)
                    }
                }
            }
            // The SSH server accept loop is structurally different (russh
            // hands channels to a Handler callback rather than returning a
            // stream synchronously) and is run directly by
            // `runtime::run_server`, not through this method.
            Carrier::Ssh { .. } => Err(Error::Carrier(
                "SSH carrier connections are not accepted through CarrierRuntime::accept"
                    .to_owned(),
            )),
            Carrier::Webrtc { .. } => Err(Error::Carrier(
                "WebRTC carrier requires a UDP listener".to_owned(),
            )),
            Carrier::Socks { .. } => Err(Error::Carrier(
                "SOCKS carrier is not available in this build".to_owned(),
            )),
        }
    }
}

fn decode_secret(value: &str) -> Result<[u8; 32]> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|_| Error::Config("steal secret is not base64".to_owned()))?;
    bytes
        .try_into()
        .map_err(|_| Error::Config("steal secret must contain 32 bytes".to_owned()))
}

pub(crate) async fn client_http_preface<S>(stream: &mut S, host: &str, path: &str) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = format!(
        "CONNECT {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nProxy-Connection: keep-alive\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;
    let response = read_http_header(stream).await?;
    let status = response
        .split("\r\n")
        .next()
        .ok_or_else(|| Error::Carrier("empty HTTP carrier response".to_owned()))?;
    if status != "HTTP/1.1 200 Connection Established"
        && status != "HTTP/1.0 200 Connection Established"
    {
        return Err(Error::Carrier(
            "HTTP carrier rejected the connection".to_owned(),
        ));
    }
    Ok(())
}

async fn server_http_preface<S>(stream: &mut S, host: &str, path: &str) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = read_http_header(stream).await?;
    let mut lines = request.split("\r\n");
    let expected = format!("CONNECT {path} HTTP/1.1");
    if lines.next() != Some(expected.as_str()) {
        return Err(Error::Carrier("invalid HTTP carrier request".to_owned()));
    }
    let host_matches = lines
        .filter_map(|line| line.split_once(':'))
        .any(|(name, value)| {
            name.eq_ignore_ascii_case("host") && value.trim().eq_ignore_ascii_case(host)
        });
    if !host_matches {
        return Err(Error::Carrier("HTTP carrier host mismatch".to_owned()));
    }
    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\nContent-Length: 0\r\n\r\n")
        .await?;
    stream.flush().await?;
    Ok(())
}

async fn read_http_header<S>(stream: &mut S) -> Result<String>
where
    S: AsyncRead + Unpin,
{
    let mut header = Vec::with_capacity(512);
    while header.len() < MAX_HTTP_HEADER {
        let byte = stream.read_u8().await?;
        header.push(byte);
        if header.ends_with(b"\r\n\r\n") {
            return String::from_utf8(header)
                .map_err(|_| Error::Carrier("HTTP carrier header is not UTF-8".to_owned()));
        }
    }
    Err(Error::Carrier(
        "HTTP carrier header is too large".to_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn http_connect_preface_is_consumed_before_tunnel_bytes() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            server_http_preface(&mut server, "front.example", "/events")
                .await
                .unwrap();
            server.read_u8().await.unwrap()
        });
        client_http_preface(&mut client, "front.example", "/events")
            .await
            .unwrap();
        client.write_u8(42).await.unwrap();
        assert_eq!(server_task.await.unwrap(), 42);
    }

    #[tokio::test]
    async fn server_rejects_the_wrong_cover_host() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        client
            .write_all(b"CONNECT /events HTTP/1.1\r\nHost: wrong.example\r\n\r\n")
            .await
            .unwrap();
        assert!(
            server_http_preface(&mut server, "front.example", "/events")
                .await
                .is_err()
        );
    }
}
