use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::config::Carrier;
use crate::error::{Error, Result};

const MAX_HTTP_HEADER: usize = 16 * 1024;

pub async fn connect(remote: &str, carrier: &Carrier) -> Result<TcpStream> {
    match carrier {
        Carrier::Http {
            host,
            path,
            tls: None,
            ..
        } => {
            let mut stream = TcpStream::connect(remote).await?;
            stream.set_nodelay(true)?;
            client_http_preface(&mut stream, host, path).await?;
            Ok(stream)
        }
        Carrier::Http { tls: Some(_), .. } => Err(Error::Carrier(
            "HTTP TLS carrier is not available in this build".to_owned(),
        )),
        Carrier::Ssh { .. } => Err(Error::Carrier(
            "SSH carrier is not available in this build".to_owned(),
        )),
        Carrier::Webrtc { .. } => Err(Error::Carrier(
            "WebRTC carrier is not available in this build".to_owned(),
        )),
        Carrier::Socks { .. } => Err(Error::Carrier(
            "SOCKS carrier is not available in this build".to_owned(),
        )),
    }
}

pub async fn accept(stream: &mut TcpStream, carrier: &Carrier) -> Result<()> {
    match carrier {
        Carrier::Http {
            host,
            path,
            tls: None,
            ..
        } => server_http_preface(stream, host, path).await,
        Carrier::Http { tls: Some(_), .. } => Err(Error::Carrier(
            "HTTP TLS carrier is not available in this build".to_owned(),
        )),
        Carrier::Ssh { .. } => Err(Error::Carrier(
            "SSH carrier is not available in this build".to_owned(),
        )),
        Carrier::Webrtc { .. } => Err(Error::Carrier(
            "WebRTC carrier requires a UDP listener".to_owned(),
        )),
        Carrier::Socks { .. } => Err(Error::Carrier(
            "SOCKS carrier is not available in this build".to_owned(),
        )),
    }
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
