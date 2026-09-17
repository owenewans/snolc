use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::task::{Context, Poll};

use futures::future::poll_fn;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use thiserror::Error;
use yamux::{Connection, Mode, Stream};

use crate::config::YamuxConfig;
use crate::wire::{
    HEADER_LENGTH, MAX_OPEN_BODY, MAX_POLICY_FAMILY, MAX_REASON, OpenRequest, OpenResponse,
    StreamKind, WireError, encode_open, encode_open_response, encode_policy, parse_header,
    parse_open, parse_open_response, parse_policy,
};

pub struct MuxSession<T> {
    connection: Connection<T>,
    role: Mode,
    policy_open: bool,
    user_streams: usize,
    max_user_streams: usize,
    inbound: VecDeque<Stream>,
}

impl<T> MuxSession<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(io: T, role: Mode, config: &YamuxConfig) -> Self {
        let mut yamux = yamux::Config::default();
        yamux
            .set_max_num_streams(config.max_streams_per_session)
            .set_max_connection_receive_window(Some(config.receive_window_bytes))
            .set_split_send_size(config.split_send_size)
            .set_read_after_close(config.read_after_close);
        Self {
            connection: Connection::new(io, yamux, role),
            role,
            policy_open: false,
            user_streams: 0,
            max_user_streams: config.max_streams_per_session - 1,
            inbound: VecDeque::new(),
        }
    }

    pub async fn open_policy(&mut self, family: &str) -> Result<Stream, MuxError> {
        if self.role != Mode::Client || self.policy_open {
            return Err(MuxError::Protocol);
        }
        let mut stream = self.open_stream().await?;
        self.drive_operation(write_policy(&mut stream, family))
            .await?;
        let response = self.drive_operation(read_policy(&mut stream)).await?;
        if response != family {
            return Err(MuxError::PolicyFamily);
        }
        self.policy_open = true;
        Ok(stream)
    }

    pub async fn accept_policy(&mut self, family: &str) -> Result<Stream, MuxError> {
        if self.role != Mode::Server || self.policy_open {
            return Err(MuxError::Protocol);
        }
        let mut stream = self.accept_stream().await?;
        let request = self.drive_operation(read_policy(&mut stream)).await?;
        if request != family {
            return Err(MuxError::PolicyFamily);
        }
        self.drive_operation(write_policy(&mut stream, family))
            .await?;
        self.policy_open = true;
        Ok(stream)
    }

    pub async fn open_flow(&mut self, request: &OpenRequest) -> Result<Stream, MuxError> {
        if self.role != Mode::Client || !self.policy_open {
            return Err(MuxError::PolicyRequired);
        }
        self.reserve_user_stream()?;
        let mut stream = match self.open_stream().await {
            Ok(stream) => stream,
            Err(error) => {
                self.user_streams -= 1;
                return Err(error);
            }
        };
        if let Err(error) = self.drive_operation(write_open(&mut stream, request)).await {
            self.user_streams -= 1;
            return Err(error);
        }
        Ok(stream)
    }

    pub async fn open_flow_confirmed(
        &mut self,
        request: &OpenRequest,
    ) -> Result<(OpenResponse, Stream), MuxError> {
        let mut stream = self.open_flow(request).await?;
        match self.drive_operation(read_open_response(&mut stream)).await {
            Ok(response) => Ok((response, stream)),
            Err(error) => {
                self.release_flow();
                Err(error)
            }
        }
    }

    pub async fn accept_flow(&mut self) -> Result<(OpenRequest, Stream), MuxError> {
        if self.role != Mode::Server || !self.policy_open {
            return Err(MuxError::PolicyRequired);
        }
        self.reserve_user_stream()?;
        let mut stream = match self.accept_stream().await {
            Ok(stream) => stream,
            Err(error) => {
                self.user_streams -= 1;
                return Err(error);
            }
        };
        let request = match self.drive_operation(read_open(&mut stream)).await {
            Ok(request) => request,
            Err(error) => {
                self.user_streams -= 1;
                return Err(error);
            }
        };
        Ok((request, stream))
    }

    pub async fn respond_flow(
        &mut self,
        stream: &mut Stream,
        response: &OpenResponse,
    ) -> Result<(), MuxError> {
        if self.role != Mode::Server || !self.policy_open {
            return Err(MuxError::PolicyRequired);
        }
        self.drive_operation(write_open_response(stream, response))
            .await
    }

    pub fn release_flow(&mut self) {
        self.user_streams = self.user_streams.saturating_sub(1);
    }

    pub async fn close(&mut self) -> Result<(), MuxError> {
        poll_fn(|context| self.connection.poll_close(context))
            .await
            .map_err(MuxError::Yamux)
    }

    pub fn poll_drive(&mut self, context: &mut Context<'_>) -> Poll<Result<(), MuxError>> {
        match self.connection.poll_next_inbound(context) {
            Poll::Ready(Some(Ok(stream))) if self.role == Mode::Server => {
                if self.inbound.len() >= self.max_user_streams {
                    return Poll::Ready(Err(MuxError::StreamLimit));
                }
                self.inbound.push_back(stream);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Ok(_))) => Poll::Ready(Err(MuxError::Protocol)),
            Poll::Ready(Some(Err(error))) => Poll::Ready(Err(MuxError::Yamux(error))),
            Poll::Ready(None) => Poll::Ready(Err(MuxError::Closed)),
            Poll::Pending => Poll::Pending,
        }
    }

    async fn open_stream(&mut self) -> Result<Stream, MuxError> {
        poll_fn(|context| self.connection.poll_new_outbound(context))
            .await
            .map_err(MuxError::Yamux)
    }

    async fn accept_stream(&mut self) -> Result<Stream, MuxError> {
        if let Some(stream) = self.inbound.pop_front() {
            return Ok(stream);
        }
        poll_fn(|context| self.connection.poll_next_inbound(context))
            .await
            .ok_or(MuxError::Closed)?
            .map_err(MuxError::Yamux)
    }

    async fn drive_operation<F, O>(&mut self, operation: F) -> Result<O, MuxError>
    where
        F: Future<Output = Result<O, MuxError>>,
    {
        futures::pin_mut!(operation);
        let mut completed = None;
        poll_fn(|context| {
            if completed.is_none() {
                match operation.as_mut().poll(context) {
                    Poll::Ready(Ok(output)) => completed = Some(output),
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => {}
                }
            }
            match self.connection.poll_next_inbound(context) {
                Poll::Ready(Some(Err(error))) => Poll::Ready(Err(MuxError::Yamux(error))),
                Poll::Ready(None) => Poll::Ready(Err(MuxError::Closed)),
                Poll::Ready(Some(Ok(_))) => Poll::Ready(Err(MuxError::Protocol)),
                Poll::Pending => match completed.take() {
                    Some(output) => Poll::Ready(Ok(output)),
                    None => Poll::Pending,
                },
            }
        })
        .await
    }

    fn reserve_user_stream(&mut self) -> Result<(), MuxError> {
        if self.user_streams >= self.max_user_streams {
            return Err(MuxError::StreamLimit);
        }
        self.user_streams += 1;
        Ok(())
    }
}

pub async fn write_policy<W: AsyncWrite + Unpin>(
    output: &mut W,
    family: &str,
) -> Result<(), MuxError> {
    let frame = encode_policy(family)?;
    output.write_all(&frame).await?;
    output.flush().await?;
    Ok(())
}

pub async fn read_policy<R: AsyncRead + Unpin>(input: &mut R) -> Result<String, MuxError> {
    let mut header = [0; HEADER_LENGTH + 2];
    input.read_exact(&mut header).await?;
    if parse_header(&header[..HEADER_LENGTH])? != StreamKind::Policy {
        return Err(MuxError::Protocol);
    }
    let length = u16::from_be_bytes([header[HEADER_LENGTH], header[HEADER_LENGTH + 1]]) as usize;
    if !(1..=MAX_POLICY_FAMILY).contains(&length) {
        return Err(MuxError::Wire(WireError::Length));
    }
    let mut frame = Vec::with_capacity(header.len() + length);
    frame.extend_from_slice(&header);
    frame.resize(header.len() + length, 0);
    input.read_exact(&mut frame[header.len()..]).await?;
    parse_policy(&frame).map_err(Into::into)
}

pub async fn write_open<W: AsyncWrite + Unpin>(
    output: &mut W,
    request: &OpenRequest,
) -> Result<(), MuxError> {
    output.write_all(&encode_open(request)?).await?;
    output.flush().await?;
    Ok(())
}

pub async fn read_open<R: AsyncRead + Unpin>(input: &mut R) -> Result<OpenRequest, MuxError> {
    let mut prefix = [0; HEADER_LENGTH + 2];
    input.read_exact(&mut prefix).await?;
    let length = u16::from_be_bytes([prefix[HEADER_LENGTH], prefix[HEADER_LENGTH + 1]]) as usize;
    if length > MAX_OPEN_BODY {
        return Err(MuxError::Wire(WireError::Length));
    }
    let mut frame = Vec::with_capacity(prefix.len() + length);
    frame.extend_from_slice(&prefix);
    frame.resize(prefix.len() + length, 0);
    input.read_exact(&mut frame[prefix.len()..]).await?;
    parse_open(&frame).map_err(Into::into)
}

pub async fn write_open_response<W: AsyncWrite + Unpin>(
    output: &mut W,
    response: &OpenResponse,
) -> Result<(), MuxError> {
    output.write_all(&encode_open_response(response)?).await?;
    output.flush().await?;
    Ok(())
}

pub async fn read_open_response<R: AsyncRead + Unpin>(
    input: &mut R,
) -> Result<OpenResponse, MuxError> {
    let mut prefix = [0; 3];
    input.read_exact(&mut prefix).await?;
    let length = u16::from_be_bytes([prefix[1], prefix[2]]) as usize;
    if length > MAX_REASON {
        return Err(MuxError::Wire(WireError::Length));
    }
    let mut frame = Vec::with_capacity(prefix.len() + length);
    frame.extend_from_slice(&prefix);
    frame.resize(prefix.len() + length, 0);
    input.read_exact(&mut frame[prefix.len()..]).await?;
    parse_open_response(&frame).map_err(Into::into)
}

#[derive(Debug, Error)]
pub enum MuxError {
    #[error("yamux failed: {0}")]
    Yamux(yamux::ConnectionError),
    #[error("stream I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error(transparent)]
    Wire(#[from] WireError),
    #[error("yamux connection is closed")]
    Closed,
    #[error("policy stream must be established first")]
    PolicyRequired,
    #[error("policy family does not match")]
    PolicyFamily,
    #[error("yamux user stream limit is exhausted")]
    StreamLimit,
    #[error("yamux stream order is invalid")]
    Protocol,
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::net::UnixStream;
    use std::path::Path;

    use async_io::Async;
    use futures::future;

    use super::*;
    use crate::config::Config;
    use crate::wire::Destination;

    #[test]
    fn policy_precedes_user_flow() {
        async_io::block_on(async {
            let (left, right) = UnixStream::pair().unwrap();
            left.set_nonblocking(true).unwrap();
            right.set_nonblocking(true).unwrap();
            let config = Config::parse(
                include_str!("../../../config/templates/snolc-server-low-memory.toml"),
                Path::new("/etc/snolc"),
            )
            .unwrap();
            let mut client =
                MuxSession::new(Async::new(left).unwrap(), Mode::Client, &config.yamux);
            let mut server =
                MuxSession::new(Async::new(right).unwrap(), Mode::Server, &config.yamux);
            let request = OpenRequest {
                kind: StreamKind::Tcp,
                destination: Destination::Domain("example.com".into()),
                port: 443,
                metadata: Vec::new(),
            };
            assert!(matches!(
                client.open_flow(&request).await,
                Err(MuxError::PolicyRequired)
            ));
            let (client_policy, server_policy) = future::join(
                client.open_policy("policy-local"),
                server.accept_policy("policy-local"),
            )
            .await;
            drop(client_policy.unwrap());
            drop(server_policy.unwrap());
            let (client_flow, server_flow) =
                future::join(client.open_flow(&request), server.accept_flow()).await;
            let client_flow = client_flow.unwrap();
            let (received, server_flow) = server_flow.unwrap();
            assert_eq!(received, request);
            drop(client_flow);
            drop(server_flow);
        });
    }
}
