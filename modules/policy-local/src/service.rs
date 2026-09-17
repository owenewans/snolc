use std::collections::VecDeque;
use std::io;
use std::task::{Context, Poll};

use serde::Deserialize;
use snolc_sdk::ByteIo;
use thiserror::Error;
use zeroize::Zeroize;

use crate::frame::{FrameDecoder, FrameError, encode_frame};

const RESPONSE_QUEUE_LIMIT: usize = 8;

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(tag = "method", deny_unknown_fields)]
pub enum ClientRequest {
    #[serde(rename = "auth")]
    Auth { credential: String },
    #[serde(rename = "status")]
    Status,
    #[serde(rename = "subscribe")]
    Subscribe,
    #[serde(rename = "disconnect_self")]
    DisconnectSelf,
}

impl ClientRequest {
    pub fn parse(input: &str) -> Result<Self, ServiceError> {
        let request: Self = toml::from_str(input).map_err(|_| ServiceError::Protocol)?;
        if let Self::Auth { credential } = &request
            && (credential.len() != 64
                || !credential
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')))
        {
            return Err(ServiceError::Protocol);
        }
        Ok(request)
    }
}

pub struct SessionChannel<S> {
    stream: S,
    decoder: FrameDecoder,
    read_buffer: Vec<u8>,
    responses: VecDeque<QueuedFrame>,
    snapshot: Option<Vec<u8>>,
    writing: Option<QueuedFrame>,
    write_offset: usize,
    frame_limit: usize,
    eof: bool,
}

struct QueuedFrame {
    bytes: Vec<u8>,
    sensitive: bool,
}

impl<S: ByteIo> SessionChannel<S> {
    pub fn new(stream: S, frame_limit: usize) -> Result<Self, ServiceError> {
        Ok(Self {
            stream,
            decoder: FrameDecoder::new(frame_limit)?,
            read_buffer: vec![0; frame_limit.min(4096)],
            responses: VecDeque::new(),
            snapshot: None,
            writing: None,
            write_offset: 0,
            frame_limit,
            eof: false,
        })
    }

    pub fn queue_response(&mut self, response: &str) -> Result<(), ServiceError> {
        if self.responses.len() >= RESPONSE_QUEUE_LIMIT {
            return Err(ServiceError::Resource);
        }
        self.responses.push_back(QueuedFrame {
            bytes: encode_frame(response, self.frame_limit)?,
            sensitive: false,
        });
        Ok(())
    }

    pub fn queue_secret(&mut self, response: &str) -> Result<(), ServiceError> {
        if self.responses.len() >= RESPONSE_QUEUE_LIMIT {
            return Err(ServiceError::Resource);
        }
        self.responses.push_back(QueuedFrame {
            bytes: encode_frame(response, self.frame_limit)?,
            sensitive: true,
        });
        Ok(())
    }

    pub fn replace_snapshot(&mut self, snapshot: &str) -> Result<(), ServiceError> {
        self.snapshot = Some(encode_frame(snapshot, self.frame_limit)?);
        Ok(())
    }

    pub fn poll(&mut self, context: &mut Context<'_>) -> Poll<Result<Vec<String>, ServiceError>> {
        let mut messages = Vec::new();
        if !self.eof {
            match self.stream.poll_read(context, &mut self.read_buffer) {
                Poll::Ready(Ok(0)) => self.eof = true,
                Poll::Ready(Ok(read)) => {
                    for frame in self.decoder.push(&self.read_buffer[..read])? {
                        messages.push(frame);
                    }
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                Poll::Pending => {}
            }
        }

        if self.writing.is_none() {
            self.writing = self.responses.pop_front().or_else(|| {
                self.snapshot.take().map(|bytes| QueuedFrame {
                    bytes,
                    sensitive: false,
                })
            });
            self.write_offset = 0;
        }
        if let Some(frame) = &mut self.writing {
            match self
                .stream
                .poll_write(context, &frame.bytes[self.write_offset..])
            {
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(ServiceError::WriteZero)),
                Poll::Ready(Ok(written)) => {
                    self.write_offset += written;
                    if self.write_offset == frame.bytes.len() {
                        if frame.sensitive {
                            frame.bytes.zeroize();
                        }
                        self.writing = None;
                        self.write_offset = 0;
                    }
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                Poll::Pending => {}
            }
        }

        if self.eof
            && self.writing.is_none()
            && self.responses.is_empty()
            && self.snapshot.is_none()
        {
            return Poll::Ready(Err(ServiceError::Closed));
        }
        if messages.is_empty() {
            Poll::Pending
        } else {
            Poll::Ready(Ok(messages))
        }
    }
}

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error(transparent)]
    Frame(#[from] FrameError),
    #[error("policy service protocol is invalid")]
    Protocol,
    #[error("policy service response queue is full")]
    Resource,
    #[error("policy service stream closed")]
    Closed,
    #[error("policy service writer returned zero")]
    WriteZero,
    #[error("policy service I/O failed: {0}")]
    Io(#[from] io::Error),
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::task::Waker;

    use super::*;

    #[derive(Default)]
    struct MemoryIo {
        input: VecDeque<u8>,
        output: Vec<u8>,
        max_read: usize,
        max_write: usize,
    }

    impl ByteIo for MemoryIo {
        fn poll_read(
            &mut self,
            _context: &mut Context<'_>,
            output: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            if self.input.is_empty() {
                return Poll::Pending;
            }
            let count = output.len().min(self.input.len()).min(self.max_read);
            for byte in &mut output[..count] {
                *byte = self.input.pop_front().unwrap();
            }
            Poll::Ready(Ok(count))
        }

        fn poll_write(
            &mut self,
            _context: &mut Context<'_>,
            input: &[u8],
        ) -> Poll<io::Result<usize>> {
            let count = input.len().min(self.max_write);
            self.output.extend_from_slice(&input[..count]);
            Poll::Ready(Ok(count))
        }

        fn poll_flush(&mut self, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown_write(&mut self, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn close(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn parses_fragmented_requests_and_partial_responses() {
        let auth = encode_frame(
            &format!("method = \"auth\"\ncredential = \"{}\"\n", "ab".repeat(32)),
            1024,
        )
        .unwrap();
        let io = MemoryIo {
            input: auth.into_iter().collect(),
            max_read: 1,
            max_write: 2,
            ..MemoryIo::default()
        };
        let mut channel = SessionChannel::new(io, 1024).unwrap();
        channel
            .queue_response("status = \"authenticated\"\n")
            .unwrap();
        let mut context = Context::from_waker(Waker::noop());
        let mut request = None;
        for _ in 0..256 {
            if let Poll::Ready(Ok(requests)) = channel.poll(&mut context) {
                request = requests
                    .into_iter()
                    .next()
                    .map(|request| ClientRequest::parse(&request).unwrap());
            }
            if request.is_some() && channel.writing.is_none() {
                break;
            }
        }
        assert!(matches!(request, Some(ClientRequest::Auth { .. })));
        let mut decoder = FrameDecoder::new(1024).unwrap();
        assert_eq!(
            decoder.push(&channel.stream.output).unwrap(),
            ["status = \"authenticated\"\n"]
        );
    }

    #[test]
    fn rejects_administrative_methods_on_user_stream() {
        assert!(matches!(
            ClientRequest::parse("method = \"user.create\"\n"),
            Err(ServiceError::Protocol)
        ));
    }

    #[test]
    fn snapshot_queue_replaces_stale_state() {
        let io = MemoryIo {
            max_read: 1,
            max_write: 1024,
            ..MemoryIo::default()
        };
        let mut channel = SessionChannel::new(io, 1024).unwrap();
        channel.replace_snapshot("revision = 1\n").unwrap();
        channel.replace_snapshot("revision = 2\n").unwrap();
        let mut context = Context::from_waker(Waker::noop());
        let _ = channel.poll(&mut context);
        let mut decoder = FrameDecoder::new(1024).unwrap();
        assert_eq!(
            decoder.push(&channel.stream.output).unwrap(),
            ["revision = 2\n"]
        );
    }
}
