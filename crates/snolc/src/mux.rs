use std::cell::RefCell;
use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};

use futures::future::poll_fn;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use thiserror::Error;
use yamux::Mode;

use crate::config::YamuxConfig;
use crate::wire::{
    HEADER_LENGTH, MAX_OPEN_BODY, MAX_POLICY_FAMILY, MAX_REASON, OpenRequest, OpenResponse,
    StreamKind, WireError, encode_open, encode_open_response, encode_policy, parse_header,
    parse_open, parse_open_response, parse_policy,
};

const MUX_HEADER_BYTES: usize = 9;
const FRAME_OPEN: u8 = 1;
const FRAME_DATA: u8 = 2;
const FRAME_FIN: u8 = 3;

struct StreamState {
    input: VecDeque<Vec<u8>>,
    offset: usize,
    eof: bool,
    reader: Option<Waker>,
    completed_write: usize,
}

struct PendingWrite {
    bytes: Vec<u8>,
    offset: usize,
    kind: u8,
    stream: u32,
    accepted: usize,
}

struct PendingRead {
    kind: u8,
    stream: u32,
    length: usize,
    bytes: Vec<u8>,
    wire_consumed: usize,
    buffer_offset: usize,
}

struct Connection<T> {
    io: Option<T>,
    streams: Vec<Option<StreamState>>,
    inbound: VecDeque<u32>,
    inbound_waker: Option<Waker>,
    next_stream: u32,
    split_send_size: usize,
    receive_limit: usize,
    received_bytes: usize,
    read_header: [u8; MUX_HEADER_BYTES],
    read_header_offset: usize,
    read_frame: Option<PendingRead>,
    write: Option<PendingWrite>,
    spare_write: Vec<u8>,
    spare_reads: Vec<Vec<u8>>,
    controls: VecDeque<(u8, u32)>,
    closed: bool,
}

pub struct MuxStream<T> {
    id: u32,
    connection: Rc<RefCell<Connection<T>>>,
    write_closed: bool,
}

pub type OpenFlowFuture<T> =
    Pin<Box<dyn Future<Output = Result<(OpenResponse, MuxStream<T>), MuxError>>>>;

pub struct MuxSession<T> {
    connection: Rc<RefCell<Connection<T>>>,
    role: Mode,
    policy_open: bool,
    user_streams: usize,
    max_user_streams: usize,
    marker: std::marker::PhantomData<T>,
}

impl<T> MuxSession<T>
where
    T: AsyncRead + AsyncWrite + Unpin + 'static,
{
    pub fn new(io: T, role: Mode, config: &YamuxConfig) -> Self {
        let next_stream = if role == Mode::Client { 1 } else { 2 };
        Self {
            connection: Rc::new(RefCell::new(Connection {
                io: Some(io),
                streams: Vec::new(),
                inbound: VecDeque::new(),
                inbound_waker: None,
                next_stream,
                split_send_size: config.split_send_size,
                receive_limit: config.receive_window_bytes,
                received_bytes: 0,
                read_header: [0; MUX_HEADER_BYTES],
                read_header_offset: 0,
                read_frame: None,
                write: None,
                spare_write: Vec::with_capacity(config.split_send_size + MUX_HEADER_BYTES),
                spare_reads: Vec::new(),
                controls: VecDeque::new(),
                closed: false,
            })),
            role,
            policy_open: false,
            user_streams: 0,
            max_user_streams: config.max_streams_per_session - 1,
            marker: std::marker::PhantomData,
        }
    }

    pub async fn open_policy(&mut self, family: &str) -> Result<MuxStream<T>, MuxError> {
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

    pub async fn accept_policy(&mut self, family: &str) -> Result<MuxStream<T>, MuxError> {
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

    pub async fn open_flow(&mut self, request: &OpenRequest) -> Result<MuxStream<T>, MuxError> {
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
    ) -> Result<(OpenResponse, MuxStream<T>), MuxError> {
        let mut stream = self.open_flow(request).await?;
        match self.drive_operation(read_open_response(&mut stream)).await {
            Ok(response) => Ok((response, stream)),
            Err(error) => {
                self.release_flow();
                Err(error)
            }
        }
    }

    pub fn begin_open_flow_confirmed(
        &mut self,
        request: OpenRequest,
    ) -> Result<OpenFlowFuture<T>, MuxError> {
        if self.role != Mode::Client || !self.policy_open {
            return Err(MuxError::PolicyRequired);
        }
        self.reserve_user_stream()?;
        let stream = match self.queue_stream() {
            Ok(stream) => stream,
            Err(error) => {
                self.user_streams -= 1;
                return Err(error);
            }
        };
        self.connection
            .borrow_mut()
            .controls
            .push_back((FRAME_OPEN, stream.id));
        Ok(Box::pin(async move {
            let mut stream = stream;
            write_open(&mut stream, &request).await?;
            let response = read_open_response(&mut stream).await?;
            Ok((response, stream))
        }))
    }

    pub async fn accept_flow(&mut self) -> Result<(OpenRequest, MuxStream<T>), MuxError> {
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
        stream: &mut MuxStream<T>,
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
        poll_fn(|context| {
            let mut connection = self.connection.borrow_mut();
            match connection.poll_flush_write(context) {
                Poll::Ready(Ok(())) => match connection.io.as_mut() {
                    Some(io) => Pin::new(io).poll_close(context),
                    None => Poll::Ready(Ok(())),
                },
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Pending => Poll::Pending,
            }
        })
        .await?;
        Ok(())
    }

    pub fn poll_drive(&mut self, context: &mut Context<'_>) -> Poll<Result<(), MuxError>> {
        let mut connection = self.connection.borrow_mut();
        match connection.poll_drive(context) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error.into())),
            Poll::Pending if connection.closed => Poll::Ready(Err(MuxError::Closed)),
            Poll::Pending => Poll::Pending,
        }
    }

    async fn open_stream(&mut self) -> Result<MuxStream<T>, MuxError> {
        let stream = self.queue_stream()?;
        let id = stream.id;
        poll_fn(|context| {
            self.connection
                .borrow_mut()
                .poll_control(context, FRAME_OPEN, id)
        })
        .await?;
        Ok(stream)
    }

    fn queue_stream(&mut self) -> Result<MuxStream<T>, MuxError> {
        let id = {
            let mut connection = self.connection.borrow_mut();
            let id = connection.next_stream;
            connection.next_stream = connection
                .next_stream
                .checked_add(2)
                .ok_or(MuxError::StreamLimit)?;
            connection.insert_stream(id)?;
            id
        };
        Ok(MuxStream::new(id, Rc::clone(&self.connection)))
    }

    async fn accept_stream(&mut self) -> Result<MuxStream<T>, MuxError> {
        let connection = Rc::clone(&self.connection);
        let id = poll_fn(|context| {
            let mut connection = connection.borrow_mut();
            if let Some(id) = connection.inbound.pop_front() {
                return Poll::Ready(Ok(id));
            }
            connection.inbound_waker = Some(context.waker().clone());
            match connection.poll_drive(context) {
                Poll::Ready(Err(error)) => Poll::Ready(Err(error.into())),
                _ if connection.closed => Poll::Ready(Err(MuxError::Closed)),
                _ => Poll::Pending,
            }
        })
        .await?;
        Ok(MuxStream::new(id, Rc::clone(&self.connection)))
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
            match self.connection.borrow_mut().poll_drive(context) {
                Poll::Ready(Err(error)) => Poll::Ready(Err(error.into())),
                _ => match completed.take() {
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

impl<T> Drop for MuxSession<T> {
    fn drop(&mut self) {
        let mut connection = self.connection.borrow_mut();
        connection.closed = true;
        connection.streams.clear();
        connection.io.take();
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> Connection<T> {
    fn insert_stream(&mut self, id: u32) -> Result<(), MuxError> {
        let index = id as usize;
        if self.streams.get(index).is_some_and(Option::is_some) {
            return Err(MuxError::Protocol);
        }
        if self.streams.len() <= index {
            self.streams.resize_with(index + 1, || None);
        }
        self.streams[index] = Some(StreamState {
            input: VecDeque::new(),
            offset: 0,
            eof: false,
            reader: None,
            completed_write: 0,
        });
        Ok(())
    }

    fn stream_mut(&mut self, id: u32) -> Option<&mut StreamState> {
        self.streams.get_mut(id as usize)?.as_mut()
    }

    fn frame(&mut self, kind: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let mut frame = std::mem::take(&mut self.spare_write);
        frame.clear();
        frame.reserve(MUX_HEADER_BYTES + payload.len());
        frame.push(kind);
        frame.extend_from_slice(&stream.to_be_bytes());
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    fn poll_control(
        &mut self,
        context: &mut Context<'_>,
        kind: u8,
        stream: u32,
    ) -> Poll<io::Result<()>> {
        if let Some(write) = &self.write {
            if write.kind == kind && write.stream == stream {
                return self.poll_flush_write(context);
            }
            match self.poll_flush_write(context) {
                Poll::Ready(Ok(())) => {}
                result => return result,
            }
        }
        if self.write.is_none() {
            self.write = Some(PendingWrite {
                bytes: self.frame(kind, stream, &[]),
                offset: 0,
                kind,
                stream,
                accepted: 0,
            });
        }
        self.poll_flush_write(context)
    }

    fn poll_data(
        &mut self,
        context: &mut Context<'_>,
        stream: u32,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let accepted = self
            .stream_mut(stream)
            .map(|state| std::mem::take(&mut state.completed_write))
            .unwrap_or(0);
        if accepted != 0 {
            return Poll::Ready(Ok(accepted));
        }
        self.start_queued_control();
        if let Some(write) = &self.write {
            if write.kind == FRAME_DATA && write.stream == stream {
                let accepted = write.accepted;
                return match self.poll_flush_write(context) {
                    Poll::Ready(Ok(())) => {
                        if let Some(state) = self.stream_mut(stream) {
                            state.completed_write = 0;
                        }
                        Poll::Ready(Ok(accepted))
                    }
                    Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                    Poll::Pending => Poll::Pending,
                };
            }
            match self.poll_flush_write(context) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        let length = input.len().min(self.split_send_size);
        self.write = Some(PendingWrite {
            bytes: self.frame(FRAME_DATA, stream, &input[..length]),
            offset: 0,
            kind: FRAME_DATA,
            stream,
            accepted: length,
        });
        match self.poll_flush_write(context) {
            Poll::Ready(Ok(())) => {
                if let Some(state) = self.stream_mut(stream) {
                    state.completed_write = 0;
                }
                Poll::Ready(Ok(length))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush_write(&mut self, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(io) = self.io.as_mut() else {
            return Poll::Ready(Err(io::ErrorKind::NotConnected.into()));
        };
        while let Some(write) = &mut self.write {
            match Pin::new(&mut *io).poll_write(context, &write.bytes[write.offset..]) {
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Poll::Ready(Ok(count)) => write.offset += count,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
            if write.offset == write.bytes.len() {
                let mut completed = self.write.take().expect("write is present");
                if completed.kind == FRAME_DATA
                    && completed.accepted != 0
                    && let Some(state) = self
                        .streams
                        .get_mut(completed.stream as usize)
                        .and_then(Option::as_mut)
                {
                    state.completed_write = completed.accepted;
                }
                completed.bytes.clear();
                self.spare_write = completed.bytes;
            }
        }
        Pin::new(io).poll_flush(context)
    }

    fn poll_drive(&mut self, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.closed {
            return Poll::Pending;
        }
        self.start_queued_control();
        if self.write.is_some() {
            match self.poll_flush_write(context) {
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) | Poll::Pending => {}
            }
        }
        match self.poll_prepare_frame(context) {
            Poll::Ready(Ok(())) => {}
            result => return result,
        }
        let frame = self.read_frame.as_mut().expect("set above");
        if frame.kind == FRAME_DATA {
            let remaining = frame.length - frame.wire_consumed;
            if frame.bytes.len() != remaining {
                frame.bytes.resize(remaining, 0);
            }
        }
        let Some(io) = self.io.as_mut() else {
            self.closed = true;
            return Poll::Pending;
        };
        while frame.buffer_offset < frame.bytes.len() {
            match Pin::new(&mut *io).poll_read(context, &mut frame.bytes[frame.buffer_offset..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "mux frame ended early",
                    )));
                }
                Poll::Ready(Ok(count)) => frame.buffer_offset += count,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        let frame = self.read_frame.take().expect("present");
        self.finish_frame(frame)?;
        Poll::Ready(Ok(()))
    }

    fn poll_prepare_frame(&mut self, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.read_frame.is_none() {
            let Some(io) = self.io.as_mut() else {
                self.closed = true;
                return Poll::Pending;
            };
            while self.read_header_offset < MUX_HEADER_BYTES {
                match Pin::new(&mut *io)
                    .poll_read(context, &mut self.read_header[self.read_header_offset..])
                {
                    Poll::Ready(Ok(0)) => {
                        self.closed = true;
                        return Poll::Pending;
                    }
                    Poll::Ready(Ok(count)) => self.read_header_offset += count,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            let kind = self.read_header[0];
            let stream = u32::from_be_bytes(self.read_header[1..5].try_into().expect("size"));
            let length =
                u32::from_be_bytes(self.read_header[5..9].try_into().expect("size")) as usize;
            self.read_header_offset = 0;
            if length > self.split_send_size
                || self.received_bytes.saturating_add(length) > self.receive_limit
            {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "mux receive limit exceeded",
                )));
            }
            if !matches!(kind, FRAME_OPEN | FRAME_DATA | FRAME_FIN)
                || kind != FRAME_DATA && length != 0
            {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid mux frame",
                )));
            }
            let mut bytes = self.spare_reads.pop().unwrap_or_default();
            bytes.clear();
            if kind != FRAME_DATA {
                bytes.resize(length, 0);
            }
            self.read_frame = Some(PendingRead {
                kind,
                stream,
                length,
                bytes,
                wire_consumed: 0,
                buffer_offset: 0,
            });
        }
        Poll::Ready(Ok(()))
    }

    fn poll_read_stream(
        &mut self,
        context: &mut Context<'_>,
        stream: u32,
        output: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        match self.poll_prepare_frame(context) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        let frame = self.read_frame.as_mut().expect("set above");
        if frame.kind != FRAME_DATA
            || frame.stream != stream
            || !frame.bytes.is_empty()
            || frame.length == frame.wire_consumed
        {
            return match self.poll_drive(context) {
                Poll::Ready(Ok(())) => {
                    context.waker().wake_by_ref();
                    Poll::Pending
                }
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Pending => Poll::Pending,
            };
        }
        let count = output.len().min(frame.length - frame.wire_consumed);
        let Some(io) = self.io.as_mut() else {
            return Poll::Ready(Err(io::ErrorKind::NotConnected.into()));
        };
        match Pin::new(io).poll_read(context, &mut output[..count]) {
            Poll::Ready(Ok(0)) => Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into())),
            Poll::Ready(Ok(read)) => {
                frame.wire_consumed += read;
                if frame.wire_consumed == frame.length {
                    let mut frame = self.read_frame.take().expect("frame is present");
                    frame.bytes.clear();
                    self.spare_reads.push(frame.bytes);
                }
                Poll::Ready(Ok(read))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn finish_frame(&mut self, frame: PendingRead) -> io::Result<()> {
        match frame.kind {
            FRAME_OPEN => {
                self.insert_stream(frame.stream)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
                self.inbound.push_back(frame.stream);
                if let Some(waker) = self.inbound_waker.take() {
                    waker.wake();
                }
            }
            FRAME_DATA => {
                let state = self
                    .streams
                    .get_mut(frame.stream as usize)
                    .and_then(Option::as_mut)
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "unknown mux stream")
                    })?;
                self.received_bytes += frame.bytes.len();
                state.input.push_back(frame.bytes);
                if let Some(waker) = state.reader.take() {
                    waker.wake();
                }
            }
            FRAME_FIN => {
                let state = self.stream_mut(frame.stream).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "unknown mux stream")
                })?;
                state.eof = true;
                if let Some(waker) = state.reader.take() {
                    waker.wake();
                }
            }
            _ => unreachable!(),
        }
        Ok(())
    }

    fn start_queued_control(&mut self) {
        if self.write.is_none()
            && let Some((kind, stream)) = self.controls.pop_front()
        {
            let bytes = self.frame(kind, stream, &[]);
            self.write = Some(PendingWrite {
                bytes,
                offset: 0,
                kind,
                stream,
                accepted: 0,
            });
        }
    }
}

impl<T> MuxStream<T> {
    fn new(id: u32, connection: Rc<RefCell<Connection<T>>>) -> Self {
        Self {
            id,
            connection,
            write_closed: false,
        }
    }
}

impl<T> Drop for MuxStream<T> {
    fn drop(&mut self) {
        if self.write_closed {
            return;
        }
        let mut connection = self.connection.borrow_mut();
        if !connection.closed {
            connection.controls.push_back((FRAME_FIN, self.id));
        }
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for MuxStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if output.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut connection = self.connection.borrow_mut();
        let (count, recycled) = {
            let state = connection.stream_mut(self.id).ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotConnected, "mux stream is closed")
            })?;
            if let Some(bytes) = state.input.front() {
                let count = output.len().min(bytes.len() - state.offset);
                output[..count].copy_from_slice(&bytes[state.offset..state.offset + count]);
                state.offset += count;
                let recycled = if state.offset == bytes.len() {
                    state.offset = 0;
                    state.input.pop_front()
                } else {
                    None
                };
                (count, recycled)
            } else if state.eof {
                return Poll::Ready(Ok(0));
            } else {
                state.reader = Some(context.waker().clone());
                (0, None)
            }
        };
        if count != 0 {
            connection.received_bytes -= count;
            if let Some(mut bytes) = recycled {
                bytes.clear();
                connection.spare_reads.push(bytes);
            }
            return Poll::Ready(Ok(count));
        }
        match connection.poll_read_stream(context, self.id, output) {
            Poll::Ready(Ok(count)) => Poll::Ready(Ok(count)),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for MuxStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.connection
            .borrow_mut()
            .poll_data(context, self.id, input)
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.connection.borrow_mut().poll_flush_write(context)
    }

    fn poll_close(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.write_closed {
            return Poll::Ready(Ok(()));
        }
        let result = {
            self.connection
                .borrow_mut()
                .poll_control(context, FRAME_FIN, self.id)
        };
        match result {
            Poll::Ready(Ok(())) => {
                self.write_closed = true;
                Poll::Ready(Ok(()))
            }
            result => result,
        }
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
    use crate::wire::{Destination, OpenStatus};

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

    #[test]
    fn concurrent_streams_preserve_large_payloads() {
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
            let (client_policy, server_policy) = future::join(
                client.open_policy("policy-local"),
                server.accept_policy("policy-local"),
            )
            .await;
            let client_policy = client_policy.unwrap();
            let server_policy = server_policy.unwrap();

            let request = OpenRequest {
                kind: StreamKind::Tcp,
                destination: Destination::Domain("example.com".into()),
                port: 443,
                metadata: Vec::new(),
            };
            let first = client.begin_open_flow_confirmed(request.clone()).unwrap();
            let second = client.begin_open_flow_confirmed(request).unwrap();
            let server_open = async {
                let (_, mut first) = server.accept_flow().await.unwrap();
                server
                    .respond_flow(
                        &mut first,
                        &OpenResponse {
                            status: OpenStatus::Ok,
                            reason: String::new(),
                        },
                    )
                    .await
                    .unwrap();
                let (_, mut second) = server.accept_flow().await.unwrap();
                server
                    .respond_flow(
                        &mut second,
                        &OpenResponse {
                            status: OpenStatus::Ok,
                            reason: String::new(),
                        },
                    )
                    .await
                    .unwrap();
                (first, second)
            };
            let ((first, second), mut server_flows) =
                future::join(future::join(first, second), server_open).await;
            let mut client_first = first.unwrap().1;
            let mut client_second = second.unwrap().1;
            let first_payload = vec![0x35; 262_144];
            let second_payload = vec![0xa7; 262_144];
            let send = async {
                future::join(
                    server_flows.0.write_all(&first_payload),
                    server_flows.1.write_all(&second_payload),
                )
                .await
            };
            let receive = async {
                let mut first = vec![0; first_payload.len()];
                let mut second = vec![0; second_payload.len()];
                let results = future::join(
                    client_first.read_exact(&mut first),
                    client_second.read_exact(&mut second),
                )
                .await;
                (results, first, second)
            };
            let (sent, (received, first_bytes, second_bytes)) = future::join(send, receive).await;
            sent.0.unwrap();
            sent.1.unwrap();
            received.0.unwrap();
            received.1.unwrap();
            assert_eq!(first_bytes, first_payload);
            assert_eq!(second_bytes, second_payload);
            drop(client_policy);
            drop(server_policy);
        });
    }
}
