use std::cell::RefCell;
use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, Waker};

use futures::io::{AsyncRead, AsyncWrite};
use snolc_abi::{
    SnolByteIoV1, SnolBytes, SnolBytesMut, SnolDatagramIoV1, SnolIoResult, SnolWakeHandle,
};
use snolc_sdk::{DatagramIo, DatagramRecv};
use thiserror::Error;

trait CoreIo: AsyncRead + AsyncWrite + Unpin {}
impl<T: AsyncRead + AsyncWrite + Unpin> CoreIo for T {}

thread_local! {
    static STREAMS: RefCell<HashMap<u64, Box<dyn CoreIo>>> = RefCell::new(HashMap::new());
    static DATAGRAMS: RefCell<HashMap<u64, Box<dyn DatagramIo>>> = RefCell::new(HashMap::new());
}

static NEXT: AtomicU64 = AtomicU64::new(1);

pub(crate) struct RegisteredIo {
    handle: u64,
    transferred: bool,
}

impl RegisteredIo {
    pub(crate) fn register(
        io: impl AsyncRead + AsyncWrite + Unpin + 'static,
        limit: usize,
    ) -> Result<Self, CoreIoError> {
        if limit == 0 {
            return Err(CoreIoError::Limit);
        }
        let handle = NEXT.fetch_add(1, Ordering::Relaxed);
        if handle == 0 {
            return Err(CoreIoError::Handle);
        }
        STREAMS.with(|streams| {
            let mut streams = streams.borrow_mut();
            if streams.len().saturating_add(datagram_count()) >= limit {
                return Err(CoreIoError::Limit);
            }
            streams.insert(handle, Box::new(io));
            Ok(Self {
                handle,
                transferred: false,
            })
        })
    }

    pub(crate) fn raw_parts(&self) -> (u64, *const SnolByteIoV1) {
        (self.handle, &CORE_BYTE_IO)
    }

    pub(crate) fn transfer(mut self) {
        self.transferred = true;
    }
}

pub(crate) struct RegisteredDatagramIo {
    handle: u64,
    transferred: bool,
}

pub(crate) struct MuxDatagramIo<S> {
    stream: S,
    read_prefix: [u8; 2],
    read_prefix_len: usize,
    read_payload: Vec<u8>,
    read_payload_len: usize,
    send_frame: Vec<u8>,
    send_offset: usize,
    closed: bool,
}

impl<S> MuxDatagramIo<S> {
    pub(crate) fn new(stream: S) -> Self {
        Self {
            stream,
            read_prefix: [0; 2],
            read_prefix_len: 0,
            read_payload: Vec::new(),
            read_payload_len: 0,
            send_frame: Vec::new(),
            send_offset: 0,
            closed: false,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> DatagramIo for MuxDatagramIo<S> {
    fn poll_recv_datagram(
        &mut self,
        context: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<io::Result<DatagramRecv>> {
        loop {
            if self.read_prefix_len < self.read_prefix.len() {
                let start = self.read_prefix_len;
                match Pin::new(&mut self.stream)
                    .poll_read(context, &mut self.read_prefix[start..])
                {
                    Poll::Ready(Ok(0)) if start == 0 => {
                        self.closed = true;
                        return Poll::Ready(Ok(DatagramRecv::Closed));
                    }
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "UDP frame ended in length prefix",
                        )));
                    }
                    Poll::Ready(Ok(count)) => {
                        self.read_prefix_len += count;
                        continue;
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            if self.read_payload.is_empty() && self.read_payload_len == 0 {
                let length = u16::from_be_bytes(self.read_prefix) as usize;
                if length > crate::wire::MAX_UDP_PAYLOAD {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "UDP frame exceeds wire limit",
                    )));
                }
                if length == 0 {
                    self.read_prefix_len = 0;
                    return Poll::Ready(Ok(DatagramRecv::Datagram(0)));
                }
                self.read_payload.resize(length, 0);
            }
            while self.read_payload_len < self.read_payload.len() {
                let start = self.read_payload_len;
                match Pin::new(&mut self.stream)
                    .poll_read(context, &mut self.read_payload[start..])
                {
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "UDP frame ended in payload",
                        )));
                    }
                    Poll::Ready(Ok(count)) => self.read_payload_len += count,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            if output.len() < self.read_payload.len() {
                return Poll::Ready(Ok(DatagramRecv::BufferTooSmall(
                    self.read_payload.len(),
                )));
            }
            let length = self.read_payload.len();
            output[..length].copy_from_slice(&self.read_payload);
            self.read_payload.clear();
            self.read_payload_len = 0;
            self.read_prefix_len = 0;
            return Poll::Ready(Ok(DatagramRecv::Datagram(length)));
        }
    }

    fn poll_send_datagram(
        &mut self,
        context: &mut Context<'_>,
        datagram: &[u8],
    ) -> Poll<io::Result<()>> {
        if datagram.len() > crate::wire::MAX_UDP_PAYLOAD {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UDP payload exceeds wire limit",
            )));
        }
        if self.send_frame.is_empty() {
            let length = u16::try_from(datagram.len()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "UDP payload exceeds u16")
            })?;
            self.send_frame.reserve(2 + datagram.len());
            self.send_frame.extend_from_slice(&length.to_be_bytes());
            self.send_frame.extend_from_slice(datagram);
        } else if self.send_frame.get(2..) != Some(datagram) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "changed UDP payload while send is pending",
            )));
        }
        while self.send_offset < self.send_frame.len() {
            let offset = self.send_offset;
            match Pin::new(&mut self.stream).poll_write(context, &self.send_frame[offset..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "UDP frame write made no progress",
                    )));
                }
                Poll::Ready(Ok(count)) => self.send_offset += count,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.send_frame.clear();
        self.send_offset = 0;
        Poll::Ready(Ok(()))
    }

    fn close(&mut self) -> io::Result<()> {
        self.closed = true;
        Ok(())
    }
}

impl RegisteredDatagramIo {
    pub(crate) fn register(
        io: impl DatagramIo + 'static,
        limit: usize,
    ) -> Result<Self, CoreIoError> {
        if limit == 0 {
            return Err(CoreIoError::Limit);
        }
        let handle = NEXT.fetch_add(1, Ordering::Relaxed);
        if handle == 0 {
            return Err(CoreIoError::Handle);
        }
        DATAGRAMS.with(|datagrams| {
            let mut datagrams = datagrams.borrow_mut();
            if datagrams.len().saturating_add(stream_count()) >= limit {
                return Err(CoreIoError::Limit);
            }
            datagrams.insert(handle, Box::new(io));
            Ok(Self {
                handle,
                transferred: false,
            })
        })
    }

    pub(crate) fn raw_parts(&self) -> (u64, *const SnolDatagramIoV1) {
        (self.handle, &CORE_DATAGRAM_IO)
    }

    pub(crate) fn transfer(mut self) {
        self.transferred = true;
    }
}

impl Drop for RegisteredDatagramIo {
    fn drop(&mut self) {
        if !self.transferred {
            DATAGRAMS.with(|datagrams| datagrams.borrow_mut().remove(&self.handle));
        }
    }
}

fn stream_count() -> usize {
    STREAMS.with(|streams| streams.borrow().len())
}

fn datagram_count() -> usize {
    DATAGRAMS.with(|datagrams| datagrams.borrow().len())
}

pub(crate) fn is_registered(handle: u64) -> bool {
    STREAMS.with(|streams| streams.borrow().contains_key(&handle))
        || DATAGRAMS.with(|datagrams| datagrams.borrow().contains_key(&handle))
}

impl Drop for RegisteredIo {
    fn drop(&mut self) {
        if !self.transferred {
            STREAMS.with(|streams| streams.borrow_mut().remove(&self.handle));
        }
    }
}

unsafe extern "C" fn read(
    handle: u64,
    output: SnolBytesMut,
    _wake: SnolWakeHandle,
) -> SnolIoResult {
    if output.pointer.is_null() && output.length != 0 {
        return SnolIoResult::error(snolc_abi::STATUS_INVALID);
    }
    STREAMS.with(|streams| {
        let mut streams = streams.borrow_mut();
        let Some(io) = streams.get_mut(&handle) else {
            return SnolIoResult::error(snolc_abi::STATUS_INVALID);
        };
        let output = if output.length == 0 {
            &mut []
        } else {
            unsafe { std::slice::from_raw_parts_mut(output.pointer, output.length) }
        };
        let mut context = Context::from_waker(Waker::noop());
        match Pin::new(io.as_mut()).poll_read(&mut context, output) {
            Poll::Ready(Ok(0)) => SnolIoResult::eof(),
            Poll::Ready(Ok(count)) if count <= output.len() => SnolIoResult::progress(count),
            Poll::Ready(Ok(_)) => SnolIoResult::error(snolc_abi::STATUS_INTERNAL),
            Poll::Ready(Err(_)) => SnolIoResult::error(snolc_abi::STATUS_IO),
            Poll::Pending => SnolIoResult::pending(),
        }
    })
}

unsafe extern "C" fn write(handle: u64, input: SnolBytes, _wake: SnolWakeHandle) -> SnolIoResult {
    if input.pointer.is_null() && input.length != 0 {
        return SnolIoResult::error(snolc_abi::STATUS_INVALID);
    }
    let input = if input.length == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(input.pointer, input.length) }
    };
    STREAMS.with(|streams| {
        let mut streams = streams.borrow_mut();
        let Some(io) = streams.get_mut(&handle) else {
            return SnolIoResult::error(snolc_abi::STATUS_INVALID);
        };
        let mut context = Context::from_waker(Waker::noop());
        match Pin::new(io.as_mut()).poll_write(&mut context, input) {
            Poll::Ready(Ok(0)) if !input.is_empty() => SnolIoResult::error(snolc_abi::STATUS_IO),
            Poll::Ready(Ok(count)) if count <= input.len() => SnolIoResult::progress(count),
            Poll::Ready(Ok(_)) => SnolIoResult::error(snolc_abi::STATUS_INTERNAL),
            Poll::Ready(Err(_)) => SnolIoResult::error(snolc_abi::STATUS_IO),
            Poll::Pending => SnolIoResult::pending(),
        }
    })
}

unsafe extern "C" fn flush(handle: u64, _wake: SnolWakeHandle) -> SnolIoResult {
    action(handle, |io, context| Pin::new(io).poll_flush(context))
}

unsafe extern "C" fn shutdown_write(handle: u64, _wake: SnolWakeHandle) -> SnolIoResult {
    action(handle, |io, context| Pin::new(io).poll_close(context))
}

fn action(
    handle: u64,
    function: impl FnOnce(&mut dyn CoreIo, &mut Context<'_>) -> Poll<io::Result<()>>,
) -> SnolIoResult {
    STREAMS.with(|streams| {
        let mut streams = streams.borrow_mut();
        let Some(io) = streams.get_mut(&handle) else {
            return SnolIoResult::error(snolc_abi::STATUS_INVALID);
        };
        let mut context = Context::from_waker(Waker::noop());
        match function(io.as_mut(), &mut context) {
            Poll::Ready(Ok(())) => SnolIoResult::progress(0),
            Poll::Ready(Err(_)) => SnolIoResult::error(snolc_abi::STATUS_IO),
            Poll::Pending => SnolIoResult::pending(),
        }
    })
}

unsafe extern "C" fn close(handle: u64) -> u32 {
    if STREAMS.with(|streams| streams.borrow_mut().remove(&handle).is_some()) {
        snolc_abi::STATUS_OK
    } else {
        snolc_abi::STATUS_INVALID
    }
}

static CORE_BYTE_IO: SnolByteIoV1 = SnolByteIoV1 {
    struct_size: size_of::<SnolByteIoV1>() as u32,
    reserved: 0,
    read: Some(read),
    write: Some(write),
    flush: Some(flush),
    shutdown_write: Some(shutdown_write),
    close: Some(close),
};

unsafe extern "C" fn recv_datagram(
    handle: u64,
    output: SnolBytesMut,
    _wake: SnolWakeHandle,
) -> SnolIoResult {
    if output.pointer.is_null() && output.length != 0 {
        return SnolIoResult::error(snolc_abi::STATUS_INVALID);
    }
    DATAGRAMS.with(|datagrams| {
        let mut datagrams = datagrams.borrow_mut();
        let Some(io) = datagrams.get_mut(&handle) else {
            return SnolIoResult::error(snolc_abi::STATUS_INVALID);
        };
        let output = if output.length == 0 {
            &mut []
        } else {
            unsafe { std::slice::from_raw_parts_mut(output.pointer, output.length) }
        };
        let mut context = Context::from_waker(Waker::noop());
        match io.poll_recv_datagram(&mut context, output) {
            Poll::Ready(Ok(DatagramRecv::Datagram(length))) if length <= output.len() => {
                SnolIoResult::progress(length)
            }
            Poll::Ready(Ok(DatagramRecv::BufferTooSmall(required))) => {
                SnolIoResult::buffer_too_small(required)
            }
            Poll::Ready(Ok(DatagramRecv::Closed)) => SnolIoResult::eof(),
            Poll::Ready(Ok(_)) => SnolIoResult::error(snolc_abi::STATUS_INTERNAL),
            Poll::Ready(Err(_)) => SnolIoResult::error(snolc_abi::STATUS_IO),
            Poll::Pending => SnolIoResult::pending(),
        }
    })
}

unsafe extern "C" fn send_datagram(
    handle: u64,
    input: SnolBytes,
    _wake: SnolWakeHandle,
) -> SnolIoResult {
    if input.pointer.is_null() && input.length != 0 {
        return SnolIoResult::error(snolc_abi::STATUS_INVALID);
    }
    let input = if input.length == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(input.pointer, input.length) }
    };
    DATAGRAMS.with(|datagrams| {
        let mut datagrams = datagrams.borrow_mut();
        let Some(io) = datagrams.get_mut(&handle) else {
            return SnolIoResult::error(snolc_abi::STATUS_INVALID);
        };
        let mut context = Context::from_waker(Waker::noop());
        match io.poll_send_datagram(&mut context, input) {
            Poll::Ready(Ok(())) => SnolIoResult::progress(input.len()),
            Poll::Ready(Err(_)) => SnolIoResult::error(snolc_abi::STATUS_IO),
            Poll::Pending => SnolIoResult::pending(),
        }
    })
}

unsafe extern "C" fn close_datagram(handle: u64) -> u32 {
    if DATAGRAMS.with(|datagrams| datagrams.borrow_mut().remove(&handle).is_some()) {
        snolc_abi::STATUS_OK
    } else {
        snolc_abi::STATUS_INVALID
    }
}

static CORE_DATAGRAM_IO: SnolDatagramIoV1 = SnolDatagramIoV1 {
    struct_size: size_of::<SnolDatagramIoV1>() as u32,
    reserved: 0,
    recv_datagram: Some(recv_datagram),
    send_datagram: Some(send_datagram),
    close: Some(close_datagram),
};

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum CoreIoError {
    #[error("core I/O registry limit is exhausted")]
    Limit,
    #[error("core I/O handle space is exhausted")]
    Handle,
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use futures::io::Cursor;

    use super::*;

    fn no_wake() -> SnolWakeHandle {
        SnolWakeHandle {
            context: std::ptr::null_mut(),
            wake: None,
            retain: None,
            release: None,
        }
    }

    #[test]
    fn transferred_stream_is_owned_by_foreign_close() {
        let stream = RegisteredIo::register(Cursor::new(b"core".to_vec()), 1).unwrap();
        let (handle, table) = stream.raw_parts();
        stream.transfer();
        let mut output = [0; 4];
        let result = unsafe {
            (*table).read.unwrap()(
                handle,
                SnolBytesMut {
                    pointer: output.as_mut_ptr(),
                    length: output.len(),
                },
                no_wake(),
            )
        };
        assert_eq!(result, SnolIoResult::progress(4));
        assert_eq!(&output, b"core");
        assert_eq!(
            unsafe { (*table).close.unwrap()(handle) },
            snolc_abi::STATUS_OK
        );
    }

    #[test]
    fn untransferred_stream_is_removed_on_drop() {
        let stream = RegisteredIo::register(Cursor::new(Vec::new()), 1).unwrap();
        let (handle, table) = stream.raw_parts();
        drop(stream);
        assert_eq!(
            unsafe { (*table).close.unwrap()(handle) },
            snolc_abi::STATUS_INVALID
        );
    }

    #[test]
    fn registration_lifetime_is_observable() {
        let stream = RegisteredIo::register(Cursor::new(Vec::<u8>::new()), 1).unwrap();
        let (handle, _) = stream.raw_parts();
        assert!(is_registered(handle));
        drop(stream);
        assert!(!is_registered(handle));
    }

    struct MemoryDatagram {
        input: VecDeque<Vec<u8>>,
        output: Vec<Vec<u8>>,
    }

    impl DatagramIo for MemoryDatagram {
        fn poll_recv_datagram(
            &mut self,
            _context: &mut Context<'_>,
            output: &mut [u8],
        ) -> Poll<io::Result<DatagramRecv>> {
            let Some(datagram) = self.input.front() else {
                return Poll::Pending;
            };
            if output.len() < datagram.len() {
                return Poll::Ready(Ok(DatagramRecv::BufferTooSmall(datagram.len())));
            }
            let datagram = self.input.pop_front().expect("front checked");
            output[..datagram.len()].copy_from_slice(&datagram);
            Poll::Ready(Ok(DatagramRecv::Datagram(datagram.len())))
        }

        fn poll_send_datagram(
            &mut self,
            _context: &mut Context<'_>,
            datagram: &[u8],
        ) -> Poll<io::Result<()>> {
            self.output.push(datagram.to_vec());
            Poll::Ready(Ok(()))
        }

        fn close(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn registered_datagram_preserves_required_length_and_empty_payload() {
        let io = MemoryDatagram {
            input: [b"wide".to_vec(), Vec::new()].into(),
            output: Vec::new(),
        };
        let registered = RegisteredDatagramIo::register(io, 1).unwrap();
        let (handle, table) = registered.raw_parts();
        let mut small = [0; 3];
        let result = unsafe {
            (*table).recv_datagram.unwrap()(
                handle,
                SnolBytesMut {
                    pointer: small.as_mut_ptr(),
                    length: small.len(),
                },
                no_wake(),
            )
        };
        assert_eq!(result, SnolIoResult::buffer_too_small(4));
        let mut output = [0; 4];
        let result = unsafe {
            (*table).recv_datagram.unwrap()(
                handle,
                SnolBytesMut {
                    pointer: output.as_mut_ptr(),
                    length: output.len(),
                },
                no_wake(),
            )
        };
        assert_eq!(result, SnolIoResult::progress(4));
        assert_eq!(&output, b"wide");
        let result = unsafe {
            (*table).recv_datagram.unwrap()(
                handle,
                SnolBytesMut {
                    pointer: std::ptr::null_mut(),
                    length: 0,
                },
                no_wake(),
            )
        };
        assert_eq!(result, SnolIoResult::progress(0));
    }

    #[test]
    fn mux_datagram_frames_zero_and_maximum_payloads() {
        let payload = vec![9; crate::wire::MAX_UDP_PAYLOAD];
        let mut encoded = vec![0, 0];
        encoded.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        encoded.extend_from_slice(&payload);
        let mut io = MuxDatagramIo::new(Cursor::new(encoded));
        let mut context = Context::from_waker(Waker::noop());
        assert!(matches!(
            io.poll_recv_datagram(&mut context, &mut []),
            Poll::Ready(Ok(DatagramRecv::Datagram(0)))
        ));
        assert!(matches!(
            io.poll_recv_datagram(&mut context, &mut [0; 1]),
            Poll::Ready(Ok(DatagramRecv::BufferTooSmall(crate::wire::MAX_UDP_PAYLOAD)))
        ));
        let mut output = vec![0; crate::wire::MAX_UDP_PAYLOAD];
        assert!(matches!(
            io.poll_recv_datagram(&mut context, &mut output),
            Poll::Ready(Ok(DatagramRecv::Datagram(crate::wire::MAX_UDP_PAYLOAD)))
        ));
        assert_eq!(output, payload);

        let mut io = MuxDatagramIo::new(Cursor::new(Vec::new()));
        assert!(matches!(
            io.poll_send_datagram(&mut context, b"one"),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(io.stream.into_inner(), [0, 3, b'o', b'n', b'e']);
    }
}
