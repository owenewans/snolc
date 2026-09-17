use std::cell::RefCell;
use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, Waker};

use futures::io::{AsyncRead, AsyncWrite};
use snolc_abi::{SnolByteIoV1, SnolBytes, SnolBytesMut, SnolIoResult, SnolWakeHandle};
use thiserror::Error;

trait CoreIo: AsyncRead + AsyncWrite + Unpin {}
impl<T: AsyncRead + AsyncWrite + Unpin> CoreIo for T {}

thread_local! {
    static STREAMS: RefCell<HashMap<u64, Box<dyn CoreIo>>> = RefCell::new(HashMap::new());
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
            if streams.len() >= limit {
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

pub(crate) fn is_registered(handle: u64) -> bool {
    STREAMS.with(|streams| streams.borrow().contains_key(&handle))
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

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum CoreIoError {
    #[error("core I/O registry limit is exhausted")]
    Limit,
    #[error("core I/O handle space is exhausted")]
    Handle,
}

#[cfg(test)]
mod tests {
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
}
