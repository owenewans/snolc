#![deny(unsafe_op_in_unsafe_fn)]

use std::cell::RefCell;
use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use serde::Deserialize;
use snolc_sdk::ByteIo;
use snolc_sdk::abi::{
    self, SnolByteIoV1, SnolBytes, SnolBytesMut, SnolIoResult, SnolProtectionApiV1, SnolWakeHandle,
};

pub struct Dummy<T>(pub T);

impl<T: ByteIo> ByteIo for Dummy<T> {
    fn poll_read(
        &mut self,
        context: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        self.0.poll_read(context, output)
    }

    fn poll_write(&mut self, context: &mut Context<'_>, input: &[u8]) -> Poll<io::Result<usize>> {
        self.0.poll_write(context, input)
    }

    fn poll_flush(&mut self, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0.poll_flush(context)
    }

    fn poll_shutdown_write(&mut self, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0.poll_shutdown_write(context)
    }

    fn close(&mut self) -> io::Result<()> {
        self.0.close()
    }
}

#[derive(Clone, Copy)]
struct Wrapped {
    lower: u64,
    io: *const SnolByteIoV1,
}

thread_local! {
    static WRAPPED: RefCell<HashMap<u64, Wrapped>> = RefCell::new(HashMap::new());
}

static NEXT: AtomicU64 = AtomicU64::new(1);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Options {}

fn validate_config(config: &[u8], _base: &[u8]) -> Result<(), String> {
    let text = std::str::from_utf8(config).map_err(|_| "config is not UTF-8".to_owned())?;
    let _: Options = toml::from_str(text).map_err(|error| error.to_string())?;
    Ok(())
}

unsafe extern "C" fn wrap(
    instance: u64,
    lower: u64,
    io: *const SnolByteIoV1,
    _context: SnolBytes,
    _wake: SnolWakeHandle,
    output: *mut u64,
) -> u32 {
    snolc_sdk::catch_status(|| {
        if !INSTANCES.contains(instance) || lower == 0 || io.is_null() {
            return abi::STATUS_INVALID;
        }
        let io_ref = unsafe { &*io };
        if io_ref.struct_size < size_of::<SnolByteIoV1>() as u32
            || io_ref.reserved != 0
            || io_ref.read.is_none()
            || io_ref.write.is_none()
            || io_ref.flush.is_none()
            || io_ref.shutdown_write.is_none()
            || io_ref.close.is_none()
        {
            return abi::STATUS_INVALID;
        }
        let Some(output) = (unsafe { output.as_mut() }) else {
            return abi::STATUS_INVALID;
        };
        let handle = NEXT.fetch_add(1, Ordering::Relaxed);
        if handle == 0 {
            return abi::STATUS_RESOURCE;
        }
        WRAPPED.with(|wrapped| wrapped.borrow_mut().insert(handle, Wrapped { lower, io }));
        *output = handle;
        abi::STATUS_OK
    })
}

fn wrapped(handle: u64) -> Option<Wrapped> {
    WRAPPED.with(|wrapped| wrapped.borrow().get(&handle).copied())
}

unsafe extern "C" fn read(handle: u64, output: SnolBytesMut, wake: SnolWakeHandle) -> SnolIoResult {
    let Some(wrapped) = wrapped(handle) else {
        return SnolIoResult::error(abi::STATUS_INVALID);
    };
    let Some(read) = (unsafe { &*wrapped.io }).read else {
        return SnolIoResult::error(abi::STATUS_INVALID);
    };
    unsafe { read(wrapped.lower, output, wake) }
}

unsafe extern "C" fn write(handle: u64, input: SnolBytes, wake: SnolWakeHandle) -> SnolIoResult {
    let Some(wrapped) = wrapped(handle) else {
        return SnolIoResult::error(abi::STATUS_INVALID);
    };
    let Some(write) = (unsafe { &*wrapped.io }).write else {
        return SnolIoResult::error(abi::STATUS_INVALID);
    };
    unsafe { write(wrapped.lower, input, wake) }
}

unsafe extern "C" fn flush(handle: u64, wake: SnolWakeHandle) -> SnolIoResult {
    let Some(wrapped) = wrapped(handle) else {
        return SnolIoResult::error(abi::STATUS_INVALID);
    };
    let Some(flush) = (unsafe { &*wrapped.io }).flush else {
        return SnolIoResult::error(abi::STATUS_INVALID);
    };
    unsafe { flush(wrapped.lower, wake) }
}

unsafe extern "C" fn shutdown_write(handle: u64, wake: SnolWakeHandle) -> SnolIoResult {
    let Some(wrapped) = wrapped(handle) else {
        return SnolIoResult::error(abi::STATUS_INVALID);
    };
    let Some(shutdown) = (unsafe { &*wrapped.io }).shutdown_write else {
        return SnolIoResult::error(abi::STATUS_INVALID);
    };
    unsafe { shutdown(wrapped.lower, wake) }
}

unsafe extern "C" fn close(handle: u64) -> u32 {
    let Some(wrapped) = WRAPPED.with(|wrapped| wrapped.borrow_mut().remove(&handle)) else {
        return abi::STATUS_INVALID;
    };
    let Some(close) = (unsafe { &*wrapped.io }).close else {
        return abi::STATUS_INVALID;
    };
    unsafe { close(wrapped.lower) }
}

static BYTE_IO: SnolByteIoV1 = SnolByteIoV1 {
    struct_size: size_of::<SnolByteIoV1>() as u32,
    reserved: 0,
    read: Some(read),
    write: Some(write),
    flush: Some(flush),
    shutdown_write: Some(shutdown_write),
    close: Some(close),
};

static PROTECTION: SnolProtectionApiV1 = SnolProtectionApiV1 {
    struct_size: size_of::<SnolProtectionApiV1>() as u32,
    reserved: 0,
    wrap: Some(wrap),
};

snolc_sdk::declare_module! {
    name: "protection-dummy",
    description: "name = \"protection-dummy\"\nroles = [\"client\", \"server\"]\nconfidentiality = false\nintegrity = false\n",
    class_mask: abi::CLASS_PROTECTION,
    validate: validate_config,
    byte_io: &BYTE_IO,
    datagram_io: std::ptr::null(),
    adapter: std::ptr::null(),
    protection: &PROTECTION,
    carrier: std::ptr::null(),
    policy: std::ptr::null(),
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::task::Waker;

    use super::*;

    #[derive(Default)]
    struct Memory {
        input: VecDeque<u8>,
        output: Vec<u8>,
    }

    impl ByteIo for Memory {
        fn poll_read(&mut self, _: &mut Context<'_>, output: &mut [u8]) -> Poll<io::Result<usize>> {
            let count = output.len().min(self.input.len());
            for byte in &mut output[..count] {
                *byte = self.input.pop_front().unwrap();
            }
            Poll::Ready(Ok(count))
        }

        fn poll_write(&mut self, _: &mut Context<'_>, input: &[u8]) -> Poll<io::Result<usize>> {
            self.output.extend_from_slice(input);
            Poll::Ready(Ok(input.len()))
        }

        fn poll_flush(&mut self, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown_write(&mut self, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn close(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn delegates_without_transforming_bytes() {
        let mut dummy = Dummy(Memory {
            input: b"read".iter().copied().collect(),
            ..Memory::default()
        });
        let mut context = Context::from_waker(Waker::noop());
        let mut output = [0; 4];
        assert!(matches!(
            dummy.poll_read(&mut context, &mut output),
            Poll::Ready(Ok(4))
        ));
        assert_eq!(&output, b"read");
        assert!(matches!(
            dummy.poll_write(&mut context, b"write"),
            Poll::Ready(Ok(5))
        ));
        assert_eq!(dummy.0.output, b"write");
    }
}
