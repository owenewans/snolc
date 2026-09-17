use std::io;
use std::marker::PhantomData;
use std::ptr::NonNull;
use std::rc::Rc;
use std::task::{Context, Poll};

use crate::ByteIo;
use crate::abi::{self, SnolByteIoV1, SnolBytes, SnolBytesMut, SnolIoResult, SnolWakeHandle};

pub struct ForeignByteIo {
    handle: u64,
    table: NonNull<SnolByteIoV1>,
    closed: bool,
    not_send: PhantomData<Rc<()>>,
}

impl ForeignByteIo {
    /// # Safety
    ///
    /// `table` must remain valid until this object is dropped, and `handle` must
    /// belong to that table.
    pub unsafe fn from_raw(
        handle: u64,
        table: *const SnolByteIoV1,
    ) -> Result<Self, ForeignIoError> {
        let table = NonNull::new(table.cast_mut()).ok_or(ForeignIoError::Table)?;
        let value = unsafe { table.as_ref() };
        if handle == 0
            || value.struct_size < size_of::<SnolByteIoV1>() as u32
            || value.reserved != 0
            || value.read.is_none()
            || value.write.is_none()
            || value.flush.is_none()
            || value.shutdown_write.is_none()
            || value.close.is_none()
        {
            return Err(ForeignIoError::Table);
        }
        Ok(Self {
            handle,
            table,
            closed: false,
            not_send: PhantomData,
        })
    }

    fn table(&self) -> &SnolByteIoV1 {
        unsafe { self.table.as_ref() }
    }
}

impl ByteIo for ForeignByteIo {
    fn poll_read(
        &mut self,
        _context: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let read = self.table().read.expect("validated table");
        let result = unsafe {
            read(
                self.handle,
                SnolBytesMut {
                    pointer: output.as_mut_ptr(),
                    length: output.len(),
                },
                no_wake(),
            )
        };
        map_io(result, output.len(), true)
    }

    fn poll_write(&mut self, _context: &mut Context<'_>, input: &[u8]) -> Poll<io::Result<usize>> {
        let write = self.table().write.expect("validated table");
        let result = unsafe {
            write(
                self.handle,
                SnolBytes {
                    pointer: input.as_ptr(),
                    length: input.len(),
                },
                no_wake(),
            )
        };
        map_io(result, input.len(), false)
    }

    fn poll_flush(&mut self, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let flush = self.table().flush.expect("validated table");
        map_action(unsafe { flush(self.handle, no_wake()) })
    }

    fn poll_shutdown_write(&mut self, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let shutdown = self.table().shutdown_write.expect("validated table");
        map_action(unsafe { shutdown(self.handle, no_wake()) })
    }

    fn close(&mut self) -> io::Result<()> {
        if self.closed {
            return Ok(());
        }
        let close = self.table().close.expect("validated table");
        let status = unsafe { close(self.handle) };
        self.closed = true;
        if status == abi::STATUS_OK {
            Ok(())
        } else {
            Err(status_error(status))
        }
    }
}

impl Drop for ForeignByteIo {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

fn no_wake() -> SnolWakeHandle {
    SnolWakeHandle {
        context: std::ptr::null_mut(),
        wake: None,
        retain: None,
        release: None,
    }
}

fn map_io(result: SnolIoResult, limit: usize, read: bool) -> Poll<io::Result<usize>> {
    match result.tag {
        abi::IO_PROGRESS if result.code == abi::STATUS_OK && result.count <= limit => {
            Poll::Ready(Ok(result.count))
        }
        abi::IO_PENDING if result.code == abi::STATUS_OK && result.count == 0 => Poll::Pending,
        abi::IO_EOF if read && result.code == abi::STATUS_OK && result.count == 0 => {
            Poll::Ready(Ok(0))
        }
        abi::IO_ERROR if result.count == 0 => Poll::Ready(Err(status_error(result.code))),
        _ => Poll::Ready(Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "foreign module returned an invalid I/O result",
        ))),
    }
}

fn map_action(result: SnolIoResult) -> Poll<io::Result<()>> {
    match result.tag {
        abi::IO_PROGRESS if result.code == abi::STATUS_OK && result.count == 0 => {
            Poll::Ready(Ok(()))
        }
        abi::IO_PENDING if result.code == abi::STATUS_OK && result.count == 0 => Poll::Pending,
        abi::IO_ERROR if result.count == 0 => Poll::Ready(Err(status_error(result.code))),
        _ => Poll::Ready(Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "foreign module returned an invalid I/O action result",
        ))),
    }
}

fn status_error(status: u32) -> io::Error {
    io::Error::other(format!("foreign module I/O failed with status {status}"))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForeignIoError {
    Table,
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::Waker;

    use super::*;

    static CLOSED: AtomicBool = AtomicBool::new(false);

    unsafe extern "C" fn read(_: u64, output: SnolBytesMut, _: SnolWakeHandle) -> SnolIoResult {
        if output.length < 1 {
            return SnolIoResult::buffer_too_small(1);
        }
        unsafe { *output.pointer = 7 };
        SnolIoResult::progress(1)
    }

    unsafe extern "C" fn write(_: u64, input: SnolBytes, _: SnolWakeHandle) -> SnolIoResult {
        SnolIoResult::progress(input.length)
    }

    unsafe extern "C" fn action(_: u64, _: SnolWakeHandle) -> SnolIoResult {
        SnolIoResult::progress(0)
    }

    unsafe extern "C" fn close(_: u64) -> u32 {
        CLOSED.store(true, Ordering::Release);
        abi::STATUS_OK
    }

    static TABLE: SnolByteIoV1 = SnolByteIoV1 {
        struct_size: size_of::<SnolByteIoV1>() as u32,
        reserved: 0,
        read: Some(read),
        write: Some(write),
        flush: Some(action),
        shutdown_write: Some(action),
        close: Some(close),
    };

    #[test]
    fn delegates_and_closes_owned_handle() {
        CLOSED.store(false, Ordering::Release);
        let mut io = unsafe { ForeignByteIo::from_raw(1, &TABLE) }.unwrap();
        let mut context = Context::from_waker(Waker::noop());
        let mut output = [0];
        assert!(matches!(
            io.poll_read(&mut context, &mut output),
            Poll::Ready(Ok(1))
        ));
        assert_eq!(output, [7]);
        assert!(matches!(
            io.poll_write(&mut context, b"two"),
            Poll::Ready(Ok(3))
        ));
        drop(io);
        assert!(CLOSED.load(Ordering::Acquire));
    }
}
