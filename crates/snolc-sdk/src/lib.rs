#![deny(unsafe_op_in_unsafe_fn)]

mod handles;
mod io;
pub mod module;
mod module_io;
mod pump;
mod resolved;

pub use handles::{HandleError, HandleTable, TypedHandle};
pub use io::{ByteIo, DatagramIo, DatagramRecv};
pub use module_io::{ForeignByteIo, ForeignDatagramIo, ForeignIoError};
pub use pump::{DatagramPump, DatagramPumpReport, Pump, PumpError, PumpReport};
pub use resolved::{
    MAX_RESOLVED_ADDRESSES, ResolvedAddressError, decode_resolved_addresses,
    encode_resolved_addresses, resolved_addresses_size,
};
pub use snolc_abi as abi;

use std::task::{Context, Poll};

#[derive(Clone, Copy)]
pub struct HostApi(*const abi::SnolHostApiV1);

// host tables are immutable and protect_socket is the only worker-thread call exposed here.
unsafe impl Send for HostApi {}
unsafe impl Sync for HostApi {}

impl HostApi {
    /// # Safety
    ///
    /// `host` must remain valid while this wrapper is used.
    pub unsafe fn from_raw(host: *const abi::SnolHostApiV1) -> Result<Self, u32> {
        let Some(host) = (unsafe { host.as_ref() }) else {
            return Err(abi::STATUS_INVALID);
        };
        if host.struct_size < size_of::<abi::SnolHostApiV1>() as u32 || host.reserved != 0 {
            return Err(abi::STATUS_INVALID);
        }
        Ok(Self(host))
    }

    pub fn protect_socket(self, socket: i64) -> Result<(), u32> {
        let host = unsafe { &*self.0 };
        let protect = host.protect_socket.ok_or(abi::STATUS_UNSUPPORTED)?;
        let status = unsafe { protect(host.context, socket) };
        if status == abi::STATUS_OK {
            Ok(())
        } else {
            Err(status)
        }
    }
}

pub struct StackSocket<T>(pub T);
pub struct MuxStream<T>(pub T);

pub trait Module {
    type Error;

    fn poll(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>>;
    fn control(&mut self, request: &[u8]) -> Result<Vec<u8>, Self::Error>;
    fn shutdown(&mut self) -> Result<(), Self::Error>;
}

pub trait Adapter: Module {
    type Flow;

    fn poll_open(&mut self, context: &mut Context<'_>) -> Poll<Result<Self::Flow, Self::Error>>;
}

pub trait Protection: Module {
    type Input: ByteIo;
    type Output: ByteIo;

    fn wrap(&mut self, input: Self::Input) -> Result<Self::Output, Self::Error>;
}

pub trait Carrier: Module {
    type Stream: ByteIo;

    fn poll_connect(
        &mut self,
        context: &mut Context<'_>,
    ) -> Poll<Result<Self::Stream, Self::Error>>;
    fn poll_accept(&mut self, context: &mut Context<'_>)
    -> Poll<Result<Self::Stream, Self::Error>>;
}

pub trait Policy: Module {
    type Session;
    type Flow;

    fn attach_session(&mut self, session: Self::Session) -> Result<u64, Self::Error>;
    fn admit_flow(
        &mut self,
        context: &mut Context<'_>,
        session: u64,
        metadata: &[u8],
    ) -> Poll<Result<(), Self::Error>>;
    fn attach_flow(&mut self, session: u64, flow: Self::Flow) -> Result<(), Self::Error>;
}

pub fn catch_status(function: impl FnOnce() -> u32) -> u32 {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(function))
        .unwrap_or(snolc_abi::STATUS_INTERNAL)
}

pub fn catch_io(function: impl FnOnce() -> abi::SnolIoResult) -> abi::SnolIoResult {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(function))
        .unwrap_or_else(|_| abi::SnolIoResult::error(abi::STATUS_INTERNAL))
}

#[cfg(test)]
mod tests {
    use std::ffi::c_void;

    use super::*;

    unsafe extern "C" fn protect(context: *mut c_void, socket: i64) -> u32 {
        let expected = context as usize as i64;
        if socket == expected {
            abi::STATUS_OK
        } else {
            abi::STATUS_DENIED
        }
    }

    #[test]
    fn host_api_forwards_socket_protection_status() {
        let raw = abi::SnolHostApiV1 {
            struct_size: size_of::<abi::SnolHostApiV1>() as u32,
            reserved: 0,
            context: 42usize as *mut c_void,
            now_monotonic_nanos: None,
            set_timer: None,
            emit_event: None,
            context_get: None,
            context_set: None,
            protect_socket: Some(protect),
        };
        let host = unsafe { HostApi::from_raw(&raw) }.unwrap();
        assert_eq!(host.protect_socket(42), Ok(()));
        assert_eq!(host.protect_socket(41), Err(abi::STATUS_DENIED));
    }
}
