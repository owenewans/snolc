#![deny(unsafe_op_in_unsafe_fn)]

mod handles;
mod io;
pub mod module;
mod module_io;
mod pump;

pub use handles::{HandleError, HandleTable, TypedHandle};
pub use io::{ByteIo, DatagramIo, DatagramRecv};
pub use module_io::{ForeignByteIo, ForeignDatagramIo, ForeignIoError};
pub use pump::{DatagramPump, DatagramPumpReport, Pump, PumpError, PumpReport};
pub use snolc_abi as abi;

use std::task::{Context, Poll};

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
