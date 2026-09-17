mod support;

use std::io;
use std::task::{Context, Poll, Waker};

use snolc_sdk::{Adapter, Module, StackSocket};
use support::MemoryIo;

struct ExampleAdapter {
    pending: Option<StackSocket<MemoryIo>>,
}

impl Module for ExampleAdapter {
    type Error = io::Error;

    fn poll(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Pending
    }

    fn control(&mut self, _request: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Err(io::ErrorKind::Unsupported.into())
    }

    fn shutdown(&mut self) -> Result<(), Self::Error> {
        self.pending = None;
        Ok(())
    }
}

impl Adapter for ExampleAdapter {
    type Flow = StackSocket<MemoryIo>;

    fn poll_open(&mut self, _context: &mut Context<'_>) -> Poll<Result<Self::Flow, Self::Error>> {
        self.pending
            .take()
            .map_or(Poll::Pending, |flow| Poll::Ready(Ok(flow)))
    }
}

fn main() {
    let mut adapter = ExampleAdapter {
        pending: Some(StackSocket(MemoryIo::with_input(b"request"))),
    };
    let mut context = Context::from_waker(Waker::noop());
    let Poll::Ready(Ok(flow)) = adapter.poll_open(&mut context) else {
        panic!("adapter did not return its pending flow");
    };
    assert!(flow.0.output().is_empty());
    assert!(matches!(adapter.poll_open(&mut context), Poll::Pending));
}
