mod support;

use std::io;
use std::task::{Context, Poll, Waker};

use snolc_sdk::{Carrier, Module};
use support::MemoryIo;

struct ExampleCarrier {
    connected: Option<MemoryIo>,
    accepted: Option<MemoryIo>,
}

impl Module for ExampleCarrier {
    type Error = io::Error;

    fn poll(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Pending
    }

    fn control(&mut self, _request: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Err(io::ErrorKind::Unsupported.into())
    }

    fn shutdown(&mut self) -> Result<(), Self::Error> {
        self.connected = None;
        self.accepted = None;
        Ok(())
    }
}

impl Carrier for ExampleCarrier {
    type Stream = MemoryIo;

    fn poll_connect(
        &mut self,
        _context: &mut Context<'_>,
    ) -> Poll<Result<Self::Stream, Self::Error>> {
        self.connected
            .take()
            .map_or(Poll::Pending, |stream| Poll::Ready(Ok(stream)))
    }

    fn poll_accept(
        &mut self,
        _context: &mut Context<'_>,
    ) -> Poll<Result<Self::Stream, Self::Error>> {
        self.accepted
            .take()
            .map_or(Poll::Pending, |stream| Poll::Ready(Ok(stream)))
    }
}

fn main() {
    let mut carrier = ExampleCarrier {
        connected: Some(MemoryIo::with_input(b"connected")),
        accepted: Some(MemoryIo::with_input(b"accepted")),
    };
    let mut context = Context::from_waker(Waker::noop());
    let Poll::Ready(Ok(connected)) = carrier.poll_connect(&mut context) else {
        panic!("carrier did not complete connect");
    };
    let Poll::Ready(Ok(accepted)) = carrier.poll_accept(&mut context) else {
        panic!("carrier did not accept a stream");
    };
    assert!(connected.output().is_empty());
    assert!(accepted.output().is_empty());
}
