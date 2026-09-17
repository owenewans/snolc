mod support;

use std::io;
use std::task::{Context, Poll};

use snolc_sdk::{ByteIo, Module, Protection};
use support::MemoryIo;

struct PassthroughProtection;

impl Module for PassthroughProtection {
    type Error = io::Error;

    fn poll(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Pending
    }

    fn control(&mut self, _request: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Err(io::ErrorKind::Unsupported.into())
    }

    fn shutdown(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl Protection for PassthroughProtection {
    type Input = MemoryIo;
    type Output = MemoryIo;

    fn wrap(&mut self, input: Self::Input) -> Result<Self::Output, Self::Error> {
        Ok(input)
    }
}

fn main() {
    let mut protection = PassthroughProtection;
    let mut stream = protection
        .wrap(MemoryIo::with_input(b"protected bytes"))
        .unwrap();
    let mut output = [0; 15];
    let mut context = Context::from_waker(std::task::Waker::noop());
    assert!(matches!(
        stream.poll_read(&mut context, &mut output),
        Poll::Ready(Ok(15))
    ));
    assert_eq!(&output, b"protected bytes");
    assert!(stream.output().is_empty());
}
