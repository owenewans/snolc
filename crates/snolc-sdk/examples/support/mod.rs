use std::collections::VecDeque;
use std::io;
use std::task::{Context, Poll};

use snolc_sdk::ByteIo;

#[derive(Default)]
pub struct MemoryIo {
    input: VecDeque<u8>,
    output: Vec<u8>,
    pub shutdown: bool,
}

impl MemoryIo {
    pub fn with_input(input: &[u8]) -> Self {
        Self {
            input: input.iter().copied().collect(),
            ..Self::default()
        }
    }

    pub fn output(&self) -> &[u8] {
        &self.output
    }
}

impl ByteIo for MemoryIo {
    fn poll_read(
        &mut self,
        _context: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let count = output.len().min(self.input.len());
        for byte in &mut output[..count] {
            *byte = self.input.pop_front().expect("count checked");
        }
        Poll::Ready(Ok(count))
    }

    fn poll_write(&mut self, _context: &mut Context<'_>, input: &[u8]) -> Poll<io::Result<usize>> {
        self.output.extend_from_slice(input);
        Poll::Ready(Ok(input.len()))
    }

    fn poll_flush(&mut self, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown_write(&mut self, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.shutdown = true;
        Poll::Ready(Ok(()))
    }

    fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}
