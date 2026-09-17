use std::io;
use std::task::{Context, Poll};

use thiserror::Error;

use crate::ByteIo;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PumpReport {
    pub read: usize,
    pub written: usize,
    pub finished: bool,
}

pub struct Pump {
    buffer: Vec<u8>,
    start: usize,
    end: usize,
    source_eof: bool,
    destination_shutdown: bool,
}

impl Pump {
    pub fn new(capacity: usize) -> Result<Self, PumpError> {
        if capacity == 0 {
            return Err(PumpError::ZeroCapacity);
        }
        Ok(Self {
            buffer: vec![0; capacity],
            start: 0,
            end: 0,
            source_eof: false,
            destination_shutdown: false,
        })
    }

    pub fn pending_bytes(&self) -> usize {
        self.end - self.start
    }

    pub fn is_finished(&self) -> bool {
        self.destination_shutdown
    }

    pub fn poll<S: ByteIo + ?Sized, D: ByteIo + ?Sized>(
        &mut self,
        context: &mut Context<'_>,
        source: &mut S,
        destination: &mut D,
        max_work: usize,
    ) -> Poll<Result<PumpReport, PumpError>> {
        let mut report = PumpReport::default();
        let mut budget = max_work;

        while budget > 0 {
            if self.start < self.end {
                let end = self.end.min(self.start + budget);
                match destination.poll_write(context, &self.buffer[self.start..end]) {
                    Poll::Ready(Ok(0)) => return Poll::Ready(Err(PumpError::WriteZero)),
                    Poll::Ready(Ok(written)) => {
                        self.start += written;
                        report.written += written;
                        budget -= written;
                        if self.start == self.end {
                            self.start = 0;
                            self.end = 0;
                        }
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                    Poll::Pending => return ready_or_pending(report),
                }
                continue;
            }

            if self.source_eof {
                if !self.destination_shutdown {
                    match destination.poll_shutdown_write(context) {
                        Poll::Ready(Ok(())) => self.destination_shutdown = true,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                        Poll::Pending => return ready_or_pending(report),
                    }
                }
                report.finished = true;
                return Poll::Ready(Ok(report));
            }

            let read_limit = self.buffer.len().min(budget);
            match source.poll_read(context, &mut self.buffer[..read_limit]) {
                Poll::Ready(Ok(0)) => self.source_eof = true,
                Poll::Ready(Ok(read)) => {
                    self.end = read;
                    report.read += read;
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                Poll::Pending => return ready_or_pending(report),
            }
        }

        Poll::Ready(Ok(report))
    }
}

fn ready_or_pending(report: PumpReport) -> Poll<Result<PumpReport, PumpError>> {
    if report.read == 0 && report.written == 0 {
        Poll::Pending
    } else {
        Poll::Ready(Ok(report))
    }
}

#[derive(Debug, Error)]
pub enum PumpError {
    #[error("pump capacity must be nonzero")]
    ZeroCapacity,
    #[error("I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("writer returned zero for a nonempty buffer")]
    WriteZero,
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::task::Waker;

    use super::*;

    #[derive(Default)]
    struct MemoryIo {
        input: VecDeque<u8>,
        output: Vec<u8>,
        max_write: usize,
        pending_write: bool,
        shutdown: bool,
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

        fn poll_write(
            &mut self,
            _context: &mut Context<'_>,
            input: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.pending_write {
                self.pending_write = false;
                return Poll::Pending;
            }
            let count = input.len().min(self.max_write);
            self.output.extend_from_slice(&input[..count]);
            Poll::Ready(Ok(count))
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

    #[test]
    fn preserves_partial_writes_and_half_close() {
        let mut source = MemoryIo {
            input: b"abcdef".iter().copied().collect(),
            ..MemoryIo::default()
        };
        let mut destination = MemoryIo {
            max_write: 2,
            ..MemoryIo::default()
        };
        let mut pump = Pump::new(4).unwrap();
        let mut context = Context::from_waker(Waker::noop());
        while !pump.is_finished() {
            let _ = pump.poll(&mut context, &mut source, &mut destination, 3);
        }
        assert_eq!(destination.output, b"abcdef");
        assert!(destination.shutdown);
    }

    #[test]
    fn keeps_pending_data_under_backpressure() {
        let mut source = MemoryIo {
            input: b"abc".iter().copied().collect(),
            ..MemoryIo::default()
        };
        let mut destination = MemoryIo {
            max_write: 3,
            pending_write: true,
            ..MemoryIo::default()
        };
        let mut pump = Pump::new(3).unwrap();
        let mut context = Context::from_waker(Waker::noop());
        let report = pump.poll(&mut context, &mut source, &mut destination, 3);
        assert!(matches!(
            report,
            Poll::Ready(Ok(PumpReport {
                read: 3,
                written: 0,
                finished: false
            }))
        ));
        assert_eq!(pump.pending_bytes(), 3);
    }

    #[test]
    fn rejects_zero_write_progress() {
        let mut source = MemoryIo {
            input: b"x".iter().copied().collect(),
            ..MemoryIo::default()
        };
        let mut destination = MemoryIo::default();
        let mut pump = Pump::new(1).unwrap();
        let mut context = Context::from_waker(Waker::noop());
        assert!(matches!(
            pump.poll(&mut context, &mut source, &mut destination, 1),
            Poll::Ready(Err(PumpError::WriteZero))
        ));
    }
}
