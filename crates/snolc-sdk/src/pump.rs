use std::io;
use std::task::{Context, Poll};

use thiserror::Error;

use crate::{ByteIo, DatagramIo, DatagramRecv};

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

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DatagramPumpReport {
    pub received: usize,
    pub sent: usize,
    pub finished: bool,
}

pub struct DatagramPump {
    buffer: Vec<u8>,
    pending: Option<usize>,
    source_closed: bool,
}

impl DatagramPump {
    pub fn new(max_datagram_bytes: usize) -> Result<Self, PumpError> {
        if max_datagram_bytes == 0 {
            return Err(PumpError::ZeroCapacity);
        }
        Ok(Self {
            buffer: vec![0; max_datagram_bytes],
            pending: None,
            source_closed: false,
        })
    }

    pub fn pending_bytes(&self) -> usize {
        self.pending.unwrap_or(0)
    }

    pub fn is_finished(&self) -> bool {
        self.source_closed && self.pending.is_none()
    }

    pub fn poll<S: DatagramIo + ?Sized, D: DatagramIo + ?Sized>(
        &mut self,
        context: &mut Context<'_>,
        source: &mut S,
        destination: &mut D,
    ) -> Poll<Result<DatagramPumpReport, PumpError>> {
        let mut report = DatagramPumpReport::default();
        if self.pending.is_none() && !self.source_closed {
            match source.poll_recv_datagram(context, &mut self.buffer) {
                Poll::Ready(Ok(DatagramRecv::Datagram(length))) if length <= self.buffer.len() => {
                    self.pending = Some(length);
                    report.received = length;
                }
                Poll::Ready(Ok(DatagramRecv::BufferTooSmall(required))) => {
                    return Poll::Ready(Err(PumpError::DatagramTooLarge(required)));
                }
                Poll::Ready(Ok(DatagramRecv::Closed)) => self.source_closed = true,
                Poll::Ready(Ok(_)) => return Poll::Ready(Err(PumpError::InvalidDatagram)),
                Poll::Ready(Err(error)) => return Poll::Ready(Err(PumpError::Io(error))),
                Poll::Pending => return Poll::Pending,
            }
        }
        if let Some(length) = self.pending {
            match destination.poll_send_datagram(context, &self.buffer[..length]) {
                Poll::Ready(Ok(())) => {
                    self.pending = None;
                    report.sent = length;
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(PumpError::Io(error))),
                Poll::Pending => return Poll::Pending,
            }
        }
        report.finished = self.is_finished();
        Poll::Ready(Ok(report))
    }
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
    #[error("datagram requires {0} bytes, exceeding the pump buffer")]
    DatagramTooLarge(usize),
    #[error("datagram I/O returned an invalid length")]
    InvalidDatagram,
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

    #[derive(Default)]
    struct MemoryDatagram {
        input: VecDeque<Vec<u8>>,
        output: Vec<Vec<u8>>,
        pending_send: bool,
    }

    impl DatagramIo for MemoryDatagram {
        fn poll_recv_datagram(
            &mut self,
            _context: &mut Context<'_>,
            output: &mut [u8],
        ) -> Poll<io::Result<DatagramRecv>> {
            let Some(datagram) = self.input.front() else {
                return Poll::Pending;
            };
            if output.len() < datagram.len() {
                return Poll::Ready(Ok(DatagramRecv::BufferTooSmall(datagram.len())));
            }
            let datagram = self.input.pop_front().expect("front checked");
            output[..datagram.len()].copy_from_slice(&datagram);
            Poll::Ready(Ok(DatagramRecv::Datagram(datagram.len())))
        }

        fn poll_send_datagram(
            &mut self,
            _context: &mut Context<'_>,
            datagram: &[u8],
        ) -> Poll<io::Result<()>> {
            if self.pending_send {
                self.pending_send = false;
                return Poll::Pending;
            }
            self.output.push(datagram.to_vec());
            Poll::Ready(Ok(()))
        }

        fn close(&mut self) -> io::Result<()> {
            Ok(())
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

    #[test]
    fn datagram_pump_keeps_one_atomic_payload_under_backpressure() {
        let payload = vec![5; 65_507];
        let mut source = MemoryDatagram {
            input: [Vec::new(), payload.clone()].into(),
            ..MemoryDatagram::default()
        };
        let mut destination = MemoryDatagram {
            pending_send: true,
            ..MemoryDatagram::default()
        };
        let mut pump = DatagramPump::new(65_507).unwrap();
        let mut context = Context::from_waker(Waker::noop());
        assert!(matches!(
            pump.poll(&mut context, &mut source, &mut destination),
            Poll::Pending
        ));
        assert_eq!(pump.pending_bytes(), 0);
        assert!(matches!(
            pump.poll(&mut context, &mut source, &mut destination),
            Poll::Ready(Ok(DatagramPumpReport { sent: 0, .. }))
        ));
        assert_eq!(destination.output, [Vec::<u8>::new()]);
        assert!(matches!(
            pump.poll(&mut context, &mut source, &mut destination),
            Poll::Ready(Ok(DatagramPumpReport { sent: 65_507, .. }))
        ));
        assert_eq!(destination.output[1], payload);
    }
}
