use std::io;
use std::task::{Context, Poll};

pub trait ByteIo {
    fn poll_read(
        &mut self,
        context: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<io::Result<usize>>;

    fn poll_write(&mut self, context: &mut Context<'_>, input: &[u8]) -> Poll<io::Result<usize>>;

    fn poll_flush(&mut self, context: &mut Context<'_>) -> Poll<io::Result<()>>;
    fn poll_shutdown_write(&mut self, context: &mut Context<'_>) -> Poll<io::Result<()>>;
    fn close(&mut self) -> io::Result<()>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatagramRecv {
    Datagram(usize),
    BufferTooSmall(usize),
    Closed,
}

pub trait DatagramIo {
    fn poll_recv_datagram(
        &mut self,
        context: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<io::Result<DatagramRecv>>;

    fn poll_send_datagram(
        &mut self,
        context: &mut Context<'_>,
        datagram: &[u8],
    ) -> Poll<io::Result<()>>;

    fn close(&mut self) -> io::Result<()>;
}
