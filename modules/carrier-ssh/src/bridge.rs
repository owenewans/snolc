use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use crossbeam_queue::ArrayQueue;
use futures::task::AtomicWaker;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(crate) fn pair(queue_chunks: usize, chunk_bytes: usize) -> (EngineIo, WorkerIo) {
    let to_worker = Arc::new(Pipe::new(queue_chunks));
    let to_engine = Arc::new(Pipe::new(queue_chunks));
    (
        EngineIo::new(Arc::clone(&to_engine), Arc::clone(&to_worker), chunk_bytes),
        WorkerIo::new(to_worker, to_engine, chunk_bytes),
    )
}

struct Pipe {
    queue: ArrayQueue<Vec<u8>>,
    closed: AtomicBool,
    reader: AtomicWaker,
    writer: AtomicWaker,
}

impl Pipe {
    fn new(chunks: usize) -> Self {
        Self {
            queue: ArrayQueue::new(chunks),
            closed: AtomicBool::new(false),
            reader: AtomicWaker::new(),
            writer: AtomicWaker::new(),
        }
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.reader.wake();
        self.writer.wake();
    }
}

struct Endpoint {
    incoming: Arc<Pipe>,
    outgoing: Arc<Pipe>,
    current: VecDeque<u8>,
    chunk_bytes: usize,
}

impl Endpoint {
    fn new(incoming: Arc<Pipe>, outgoing: Arc<Pipe>, chunk_bytes: usize) -> Self {
        Self {
            incoming,
            outgoing,
            current: VecDeque::new(),
            chunk_bytes,
        }
    }

    fn poll_read(
        &mut self,
        context: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if output.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.current.is_empty()
            && let Some(chunk) = self.incoming.queue.pop()
        {
            self.current = chunk.into();
            self.incoming.writer.wake();
        }
        if !self.current.is_empty() {
            let count = output.len().min(self.current.len());
            for target in &mut output[..count] {
                *target = self.current.pop_front().expect("length checked");
            }
            return Poll::Ready(Ok(count));
        }
        if self.incoming.closed.load(Ordering::Acquire) {
            return Poll::Ready(Ok(0));
        }
        self.incoming.reader.register(context.waker());
        if let Some(chunk) = self.incoming.queue.pop() {
            self.current = chunk.into();
            self.incoming.writer.wake();
            return self.poll_read(context, output);
        }
        if self.incoming.closed.load(Ordering::Acquire) {
            Poll::Ready(Ok(0))
        } else {
            Poll::Pending
        }
    }

    fn poll_write(&mut self, context: &mut Context<'_>, input: &[u8]) -> Poll<io::Result<usize>> {
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.outgoing.closed.load(Ordering::Acquire) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "SSH stream is closed",
            )));
        }
        let count = input.len().min(self.chunk_bytes);
        match self.outgoing.queue.push(input[..count].to_vec()) {
            Ok(()) => {
                self.outgoing.reader.wake();
                Poll::Ready(Ok(count))
            }
            Err(_) => {
                self.outgoing.writer.register(context.waker());
                if self.outgoing.queue.is_full() {
                    Poll::Pending
                } else {
                    self.poll_write(context, input)
                }
            }
        }
    }

    fn shutdown(&self) {
        self.outgoing.close();
    }
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        self.incoming.close();
        self.outgoing.close();
    }
}

pub(crate) struct EngineIo(Endpoint);

impl EngineIo {
    fn new(incoming: Arc<Pipe>, outgoing: Arc<Pipe>, chunk_bytes: usize) -> Self {
        Self(Endpoint::new(incoming, outgoing, chunk_bytes))
    }
}

impl futures::io::AsyncRead for EngineIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        self.0.poll_read(context, output)
    }
}

impl futures::io::AsyncWrite for EngineIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.0.poll_write(context, input)
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0.shutdown();
        Poll::Ready(Ok(()))
    }
}

pub(crate) struct WorkerIo(Endpoint);

impl WorkerIo {
    fn new(incoming: Arc<Pipe>, outgoing: Arc<Pipe>, chunk_bytes: usize) -> Self {
        Self(Endpoint::new(incoming, outgoing, chunk_bytes))
    }
}

impl AsyncRead for WorkerIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let unfilled = output.initialize_unfilled();
        match self.0.poll_read(context, unfilled) {
            Poll::Ready(Ok(count)) => {
                output.advance(count);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for WorkerIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.0.poll_write(context, input)
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0.shutdown();
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_bridge_moves_both_directions_and_eof() {
        let (mut engine, mut worker) = pair(2, 4);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            futures::io::AsyncWriteExt::write_all(&mut engine, b"client")
                .await
                .unwrap();
            let mut input = [0; 6];
            tokio::io::AsyncReadExt::read_exact(&mut worker, &mut input)
                .await
                .unwrap();
            assert_eq!(&input, b"client");
            tokio::io::AsyncWriteExt::write_all(&mut worker, b"server")
                .await
                .unwrap();
            let mut output = [0; 6];
            futures::io::AsyncReadExt::read_exact(&mut engine, &mut output)
                .await
                .unwrap();
            assert_eq!(&output, b"server");
            tokio::io::AsyncWriteExt::shutdown(&mut worker)
                .await
                .unwrap();
            assert_eq!(
                futures::io::AsyncReadExt::read(&mut engine, &mut output)
                    .await
                    .unwrap(),
                0
            );
        });
    }
}
