use std::collections::VecDeque;
use std::pin::Pin;
use std::task::Poll;

use futures::future::poll_fn;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot, watch};
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use yamux::{Config, Connection, Mode};

use crate::error::{Error, Result};

const COMMAND_CAPACITY: usize = 32;

pub struct MuxStream {
    pub id: u64,
    pub io: Compat<yamux::Stream>,
}

#[derive(Clone)]
pub struct MuxHandle {
    commands: mpsc::Sender<Command>,
    state: watch::Receiver<State>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum State {
    Running,
    Closed,
}

enum Command {
    Open(oneshot::Sender<Result<MuxStream>>),
    Abort,
}

enum Event {
    Inbound(yamux::Stream),
    Closed,
    Abort,
}

pub fn spawn<T>(
    io: T,
    mode: Mode,
    max_streams: usize,
    max_window: usize,
) -> Result<(MuxHandle, mpsc::Receiver<MuxStream>)>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if max_streams == 0 {
        return Err(Error::Config(
            "yamux stream limit cannot be zero".to_owned(),
        ));
    }
    let minimum_window = max_streams
        .checked_mul(yamux::DEFAULT_CREDIT as usize)
        .ok_or_else(|| Error::Config("yamux receive window overflow".to_owned()))?;
    if max_window < minimum_window {
        return Err(Error::Config(
            "yamux receive window is below the per-stream minimum".to_owned(),
        ));
    }

    let mut config = Config::default();
    config.set_max_num_streams(max_streams);
    config.set_max_connection_receive_window(Some(max_window));
    config.set_read_after_close(false);
    let connection = Connection::new(io.compat(), config, mode);
    let (commands_tx, commands_rx) = mpsc::channel(COMMAND_CAPACITY);
    let (inbound_tx, inbound_rx) = mpsc::channel(max_streams.min(1024));
    let (state_tx, state_rx) = watch::channel(State::Running);
    tokio::spawn(drive(connection, commands_rx, inbound_tx, state_tx));

    Ok((
        MuxHandle {
            commands: commands_tx,
            state: state_rx,
        },
        inbound_rx,
    ))
}

impl MuxHandle {
    pub async fn open(&self) -> Result<MuxStream> {
        if *self.state.borrow() == State::Closed {
            return Err(Error::Carrier(
                "multiplexed connection is closed".to_owned(),
            ));
        }
        let (reply, response) = oneshot::channel();
        self.commands
            .send(Command::Open(reply))
            .await
            .map_err(|_| Error::Carrier("multiplexed connection is closed".to_owned()))?;
        response
            .await
            .map_err(|_| Error::Carrier("multiplexed connection is closed".to_owned()))?
    }

    pub async fn abort(&self) {
        let _ = self.commands.send(Command::Abort).await;
    }

    pub async fn wait_closed(&self) {
        let mut state = self.state.clone();
        while *state.borrow_and_update() != State::Closed {
            if state.changed().await.is_err() {
                break;
            }
        }
    }
}

async fn drive<T>(
    mut connection: Connection<Compat<T>>,
    mut commands: mpsc::Receiver<Command>,
    inbound: mpsc::Sender<MuxStream>,
    state: watch::Sender<State>,
) where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut opens = VecDeque::new();
    loop {
        let event = poll_fn(|context| {
            loop {
                match Pin::new(&mut commands).poll_recv(context) {
                    Poll::Ready(Some(Command::Open(reply))) => opens.push_back(reply),
                    Poll::Ready(Some(Command::Abort)) => return Poll::Ready(Event::Abort),
                    Poll::Ready(None) | Poll::Pending => break,
                }
            }

            if !opens.is_empty() {
                match connection.poll_new_outbound(context) {
                    Poll::Ready(Ok(stream)) => {
                        let reply = opens.pop_front().expect("pending yamux open");
                        let id = stream.id().val() as u64;
                        let _ = reply.send(Ok(MuxStream {
                            id,
                            io: stream.compat(),
                        }));
                    }
                    Poll::Ready(Err(error)) => {
                        let message = error.to_string();
                        for reply in opens.drain(..) {
                            let _ = reply.send(Err(Error::Carrier(message.clone())));
                        }
                        return Poll::Ready(Event::Closed);
                    }
                    Poll::Pending => {}
                }
            }

            match connection.poll_next_inbound(context) {
                Poll::Ready(Some(Ok(stream))) => Poll::Ready(Event::Inbound(stream)),
                Poll::Ready(Some(Err(_))) | Poll::Ready(None) => Poll::Ready(Event::Closed),
                Poll::Pending => Poll::Pending,
            }
        })
        .await;

        match event {
            Event::Inbound(stream) => {
                let item = MuxStream {
                    id: stream.id().val() as u64,
                    io: stream.compat(),
                };
                if inbound.send(item).await.is_err() {
                    break;
                }
            }
            Event::Closed | Event::Abort => break,
        }
    }

    for reply in opens {
        let _ = reply.send(Err(Error::Carrier(
            "multiplexed connection is closed".to_owned(),
        )));
    }
    let _ = state.send(State::Closed);
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[tokio::test]
    async fn opens_multiple_independent_streams_on_one_connection() {
        let (left, right) = tokio::io::duplex(64 * 1024);
        let window = 8 * yamux::DEFAULT_CREDIT as usize;
        let (client, _) = spawn(left, Mode::Client, 8, window).unwrap();
        let (_server, mut incoming) = spawn(right, Mode::Server, 8, window).unwrap();

        let mut first = client.open().await.unwrap();
        let mut second = client.open().await.unwrap();
        first.io.write_all(b"first").await.unwrap();
        second.io.write_all(b"second").await.unwrap();

        let mut server_first = incoming.recv().await.unwrap();
        let mut server_second = incoming.recv().await.unwrap();
        let mut first_data = [0_u8; 5];
        let mut second_data = [0_u8; 6];
        server_first.io.read_exact(&mut first_data).await.unwrap();
        server_second.io.read_exact(&mut second_data).await.unwrap();
        assert_eq!(&first_data, b"first");
        assert_eq!(&second_data, b"second");
        assert_ne!(first.id, second.id);
    }

    #[tokio::test]
    async fn abort_closes_all_new_stream_requests() {
        let (left, _right) = tokio::io::duplex(1024);
        let window = 2 * yamux::DEFAULT_CREDIT as usize;
        let (client, _) = spawn(left, Mode::Client, 2, window).unwrap();
        client.abort().await;
        client.wait_closed().await;
        assert!(client.open().await.is_err());
    }
}
