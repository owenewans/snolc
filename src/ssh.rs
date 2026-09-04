//! SSH carrier: the wire looks like a real SSH session (real key exchange,
//! real transport encryption, a real client opening a real "session"
//! channel) but authentication is pure camouflage -- the server accepts any
//! SSH public key, since the real per-client authentication is the snolc
//! ed25519 handshake carried inside the channel. The host key is generated
//! once at server startup and reused for the process lifetime, like a real
//! `sshd`'s host key, rather than changing on every connection (which would
//! itself be a giveaway to anyone paying attention).

use std::sync::Arc;

use russh::keys::{Algorithm, PrivateKey, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::server::{Auth, Msg as ServerMsg, Server as ServerFactory};
use russh::{Channel, ChannelId, client, server};
use tokio::net::TcpStream;

use crate::carrier::BoxedStream;
use crate::error::{Error, Result};

const USERNAME: &str = "snolc";

/// Connects to `remote`, over an already-established TCP stream, as an SSH
/// client: real key exchange, a throwaway ephemeral host-key-independent
/// client identity (rejected or accepted is irrelevant -- the server accepts
/// any key), and one opened "session" channel used as the transport for the
/// snolc protocol.
pub async fn connect(stream: TcpStream) -> Result<BoxedStream> {
    struct ClientHandler;
    impl client::Handler for ClientHandler {
        type Error = russh::Error;

        async fn check_server_key(
            &mut self,
            _server_public_key: &PublicKeyOrCertificate,
        ) -> std::result::Result<bool, Self::Error> {
            // The host key is not meaningful here: real authentication is
            // the snolc handshake carried inside the channel, not this
            // camouflage transport's identity.
            Ok(true)
        }
    }

    let config = Arc::new(client::Config {
        nodelay: true,
        ..Default::default()
    });
    let mut session = client::connect_stream(config, stream, ClientHandler)
        .await
        .map_err(|error| Error::Carrier(format!("SSH connection failed: {error}")))?;

    let identity = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
        .map_err(|error| Error::Carrier(format!("cannot generate SSH client key: {error}")))?;
    let hash_algorithm = session
        .best_supported_rsa_hash()
        .await
        .map_err(|error| Error::Carrier(format!("SSH negotiation failed: {error}")))?
        .flatten();
    let result = session
        .authenticate_publickey(
            USERNAME,
            PrivateKeyWithHashAlg::new(Arc::new(identity), hash_algorithm),
        )
        .await
        .map_err(|error| Error::Carrier(format!("SSH authentication failed: {error}")))?;
    if !result.success() {
        return Err(Error::Carrier("SSH authentication was rejected".to_owned()));
    }

    let channel = session
        .channel_open_session()
        .await
        .map_err(|error| Error::Carrier(format!("SSH channel open failed: {error}")))?;
    Ok(Box::new(channel.into_stream()))
}

/// Runs one accepted TCP connection as an SSH server session. `on_channel`
/// is invoked (and expected to spawn its own task) for every "session"
/// channel the client opens; the snolc protocol runs entirely inside that
/// channel.
pub async fn accept(
    stream: TcpStream,
    host_key: Arc<PrivateKey>,
    on_channel: Arc<dyn Fn(BoxedStream) + Send + Sync>,
) -> Result<()> {
    let config = Arc::new(server::Config {
        keys: vec![(*host_key).clone()],
        ..Default::default()
    });
    let handler = Handler { on_channel };
    let running = server::run_stream(config, stream, handler)
        .await
        .map_err(|error| Error::Carrier(format!("SSH session failed: {error}")))?;
    running
        .await
        .map_err(|error| Error::Carrier(format!("SSH session failed: {error}")))?;
    Ok(())
}

#[derive(Clone)]
struct Handler {
    on_channel: Arc<dyn Fn(BoxedStream) + Send + Sync>,
}

impl ServerFactory for Handler {
    type Handler = Self;

    fn new_client(&mut self, _peer: Option<std::net::SocketAddr>) -> Self {
        self.clone()
    }
}

impl server::Handler for Handler {
    type Error = russh::Error;

    async fn channel_open_session(
        &mut self,
        channel: Channel<ServerMsg>,
        reply: server::ChannelOpenHandle,
        _session: &mut server::Session,
    ) -> std::result::Result<(), Self::Error> {
        reply.accept().await;
        (self.on_channel)(Box::new(channel.into_stream()));
        Ok(())
    }

    async fn auth_publickey(
        &mut self,
        _user: &str,
        _key: &russh::keys::PublicKey,
    ) -> std::result::Result<Auth, Self::Error> {
        // Camouflage-only: the real per-client check is the snolc handshake
        // carried inside the channel, not this transport-level identity.
        Ok(Auth::Accept)
    }

    async fn data(
        &mut self,
        _channel: ChannelId,
        _data: &[u8],
        _session: &mut server::Session,
    ) -> std::result::Result<(), Self::Error> {
        // Channel data is consumed through the ChannelStream handed to
        // `on_channel`, not through this callback.
        Ok(())
    }
}

/// Generates the process-lifetime SSH host key for the server.
pub fn generate_host_key() -> Result<PrivateKey> {
    PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
        .map_err(|error| Error::Carrier(format!("cannot generate SSH host key: {error}")))
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    use super::*;

    #[tokio::test]
    async fn client_opens_a_real_ssh_session_and_exchanges_data_over_the_channel() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let host_key = Arc::new(generate_host_key().unwrap());

        let (channel_tx, channel_rx) = oneshot::channel();
        let channel_tx = std::sync::Mutex::new(Some(channel_tx));
        let callback: Arc<dyn Fn(BoxedStream) + Send + Sync> = Arc::new(move |stream| {
            if let Some(sender) = channel_tx.lock().unwrap().take() {
                let _ = sender.send(stream);
            }
        });

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            accept(stream, host_key, callback).await
        });

        let client_stream = TcpStream::connect(address).await.unwrap();
        let mut client_channel = connect(client_stream).await.unwrap();

        let mut server_channel = channel_rx.await.unwrap();
        client_channel.write_all(b"snolc-over-ssh").await.unwrap();
        let mut received = [0_u8; 14];
        server_channel.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"snolc-over-ssh");

        server_channel.write_all(b"pong").await.unwrap();
        let mut reply = [0_u8; 4];
        client_channel.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"pong");

        drop(client_channel);
        drop(server_channel);
        // The server task ends once the underlying SSH connection closes.
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), server).await;
    }
}
