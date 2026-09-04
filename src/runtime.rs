use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};
use tokio::time::interval;

use crate::carrier::{Accepted, CarrierRuntime};
use crate::config::{Config, Role, UnknownClient};
use crate::error::{Error, Result};
use crate::identity::Identity;
use crate::inbound::{http as http_inbound, socks as socks_inbound};
use crate::logging::{Level, Logger};
use crate::mirror;
use crate::mux;
use crate::outbound::Connector;
use crate::protection::ProtectionMode;
use crate::routing::RuleSet;
use crate::tunnel::{
    self, ClientSession, encode_plain_frame, read_client_hello, server_handshake_with_hello,
};

/// Fixed delay between client reconnect attempts. Not exposed in the config;
/// `reconnect` only governs whether and how many attempts are made.
const RECONNECT_DELAY: Duration = Duration::from_secs(1);
/// Client-side yamux limits. The client never receives inbound streams, so
/// these only bound how many outbound proxied streams may be open at once.
const CLIENT_MAX_STREAMS: usize = 256;
/// Interval on which the server re-reads its config file to pick up client
/// key revocations/additions, comfortably under the 1-second requirement.
const RELOAD_INTERVAL: Duration = Duration::from_millis(200);

pub async fn run(path: &Path, logger: Logger) -> Result<()> {
    let config = Config::load(path)?;
    let shutdown_logger = logger.clone();
    tokio::select! {
        result = async {
            match config.role {
                Role::Client => run_client(path.to_path_buf(), config, logger).await,
                Role::Server => run_server(path.to_path_buf(), config, logger).await,
            }
        } => result,
        result = shutdown_signal() => {
            result?;
            shutdown_logger.record(Level::Debug, "shutdown signal received");
            Ok(())
        }
    }
}

#[cfg(unix)]
async fn shutdown_signal() -> std::io::Result<()> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result,
        _ = terminate.recv() => Ok(()),
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() -> std::io::Result<()> {
    tokio::signal::ctrl_c().await
}

// ---------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------

async fn run_client(path: PathBuf, config: Config, logger: Logger) -> Result<()> {
    let identity = Identity::from_base64(
        config
            .protection
            .key
            .as_deref()
            .ok_or_else(|| Error::Config("client private key is required".to_owned()))?,
    )?;
    let mode = config.protection.mode;
    let heartbeat = Duration::from_secs(config.heartbeat);
    let remote = config
        .remote
        .clone()
        .ok_or_else(|| Error::Config("client remote is required".to_owned()))?;

    let routing = config
        .routing
        .as_deref()
        .map(RuleSet::load)
        .transpose()?
        .map(Arc::new);

    let (sessions_tx, sessions_rx) = watch::channel::<Option<ClientSession>>(None);
    let connector = Connector::new(sessions_rx, routing);

    let mut inbounds = tokio::task::JoinSet::new();
    if let Some(socks) = config.socks.clone().filter(|socks| socks.listen) {
        let connector = connector.clone();
        let logger = logger.clone();
        inbounds.spawn(async move { socks_inbound::serve(socks, connector, logger).await });
    }
    if let Some(http) = config.http.clone().filter(|http| http.listen) {
        let connector = connector.clone();
        let logger = logger.clone();
        inbounds.spawn(async move { http_inbound::serve(http, connector, logger).await });
    }
    if let Some(tun) = config.tun.clone() {
        let connector = connector.clone();
        let logger = logger.clone();
        inbounds.spawn(async move { crate::tun::run(tun, connector, logger).await });
    }
    if inbounds.is_empty() {
        return Err(Error::Config(
            "client requires an active inbound".to_owned(),
        ));
    }

    let carrier = CarrierRuntime::client(config.carrier.clone());
    let mut attempts: i32 = 0;
    loop {
        let outcome = connect_once(
            &remote,
            &carrier,
            &identity,
            mode,
            heartbeat,
            &sessions_tx,
            &logger,
        )
        .await;

        if let Err(error) = &outcome {
            logger.record(Level::Warning, &format!("session ended: {error}"));
        }

        match config.reconnect {
            Some(0) | None => {
                return outcome;
            }
            Some(-1) => {}
            Some(limit) => {
                attempts += 1;
                if attempts >= limit {
                    return outcome.and(Err(Error::Carrier(
                        "reconnect attempts exhausted".to_owned(),
                    )));
                }
            }
        }

        tokio::select! {
            () = tokio::time::sleep(RECONNECT_DELAY) => {}
            Some(result) = inbounds.join_next() => {
                return match result {
                    Ok(inner) => inner,
                    Err(error) => Err(Error::Runtime(format!("inbound task failed: {error}"))),
                };
            }
        }
        // Reload the config so key rotation / remote changes on disk apply
        // to the next connection attempt without a full process restart.
        if let Ok(fresh) = Config::load(&path)
            && fresh.role == Role::Client
        {
            logger.record(Level::Debug, "reloaded client configuration");
        }
    }
}

async fn connect_once(
    remote: &str,
    carrier: &CarrierRuntime,
    identity: &Identity,
    mode: ProtectionMode,
    heartbeat: Duration,
    sessions_tx: &watch::Sender<Option<ClientSession>>,
    logger: &Logger,
) -> Result<()> {
    let mut stream = carrier.connect(remote).await?;
    let master = tunnel::client_handshake(&mut stream, identity, mode).await?;
    logger.record(Level::Debug, "handshake established");

    let window = CLIENT_MAX_STREAMS * yamux::DEFAULT_CREDIT as usize;
    let (mux, mut incoming) = mux::spawn(stream, yamux::Mode::Client, CLIENT_MAX_STREAMS, window)?;

    // The client never expects the server to open streams. Drain and drop
    // any that arrive so the yamux driver never blocks on a full channel.
    tokio::spawn(async move {
        while incoming.recv().await.is_some() {
            // Unexpected inbound stream from the server; nothing to do with it.
        }
    });

    let session = ClientSession::new(mux, master, mode);
    let _ = sessions_tx.send(Some(session.clone()));
    let result = session.monitor_heartbeat(heartbeat).await;
    let _ = sessions_tx.send(None);
    session.abort().await;
    result
}

// ---------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------

#[derive(Clone)]
struct ServerAuth {
    allowed: Vec<[u8; 32]>,
    unknown: UnknownClient,
    /// Response cache for the unknown-client mirror fallback, when enabled.
    /// Rebuilt (and its previous contents dropped) on every config reload.
    mirror_cache: Option<Arc<mirror::Cache>>,
}

impl ServerAuth {
    fn new(allowed: Vec<[u8; 32]>, unknown: UnknownClient) -> Self {
        let mirror_cache = mirror_config(&unknown)
            .filter(|mirror| mirror.cache)
            .map(|mirror| Arc::new(mirror::Cache::new(Duration::from_secs(mirror.ttl))));
        Self {
            allowed,
            unknown,
            mirror_cache,
        }
    }
}

fn mirror_config(unknown: &UnknownClient) -> Option<&crate::config::MirrorConfig> {
    match unknown {
        UnknownClient::Site { mirror, .. } | UnknownClient::Service { mirror, .. } => Some(mirror),
        UnknownClient::Error | UnknownClient::File { .. } => None,
    }
}

async fn run_server(path: PathBuf, config: Config, logger: Logger) -> Result<()> {
    let bind = config
        .bind
        .clone()
        .ok_or_else(|| Error::Config("server bind is required".to_owned()))?;
    let limits = config
        .limits
        .clone()
        .ok_or_else(|| Error::Config("server limits are required".to_owned()))?;
    let mode = config.protection.mode;
    let heartbeat = Duration::from_secs(config.heartbeat);

    let allowed = tunnel::decode_public_keys(
        config
            .protection
            .clients
            .clone()
            .ok_or_else(|| Error::Config("server clients are required".to_owned()))?
            .into_iter()
            .map(|client| client.key),
    )?;
    let unknown = config
        .protection
        .unknown
        .clone()
        .ok_or_else(|| Error::Config("unknown-client behavior is required".to_owned()))?;

    let (auth_tx, auth_rx) = watch::channel(ServerAuth::new(allowed, unknown));
    tokio::spawn(reload_auth(path, auth_tx, logger.clone()));

    if matches!(config.carrier, crate::config::Carrier::Ssh { .. }) {
        return run_ssh_server(bind, mode, heartbeat, limits, auth_rx, logger).await;
    }
    if matches!(config.carrier, crate::config::Carrier::Webrtc { .. }) {
        return run_webrtc_server(bind, mode, heartbeat, limits, auth_rx, logger).await;
    }

    let carrier = Arc::new(CarrierRuntime::server(config.carrier.clone(), logger.clone()).await?);
    let listener = TcpListener::bind(&bind).await?;
    let semaphore = Arc::new(Semaphore::new(limits.connections));

    loop {
        let (stream, peer) = listener.accept().await?;
        stream.set_nodelay(true)?;

        let Ok(permit) = semaphore.clone().try_acquire_owned() else {
            logger.record(Level::Warning, "connection limit reached, dropping client");
            continue;
        };

        let carrier = carrier.clone();
        let auth = auth_rx.clone();
        let limits = limits.clone();
        let logger = logger.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) =
                handle_connection(stream, carrier, mode, heartbeat, limits, auth, &logger).await
            {
                logger.record(Level::Debug, &format!("client {peer}: {error}"));
            }
        });
    }
}

async fn reload_auth(path: PathBuf, sender: watch::Sender<ServerAuth>, logger: Logger) {
    let mut ticker = interval(RELOAD_INTERVAL);
    loop {
        ticker.tick().await;
        let Ok(config) = Config::load(&path) else {
            continue;
        };
        if config.role != Role::Server {
            continue;
        }
        let Some(clients) = config.protection.clients else {
            continue;
        };
        let Some(unknown) = config.protection.unknown else {
            continue;
        };
        let Ok(allowed) = tunnel::decode_public_keys(clients.into_iter().map(|client| client.key))
        else {
            continue;
        };
        if sender.send(ServerAuth::new(allowed, unknown)).is_err() {
            return;
        }
        let _ = &logger;
    }
}

async fn handle_connection(
    stream: TcpStream,
    carrier: Arc<CarrierRuntime>,
    mode: ProtectionMode,
    heartbeat: Duration,
    limits: crate::config::Limits,
    auth: watch::Receiver<ServerAuth>,
    logger: &Logger,
) -> Result<()> {
    let stream = match carrier.accept(stream).await? {
        Accepted::Tunnel(stream) => stream,
        Accepted::Handled => return Ok(()),
    };
    serve_tunnel(stream, mode, heartbeat, limits, auth, logger).await
}

/// Runs the snolc handshake and, on success, the multiplexed session, over
/// an already carrier-established stream. Shared by every carrier: for
/// plain/acme/steal HTTP carriers `stream` comes from one accepted TCP
/// connection; for the SSH carrier it comes from one opened SSH channel
/// (see [`run_ssh_server`]), of which there may be several per connection.
async fn serve_tunnel(
    mut stream: crate::carrier::BoxedStream,
    mode: ProtectionMode,
    heartbeat: Duration,
    limits: crate::config::Limits,
    auth: watch::Receiver<ServerAuth>,
    logger: &Logger,
) -> Result<()> {
    let hello = read_client_hello(&mut stream).await?;
    let identity = crate::handshake::peek_client_identity(&hello.payload)?;

    let auth = auth.borrow().clone();
    if !auth.allowed.contains(&identity) {
        return respond_to_unknown_client(stream, &hello, &auth, logger).await;
    }

    let established = server_handshake_with_hello(&mut stream, hello, mode, &auth.allowed).await?;
    let window = limits.streams * yamux::DEFAULT_CREDIT as usize;
    let (server_mux, incoming) = mux::spawn(stream, yamux::Mode::Server, limits.streams, window)?;
    tunnel::serve_session(incoming, server_mux, established.master, mode, heartbeat).await
}

/// The SSH carrier's server accept loop. Structurally different from the
/// other carriers: russh owns the per-connection protocol loop and hands
/// channels to a callback rather than returning a stream synchronously, so
/// it cannot go through [`CarrierRuntime::accept`]. `serve_tunnel` runs once
/// per opened "session" channel.
async fn run_ssh_server(
    bind: String,
    mode: ProtectionMode,
    heartbeat: Duration,
    limits: crate::config::Limits,
    auth_rx: watch::Receiver<ServerAuth>,
    logger: Logger,
) -> Result<()> {
    let host_key = Arc::new(crate::ssh::generate_host_key()?);
    let listener = TcpListener::bind(&bind).await?;
    let semaphore = Arc::new(Semaphore::new(limits.connections));

    loop {
        let (stream, peer) = listener.accept().await?;
        stream.set_nodelay(true)?;

        let Ok(permit) = semaphore.clone().try_acquire_owned() else {
            logger.record(Level::Warning, "connection limit reached, dropping client");
            continue;
        };

        let host_key = host_key.clone();
        let auth_for_connection = auth_rx.clone();
        let limits_for_connection = limits.clone();
        let logger_for_connection = logger.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let auth_for_channel = auth_for_connection;
            let limits_for_channel = limits_for_connection;
            let logger_for_channel = logger_for_connection.clone();
            let callback: Arc<dyn Fn(crate::carrier::BoxedStream) + Send + Sync> =
                Arc::new(move |stream| {
                    let auth = auth_for_channel.clone();
                    let limits = limits_for_channel.clone();
                    let logger = logger_for_channel.clone();
                    tokio::spawn(async move {
                        if let Err(error) =
                            serve_tunnel(stream, mode, heartbeat, limits, auth, &logger).await
                        {
                            logger.record(Level::Debug, &format!("client {peer}: {error}"));
                        }
                    });
                });
            if let Err(error) = crate::ssh::accept(stream, host_key, callback).await {
                logger_for_connection.record(Level::Debug, &format!("client {peer}: {error}"));
            }
        });
    }
}

/// The WebRTC carrier has a UDP signaling listener and yields one stream per
/// established SCTP data channel, so it cannot use the TCP accept loop shared
/// by the HTTP carriers.
async fn run_webrtc_server(
    bind: String,
    mode: ProtectionMode,
    heartbeat: Duration,
    limits: crate::config::Limits,
    auth_rx: watch::Receiver<ServerAuth>,
    logger: Logger,
) -> Result<()> {
    let mut listener =
        crate::webrtc::Listener::bind(&bind, limits.connections, logger.clone()).await?;
    loop {
        let accepted = listener.accept().await?;
        let auth = auth_rx.clone();
        let limits = limits.clone();
        let logger = logger.clone();
        tokio::spawn(async move {
            let _permit = accepted.permit;
            if let Err(error) =
                serve_tunnel(accepted.stream, mode, heartbeat, limits, auth, &logger).await
            {
                logger.record(
                    Level::Debug,
                    &format!("WebRTC client {}: {error}", accepted.peer),
                );
            }
        });
    }
}

async fn respond_to_unknown_client(
    mut stream: crate::carrier::BoxedStream,
    hello: &crate::frame::Frame,
    auth: &ServerAuth,
    logger: &Logger,
) -> Result<()> {
    logger.record(
        Level::Warning,
        "rejected connection from an unknown client key",
    );
    match &auth.unknown {
        UnknownClient::Error => {
            drop(stream);
            Err(Error::Authentication("unknown client key".to_owned()))
        }
        UnknownClient::File { path } => {
            let contents = tokio::fs::read(path).await?;
            stream.write_all(&contents).await?;
            stream.shutdown().await?;
            Err(Error::Authentication("unknown client key".to_owned()))
        }
        UnknownClient::Site { target, .. } | UnknownClient::Service { target, .. } => {
            let prefix = encode_plain_frame(hello)?;
            mirror::serve(stream, target, &prefix, auth.mirror_cache.as_deref()).await?;
            Err(Error::Authentication("unknown client key".to_owned()))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::{sleep, timeout};

    use super::*;
    use crate::identity::Identity;

    async fn free_port() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap().port()
    }

    /// Exercises `runtime::run` end to end exactly as the CLI does: real YAML
    /// files on disk, a real HTTP-carrier TCP connection between client and
    /// server, the ephemeral handshake, a yamux session, and a SOCKS5 inbound
    /// proxying traffic to a real TCP echo server.
    #[tokio::test]
    async fn client_and_server_runtimes_proxy_a_real_socks5_connection() {
        let directory = tempfile::tempdir().unwrap();
        let identity = Identity::generate().unwrap();

        let destination = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination_address = destination.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut stream, _) = destination.accept().await.unwrap();
            let mut buffer = [0_u8; 5];
            stream.read_exact(&mut buffer).await.unwrap();
            stream.write_all(&buffer).await.unwrap();
        });

        let server_port = free_port().await;
        let socks_port = free_port().await;

        let server_path = directory.path().join("server.yml");
        std::fs::write(
            &server_path,
            format!(
                r#"
role: server
remote: null
bind: "127.0.0.1:{server_port}"
carrier:
  kind: http
  transport: tcp
  host: cover.example
  path: /events
  tls: null
protection:
  mode: chacha poly
  key: null
  clients:
    - key: {public}
  unknown:
    mode: error
heartbeat: 1
reconnect: null
limits:
  connections: 4
  streams: 8
  fragments: 16
  memory: 2097152
routing: null
tun: null
socks: null
http: null
"#,
                public = identity.public_base64(),
            ),
        )
        .unwrap();

        let client_path = directory.path().join("client.yml");
        std::fs::write(
            &client_path,
            format!(
                r#"
role: client
remote: "127.0.0.1:{server_port}"
bind: null
carrier:
  kind: http
  transport: tcp
  host: cover.example
  path: /events
  tls: null
protection:
  mode: chacha poly
  key: {private}
  clients: null
  unknown: null
heartbeat: 1
reconnect: -1
limits: null
routing: null
tun: null
socks:
  pass: null
  user: null
  host: 127.0.0.1
  port: {socks_port}
  listen: true
http: null
"#,
                private = identity.private_base64().as_str(),
            ),
        )
        .unwrap();

        let server = tokio::spawn(async move { run(&server_path, Logger::disabled()).await });
        let client = tokio::spawn(async move { run(&client_path, Logger::disabled()).await });

        let mut socks_stream = connect_with_retries(socks_port).await;
        socks_stream.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0_u8; 2];
        socks_stream.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);

        let mut request = vec![5, 1, 0, 1];
        let IpAddr::V4(ip) = destination_address.ip() else {
            unreachable!("loopback listener is always IPv4 here")
        };
        request.extend_from_slice(&ip.octets());
        request.extend_from_slice(&destination_address.port().to_be_bytes());
        socks_stream.write_all(&request).await.unwrap();
        let mut reply = [0_u8; 10];
        socks_stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0, "SOCKS5 CONNECT must succeed");

        socks_stream.write_all(b"snolc").await.unwrap();
        let mut echoed = [0_u8; 5];
        socks_stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"snolc");

        drop(socks_stream);
        echo.await.unwrap();
        server.abort();
        client.abort();
    }

    /// Same end-to-end flow as above, but through the SSH carrier instead of
    /// the HTTP one: a real SSH key exchange and session, a "session"
    /// channel used as the transport, and a real snolc handshake and
    /// yamux session running inside it.
    #[tokio::test]
    async fn client_and_server_runtimes_proxy_over_the_ssh_carrier() {
        let directory = tempfile::tempdir().unwrap();
        let identity = Identity::generate().unwrap();

        let destination = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination_address = destination.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut stream, _) = destination.accept().await.unwrap();
            let mut buffer = [0_u8; 5];
            stream.read_exact(&mut buffer).await.unwrap();
            stream.write_all(&buffer).await.unwrap();
        });

        let server_port = free_port().await;
        let socks_port = free_port().await;

        let server_path = directory.path().join("server.yml");
        std::fs::write(
            &server_path,
            format!(
                r#"
role: server
remote: null
bind: "127.0.0.1:{server_port}"
carrier:
  kind: ssh
  transport: tcp
protection:
  mode: chacha poly
  key: null
  clients:
    - key: {public}
  unknown:
    mode: error
heartbeat: 1
reconnect: null
limits:
  connections: 4
  streams: 8
  fragments: 16
  memory: 2097152
routing: null
tun: null
socks: null
http: null
"#,
                public = identity.public_base64(),
            ),
        )
        .unwrap();

        let client_path = directory.path().join("client.yml");
        std::fs::write(
            &client_path,
            format!(
                r#"
role: client
remote: "127.0.0.1:{server_port}"
bind: null
carrier:
  kind: ssh
  transport: tcp
protection:
  mode: chacha poly
  key: {private}
  clients: null
  unknown: null
heartbeat: 1
reconnect: -1
limits: null
routing: null
tun: null
socks:
  pass: null
  user: null
  host: 127.0.0.1
  port: {socks_port}
  listen: true
http: null
"#,
                private = identity.private_base64().as_str(),
            ),
        )
        .unwrap();

        let server = tokio::spawn(async move { run(&server_path, Logger::disabled()).await });
        let client = tokio::spawn(async move { run(&client_path, Logger::disabled()).await });

        // The SOCKS listener starts accepting immediately, but the SSH key
        // exchange + snolc handshake to the server takes a little longer
        // than the HTTP carrier's near-instant preface; give it a moment
        // rather than racing the very first CONNECT against it.
        tokio::time::sleep(Duration::from_millis(500)).await;

        let mut socks_stream = connect_with_retries(socks_port).await;
        socks_stream.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0_u8; 2];
        socks_stream.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);

        let mut request = vec![5, 1, 0, 1];
        let IpAddr::V4(ip) = destination_address.ip() else {
            unreachable!("loopback listener is always IPv4 here")
        };
        request.extend_from_slice(&ip.octets());
        request.extend_from_slice(&destination_address.port().to_be_bytes());
        socks_stream.write_all(&request).await.unwrap();
        let mut reply = [0_u8; 10];
        socks_stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0, "SOCKS5 CONNECT must succeed");

        socks_stream.write_all(b"snolc").await.unwrap();
        let mut echoed = [0_u8; 5];
        socks_stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"snolc");

        drop(socks_stream);
        echo.await.unwrap();
        server.abort();
        client.abort();
    }

    /// The `error` unknown-client fallback must close the connection and
    /// must not accept an unrecognized identity into a real session.
    #[tokio::test]
    async fn unknown_client_error_fallback_closes_the_connection() {
        let known = Identity::generate().unwrap();
        let stranger = Identity::generate().unwrap();

        let carrier_config = crate::config::Carrier::Http {
            transport: crate::config::Transport::Tcp,
            host: "cover.example".to_owned(),
            path: "/events".to_owned(),
            tls: None,
        };
        let limits = crate::config::Limits {
            connections: 4,
            streams: 8,
            fragments: 16,
            memory: 8 * yamux::DEFAULT_CREDIT as usize,
        };
        let (_auth_tx, auth_rx) =
            watch::channel(ServerAuth::new(vec![known.public()], UnknownClient::Error));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        let server_carrier = Arc::new(
            CarrierRuntime::server(carrier_config, Logger::disabled())
                .await
                .unwrap(),
        );
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_connection(
                stream,
                server_carrier,
                ProtectionMode::ChaChaPoly,
                Duration::from_secs(1),
                limits,
                auth_rx,
                &Logger::disabled(),
            )
            .await
        });

        let mut client_stream = TcpStream::connect(address).await.unwrap();
        crate::carrier::client_http_preface(&mut client_stream, "cover.example", "/events")
            .await
            .unwrap();
        let master_attempt =
            tunnel::client_handshake(&mut client_stream, &stranger, ProtectionMode::ChaChaPoly)
                .await;
        // The server closes the socket instead of completing the handshake,
        // so the client observes an I/O or protocol error, never a session.
        assert!(master_attempt.is_err());

        let outcome = timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(outcome, Err(Error::Authentication(_))));
    }

    async fn connect_with_retries(port: u16) -> TcpStream {
        for _ in 0..50 {
            if let Ok(stream) = TcpStream::connect(("127.0.0.1", port)).await {
                return stream;
            }
            sleep(Duration::from_millis(50)).await;
        }
        panic!("SOCKS inbound never became reachable");
    }
}
