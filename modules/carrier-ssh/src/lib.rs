#![deny(unsafe_op_in_unsafe_fn)]

mod bridge;

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};
use std::task::{Context, Poll, Waker};
use std::thread::JoinHandle;
use std::time::Duration;

use futures::io::{AsyncRead, AsyncWrite};
use russh::client;
use russh::client::AuthResult;
use russh::keys::{Algorithm, PublicKey, PublicKeyOrCertificate};
use russh::server;
use russh::{Channel, ChannelId, ChannelMsg, Disconnect, MethodKind, MethodSet, Pty};
use serde::Deserialize;
use snolc_sdk::abi::{
    self, SnolByteIoV1, SnolBytes, SnolBytesMut, SnolCarrierApiV1, SnolIoResult,
    SnolModuleDescriptor, SnolWakeHandle,
};
use tokio::io::copy_bidirectional;
use tokio::task::JoinSet;

use bridge::{EngineIo, pair};

#[derive(Clone, Deserialize)]
#[serde(tag = "mode", rename_all = "lowercase", deny_unknown_fields)]
enum Options {
    Connect {
        endpoint_ip: SocketAddr,
        username: String,
        server_host_key: PathBuf,
        max_connections: usize,
        queue_chunks: usize,
        chunk_bytes: usize,
        inactivity_timeout_ms: u64,
        auth: ClientAuth,
    },
    Listen {
        endpoint_ip: SocketAddr,
        username: String,
        host_key: PathBuf,
        max_connections: usize,
        queue_chunks: usize,
        chunk_bytes: usize,
        inactivity_timeout_ms: u64,
        auth: ServerAuth,
    },
}

#[derive(Clone, Deserialize)]
#[serde(tag = "mode", rename_all = "kebab-case", deny_unknown_fields)]
enum ClientAuth {
    Password { password: String },
    Ed25519 { private_key: PathBuf },
}

#[derive(Clone, Deserialize)]
#[serde(tag = "mode", rename_all = "kebab-case", deny_unknown_fields)]
enum ServerAuth {
    Password { password: String },
    Ed25519 { public_key: PathBuf },
}

impl Options {
    fn resolve(&mut self, base: &Path) {
        match self {
            Self::Connect {
                server_host_key,
                auth,
                ..
            } => {
                resolve_path(server_host_key, base);
                if let ClientAuth::Ed25519 { private_key } = auth {
                    resolve_path(private_key, base);
                }
            }
            Self::Listen { host_key, auth, .. } => {
                resolve_path(host_key, base);
                if let ServerAuth::Ed25519 { public_key } = auth {
                    resolve_path(public_key, base);
                }
            }
        }
    }

    fn validate(&self) -> Result<(), String> {
        let (endpoint, username, max_connections, queue_chunks, chunk_bytes, timeout) = match self {
            Self::Connect {
                endpoint_ip,
                username,
                max_connections,
                queue_chunks,
                chunk_bytes,
                inactivity_timeout_ms,
                ..
            }
            | Self::Listen {
                endpoint_ip,
                username,
                max_connections,
                queue_chunks,
                chunk_bytes,
                inactivity_timeout_ms,
                ..
            } => (
                endpoint_ip,
                username,
                max_connections,
                queue_chunks,
                chunk_bytes,
                inactivity_timeout_ms,
            ),
        };
        if endpoint.port() == 0
            || username.is_empty()
            || username.len() > 64
            || *max_connections == 0
            || *queue_chunks == 0
            || *queue_chunks > 1024
            || *chunk_bytes == 0
            || *chunk_bytes > 65_536
            || *timeout == 0
        {
            return Err("SSH carrier options are inconsistent".into());
        }
        match self {
            Self::Connect {
                server_host_key,
                auth,
                ..
            } => {
                require_ed25519_public(server_host_key)?;
                match auth {
                    ClientAuth::Password { password } if !password.is_empty() => Ok(()),
                    ClientAuth::Ed25519 { private_key } => require_ed25519_private(private_key),
                    _ => Err("SSH client credential is invalid".into()),
                }
            }
            Self::Listen { host_key, auth, .. } => {
                require_ed25519_private(host_key)?;
                match auth {
                    ServerAuth::Password { password } if !password.is_empty() => Ok(()),
                    ServerAuth::Ed25519 { public_key } => require_ed25519_public(public_key),
                    _ => Err("SSH server credential is invalid".into()),
                }
            }
        }
    }

    fn max_connections(&self) -> usize {
        match self {
            Self::Connect {
                max_connections, ..
            }
            | Self::Listen {
                max_connections, ..
            } => *max_connections,
        }
    }

    fn is_client(&self) -> bool {
        matches!(self, Self::Connect { .. })
    }
}

fn resolve_path(path: &mut PathBuf, base: &Path) {
    if !path.is_absolute() {
        *path = base.join(&*path);
    }
}

fn require_ed25519_public(path: &Path) -> Result<(), String> {
    let key = russh::keys::load_public_key(path).map_err(|error| error.to_string())?;
    if key.algorithm() == Algorithm::Ed25519 {
        Ok(())
    } else {
        Err("SSH public key must be Ed25519".into())
    }
}

fn require_ed25519_private(path: &Path) -> Result<(), String> {
    let key = russh::keys::load_secret_key(path, None).map_err(|error| error.to_string())?;
    if key.algorithm() == Algorithm::Ed25519 {
        Ok(())
    } else {
        Err("SSH private key must be Ed25519".into())
    }
}

fn parse_options(config: &[u8], base: &[u8]) -> Result<Options, String> {
    let config = std::str::from_utf8(config).map_err(|_| "config is not UTF-8".to_owned())?;
    let base = std::str::from_utf8(base).map_err(|_| "base path is not UTF-8".to_owned())?;
    let mut options: Options = toml::from_str(config).map_err(|error| error.to_string())?;
    options.resolve(Path::new(base));
    options.validate()?;
    Ok(options)
}

struct InstanceState {
    commands: tokio::sync::mpsc::Sender<WorkerCommand>,
    events: Receiver<WorkerEvent>,
    worker: Option<JoinHandle<()>>,
    ready: VecDeque<EngineIo>,
    failures: usize,
    failed: bool,
    connect_pending: bool,
    client: bool,
    active_connections: usize,
    max_connections: usize,
    connect_wake: WakeSlot,
    accept_wake: WakeSlot,
}

enum WorkerCommand {
    Connect,
    Shutdown,
}

enum WorkerEvent {
    Ready(EngineIo),
    AttemptFailed,
    Fatal,
}

struct StreamState {
    owner: u64,
    io: EngineIo,
    read_wake: WakeSlot,
    write_wake: WakeSlot,
}

#[derive(Default)]
struct WakeSlot(Option<SnolWakeHandle>);

impl WakeSlot {
    fn replace(&mut self, wake: SnolWakeHandle) {
        self.clear();
        if let Some(retain) = wake.retain
            && unsafe { retain(wake.context) } == abi::STATUS_OK
        {
            self.0 = Some(wake);
        }
    }

    fn wake(&mut self) {
        if let Some(wake) = self.0.take() {
            if let Some(function) = wake.wake {
                unsafe { function(wake.context) };
            }
            if let Some(release) = wake.release {
                unsafe { release(wake.context) };
            }
        }
    }

    fn clear(&mut self) {
        if let Some(wake) = self.0.take()
            && let Some(release) = wake.release
        {
            unsafe { release(wake.context) };
        }
    }
}

impl Drop for WakeSlot {
    fn drop(&mut self) {
        self.clear();
    }
}

thread_local! {
    static INSTANCES: RefCell<HashMap<u64, InstanceState>> = RefCell::new(HashMap::new());
    static STREAMS: RefCell<HashMap<u64, StreamState>> = RefCell::new(HashMap::new());
}

static INSTANCE_NEXT: AtomicU64 = AtomicU64::new(1);
static STREAM_NEXT: AtomicU64 = AtomicU64::new(1);

unsafe extern "C" fn describe(output: SnolBytesMut, written: *mut usize) -> u32 {
    snolc_sdk::catch_status(|| unsafe {
        snolc_sdk::module::write_output(
            b"name = \"carrier-ssh\"\nroles = [\"client\", \"server\"]\nordered = true\nsubsystem = \"snolc\"\n",
            output,
            written,
        )
    })
}

unsafe extern "C" fn validate_config(
    config: SnolBytes,
    base: SnolBytes,
    error: SnolBytesMut,
    written: *mut usize,
) -> u32 {
    snolc_sdk::catch_status(|| {
        let config = match unsafe { snolc_sdk::module::input(config) } {
            Ok(config) => config,
            Err(status) => return status,
        };
        let base = match unsafe { snolc_sdk::module::input(base) } {
            Ok(base) => base,
            Err(status) => return status,
        };
        match parse_options(config, base) {
            Ok(_) => unsafe { snolc_sdk::module::write_output(&[], error, written) },
            Err(message) => {
                let _ =
                    unsafe { snolc_sdk::module::write_output(message.as_bytes(), error, written) };
                abi::STATUS_INVALID
            }
        }
    })
}

unsafe extern "C" fn create(
    config: SnolBytes,
    base: SnolBytes,
    _host: *const abi::SnolHostApiV1,
    output: *mut u64,
) -> u32 {
    snolc_sdk::catch_status(|| {
        let config = match unsafe { snolc_sdk::module::input(config) } {
            Ok(config) => config,
            Err(status) => return status,
        };
        let base = match unsafe { snolc_sdk::module::input(base) } {
            Ok(base) => base,
            Err(status) => return status,
        };
        let options = match parse_options(config, base) {
            Ok(options) => options,
            Err(_) => return abi::STATUS_INVALID,
        };
        let Some(output) = (unsafe { output.as_mut() }) else {
            return abi::STATUS_INVALID;
        };
        let capacity = options.max_connections().saturating_add(1);
        let (command_tx, command_rx) = tokio::sync::mpsc::channel(capacity);
        let (event_tx, event_rx) = mpsc::sync_channel(capacity);
        let worker_options = options.clone();
        let worker = match std::thread::Builder::new()
            .name("snolc-carrier-ssh".into())
            .spawn(move || worker_main(worker_options, command_rx, event_tx))
        {
            Ok(worker) => worker,
            Err(_) => return abi::STATUS_RESOURCE,
        };
        let handle = INSTANCE_NEXT.fetch_add(1, Ordering::Relaxed);
        if handle == 0 {
            let _ = command_tx.try_send(WorkerCommand::Shutdown);
            let _ = worker.join();
            return abi::STATUS_RESOURCE;
        }
        INSTANCES.with(|instances| {
            instances.borrow_mut().insert(
                handle,
                InstanceState {
                    commands: command_tx,
                    events: event_rx,
                    worker: Some(worker),
                    ready: VecDeque::new(),
                    failures: 0,
                    failed: false,
                    connect_pending: false,
                    client: options.is_client(),
                    active_connections: 0,
                    max_connections: options.max_connections(),
                    connect_wake: WakeSlot::default(),
                    accept_wake: WakeSlot::default(),
                },
            );
        });
        *output = handle;
        abi::STATUS_OK
    })
}

unsafe extern "C" fn poll(instance: u64, _wake: SnolWakeHandle) -> u32 {
    snolc_sdk::catch_status(|| {
        let found = INSTANCES.with(|instances| {
            let mut instances = instances.borrow_mut();
            let Some(state) = instances.get_mut(&instance) else {
                return false;
            };
            drain_events(state);
            state.connect_wake.wake();
            state.accept_wake.wake();
            true
        });
        if !found {
            return abi::STATUS_INVALID;
        }
        STREAMS.with(|streams| {
            for stream in streams.borrow_mut().values_mut() {
                if stream.owner == instance {
                    stream.read_wake.wake();
                    stream.write_wake.wake();
                }
            }
        });
        abi::STATUS_PENDING
    })
}

fn drain_events(state: &mut InstanceState) {
    loop {
        match state.events.try_recv() {
            Ok(WorkerEvent::Ready(stream)) => {
                state.connect_pending = false;
                state.ready.push_back(stream);
            }
            Ok(WorkerEvent::AttemptFailed) => {
                state.connect_pending = false;
                state.failures = state.failures.saturating_add(1);
            }
            Ok(WorkerEvent::Fatal) => state.failed = true,
            Err(TryRecvError::Empty) => break,
            Err(TryRecvError::Disconnected) => {
                state.failed = true;
                break;
            }
        }
    }
}

unsafe extern "C" fn control(
    instance: u64,
    _request: SnolBytes,
    _response: SnolBytesMut,
    written: *mut usize,
) -> u32 {
    snolc_sdk::catch_status(|| {
        let Some(written) = (unsafe { written.as_mut() }) else {
            return abi::STATUS_INVALID;
        };
        *written = 0;
        if INSTANCES.with(|instances| instances.borrow().contains_key(&instance)) {
            abi::STATUS_UNSUPPORTED
        } else {
            abi::STATUS_INVALID
        }
    })
}

unsafe extern "C" fn shutdown(instance: u64) -> u32 {
    snolc_sdk::catch_status(|| {
        INSTANCES.with(|instances| {
            let instances = instances.borrow();
            let Some(state) = instances.get(&instance) else {
                return abi::STATUS_INVALID;
            };
            match state.commands.try_send(WorkerCommand::Shutdown) {
                Ok(()) | Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => abi::STATUS_OK,
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => abi::STATUS_RESOURCE,
            }
        })
    })
}

unsafe extern "C" fn destroy(instance: u64) {
    let _ = std::panic::catch_unwind(|| {
        STREAMS.with(|streams| {
            streams
                .borrow_mut()
                .retain(|_, stream| stream.owner != instance)
        });
        let state = INSTANCES.with(|instances| instances.borrow_mut().remove(&instance));
        if let Some(mut state) = state {
            let _ = state.commands.try_send(WorkerCommand::Shutdown);
            if let Some(worker) = state.worker.take() {
                let _ = worker.join();
            }
        }
    });
}

unsafe extern "C" fn connect(
    instance: u64,
    endpoint: SnolBytes,
    wake: SnolWakeHandle,
    output: *mut u64,
) -> u32 {
    snolc_sdk::catch_status(|| {
        let endpoint = match unsafe { snolc_sdk::module::input(endpoint) } {
            Ok(endpoint) => endpoint,
            Err(status) => return status,
        };
        if !endpoint.is_empty() {
            return abi::STATUS_UNSUPPORTED;
        }
        INSTANCES.with(|instances| {
            let mut instances = instances.borrow_mut();
            let Some(state) = instances.get_mut(&instance) else {
                return abi::STATUS_INVALID;
            };
            drain_events(state);
            if !state.client {
                return abi::STATUS_UNSUPPORTED;
            }
            take_or_start(state, instance, wake, output, true)
        })
    })
}

unsafe extern "C" fn accept(instance: u64, wake: SnolWakeHandle, output: *mut u64) -> u32 {
    snolc_sdk::catch_status(|| {
        INSTANCES.with(|instances| {
            let mut instances = instances.borrow_mut();
            let Some(state) = instances.get_mut(&instance) else {
                return abi::STATUS_INVALID;
            };
            drain_events(state);
            if state.client {
                return abi::STATUS_UNSUPPORTED;
            }
            take_or_start(state, instance, wake, output, false)
        })
    })
}

fn take_or_start(
    state: &mut InstanceState,
    owner: u64,
    wake: SnolWakeHandle,
    output: *mut u64,
    connect: bool,
) -> u32 {
    if let Some(stream) = state.ready.pop_front() {
        return finish_stream(owner, stream, state, output);
    }
    if state.failures != 0 {
        state.failures -= 1;
        return abi::STATUS_IO;
    }
    if state.failed {
        return abi::STATUS_IO;
    }
    if state.active_connections >= state.max_connections {
        return abi::STATUS_RESOURCE;
    }
    if connect && !state.connect_pending {
        match state.commands.try_send(WorkerCommand::Connect) {
            Ok(()) => state.connect_pending = true,
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                return abi::STATUS_RESOURCE;
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => return abi::STATUS_IO,
        }
    }
    if connect {
        state.connect_wake.replace(wake);
    } else {
        state.accept_wake.replace(wake);
    }
    abi::STATUS_PENDING
}

fn finish_stream(
    owner: u64,
    stream: EngineIo,
    instance: &mut InstanceState,
    output: *mut u64,
) -> u32 {
    let Some(output) = (unsafe { output.as_mut() }) else {
        return abi::STATUS_INVALID;
    };
    let handle = STREAM_NEXT.fetch_add(1, Ordering::Relaxed);
    if handle == 0 {
        return abi::STATUS_RESOURCE;
    }
    STREAMS.with(|streams| {
        streams.borrow_mut().insert(
            handle,
            StreamState {
                owner,
                io: stream,
                read_wake: WakeSlot::default(),
                write_wake: WakeSlot::default(),
            },
        );
    });
    instance.active_connections += 1;
    *output = handle;
    abi::STATUS_OK
}

unsafe extern "C" fn read(handle: u64, output: SnolBytesMut, wake: SnolWakeHandle) -> SnolIoResult {
    snolc_sdk::catch_io(|| {
        if output.pointer.is_null() && output.length != 0 {
            return SnolIoResult::error(abi::STATUS_INVALID);
        }
        STREAMS.with(|streams| {
            let mut streams = streams.borrow_mut();
            let Some(stream) = streams.get_mut(&handle) else {
                return SnolIoResult::error(abi::STATUS_INVALID);
            };
            let output = if output.length == 0 {
                &mut []
            } else {
                unsafe { std::slice::from_raw_parts_mut(output.pointer, output.length) }
            };
            let mut context = Context::from_waker(Waker::noop());
            match Pin::new(&mut stream.io).poll_read(&mut context, output) {
                Poll::Ready(Ok(0)) => SnolIoResult::eof(),
                Poll::Ready(Ok(count)) => SnolIoResult::progress(count),
                Poll::Ready(Err(_)) => SnolIoResult::error(abi::STATUS_IO),
                Poll::Pending => {
                    stream.read_wake.replace(wake);
                    SnolIoResult::pending()
                }
            }
        })
    })
}

unsafe extern "C" fn write(handle: u64, input: SnolBytes, wake: SnolWakeHandle) -> SnolIoResult {
    snolc_sdk::catch_io(|| {
        let input = match unsafe { snolc_sdk::module::input(input) } {
            Ok(input) => input,
            Err(status) => return SnolIoResult::error(status),
        };
        if input.is_empty() {
            return SnolIoResult::progress(0);
        }
        STREAMS.with(|streams| {
            let mut streams = streams.borrow_mut();
            let Some(stream) = streams.get_mut(&handle) else {
                return SnolIoResult::error(abi::STATUS_INVALID);
            };
            let mut context = Context::from_waker(Waker::noop());
            match Pin::new(&mut stream.io).poll_write(&mut context, input) {
                Poll::Ready(Ok(0)) | Poll::Ready(Err(_)) => SnolIoResult::error(abi::STATUS_IO),
                Poll::Ready(Ok(count)) => SnolIoResult::progress(count),
                Poll::Pending => {
                    stream.write_wake.replace(wake);
                    SnolIoResult::pending()
                }
            }
        })
    })
}

unsafe extern "C" fn flush(handle: u64, wake: SnolWakeHandle) -> SnolIoResult {
    io_action(handle, wake, |io, context| Pin::new(io).poll_flush(context))
}

unsafe extern "C" fn shutdown_write(handle: u64, wake: SnolWakeHandle) -> SnolIoResult {
    io_action(handle, wake, |io, context| Pin::new(io).poll_close(context))
}

fn io_action(
    handle: u64,
    wake: SnolWakeHandle,
    action: impl FnOnce(&mut EngineIo, &mut Context<'_>) -> Poll<io::Result<()>>,
) -> SnolIoResult {
    snolc_sdk::catch_io(|| {
        STREAMS.with(|streams| {
            let mut streams = streams.borrow_mut();
            let Some(stream) = streams.get_mut(&handle) else {
                return SnolIoResult::error(abi::STATUS_INVALID);
            };
            let mut context = Context::from_waker(Waker::noop());
            match action(&mut stream.io, &mut context) {
                Poll::Ready(Ok(())) => SnolIoResult::progress(0),
                Poll::Ready(Err(_)) => SnolIoResult::error(abi::STATUS_IO),
                Poll::Pending => {
                    stream.write_wake.replace(wake);
                    SnolIoResult::pending()
                }
            }
        })
    })
}

unsafe extern "C" fn close(handle: u64) -> u32 {
    snolc_sdk::catch_status(|| {
        let owner = STREAMS.with(|streams| streams.borrow_mut().remove(&handle).map(|s| s.owner));
        let Some(owner) = owner else {
            return abi::STATUS_INVALID;
        };
        INSTANCES.with(|instances| {
            if let Some(instance) = instances.borrow_mut().get_mut(&owner) {
                instance.active_connections = instance.active_connections.saturating_sub(1);
            }
        });
        abi::STATUS_OK
    })
}

fn worker_main(
    options: Options,
    commands: tokio::sync::mpsc::Receiver<WorkerCommand>,
    events: SyncSender<WorkerEvent>,
) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            let _ = events.try_send(WorkerEvent::Fatal);
            return;
        }
    };
    let task_events = events.clone();
    let result = runtime.block_on(async move {
        match options {
            Options::Connect { .. } => client_worker(options, commands, task_events.clone()).await,
            Options::Listen { .. } => server_worker(options, commands, task_events.clone()).await,
        }
    });
    if result.is_err() {
        let _ = events.try_send(WorkerEvent::Fatal);
    }
}

async fn client_worker(
    options: Options,
    mut commands: tokio::sync::mpsc::Receiver<WorkerCommand>,
    events: SyncSender<WorkerEvent>,
) -> Result<(), ()> {
    let mut sessions = JoinSet::new();
    loop {
        tokio::select! {
            command = commands.recv() => match command {
                Some(WorkerCommand::Connect) => {
                    let options = options.clone();
                    let events = events.clone();
                    sessions.spawn(async move {
                        if run_client_session(options, events.clone()).await.is_err() {
                            let _ = events.try_send(WorkerEvent::AttemptFailed);
                        }
                    });
                }
                Some(WorkerCommand::Shutdown) | None => {
                    sessions.abort_all();
                    return Ok(());
                }
            },
            Some(_) = sessions.join_next(), if !sessions.is_empty() => {}
        }
    }
}

async fn run_client_session(options: Options, events: SyncSender<WorkerEvent>) -> Result<(), ()> {
    let Options::Connect {
        endpoint_ip,
        username,
        server_host_key,
        queue_chunks,
        chunk_bytes,
        inactivity_timeout_ms,
        auth,
        ..
    } = options
    else {
        return Err(());
    };
    let trusted = russh::keys::load_public_key(server_host_key).map_err(|_| ())?;
    let config = Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_millis(inactivity_timeout_ms)),
        nodelay: true,
        ..Default::default()
    });
    let mut session = client::connect(config, endpoint_ip, ClientHandler { trusted })
        .await
        .map_err(|_| ())?;
    let authenticated = match auth {
        ClientAuth::Password { password } => session
            .authenticate_password(username, password)
            .await
            .map_err(|_| ())?,
        ClientAuth::Ed25519 { private_key } => {
            let private = russh::keys::load_secret_key(private_key, None).map_err(|_| ())?;
            session
                .authenticate_publickey(
                    username,
                    russh::keys::PrivateKeyWithHashAlg::new(Arc::new(private), None),
                )
                .await
                .map_err(|_| ())?
        }
    };
    if authenticated != AuthResult::Success {
        return Err(());
    }
    let mut channel = session.channel_open_session().await.map_err(|_| ())?;
    channel
        .request_subsystem(true, "snolc")
        .await
        .map_err(|_| ())?;
    loop {
        match channel.wait().await {
            Some(ChannelMsg::Success) => break,
            Some(ChannelMsg::Failure | ChannelMsg::Close) | None => return Err(()),
            Some(_) => {}
        }
    }
    let (engine, mut worker) = pair(queue_chunks, chunk_bytes);
    events
        .try_send(WorkerEvent::Ready(engine))
        .map_err(|_| ())?;
    let mut channel = channel.into_stream();
    let _ = copy_bidirectional(&mut channel, &mut worker).await;
    let _ = session
        .disconnect(Disconnect::ByApplication, "snolc closed", "en")
        .await;
    Ok(())
}

struct ClientHandler {
    trusted: PublicKey,
}

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(server_public_key.public_key() == self.trusted)
    }
}

async fn server_worker(
    options: Options,
    mut commands: tokio::sync::mpsc::Receiver<WorkerCommand>,
    events: SyncSender<WorkerEvent>,
) -> Result<(), ()> {
    let Options::Listen {
        endpoint_ip,
        username,
        host_key,
        max_connections,
        queue_chunks,
        chunk_bytes,
        inactivity_timeout_ms,
        auth,
    } = options
    else {
        return Err(());
    };
    let host_key = russh::keys::load_secret_key(host_key, None).map_err(|_| ())?;
    let credential = load_server_credential(auth)?;
    let methods = match credential {
        ServerCredential::Password(_) => MethodSet::from(&[MethodKind::Password][..]),
        ServerCredential::Ed25519(_) => MethodSet::from(&[MethodKind::PublicKey][..]),
    };
    let config = Arc::new(server::Config {
        methods,
        keys: vec![host_key],
        inactivity_timeout: Some(Duration::from_millis(inactivity_timeout_ms)),
        nodelay: true,
        ..Default::default()
    });
    let listener = tokio::net::TcpListener::bind(endpoint_ip)
        .await
        .map_err(|_| ())?;
    let mut sessions = JoinSet::new();
    loop {
        tokio::select! {
            command = commands.recv() => match command {
                Some(WorkerCommand::Shutdown) | None => {
                    sessions.abort_all();
                    return Ok(());
                }
                Some(WorkerCommand::Connect) => {}
            },
            accepted = listener.accept() => {
                let (socket, _) = accepted.map_err(|_| ())?;
                if sessions.len() >= max_connections {
                    drop(socket);
                    continue;
                }
                let config = Arc::clone(&config);
                let handler = ServerHandler {
                    username: username.clone(),
                    credential: credential.clone(),
                    channels: HashMap::new(),
                    events: events.clone(),
                    queue_chunks,
                    chunk_bytes,
                };
                sessions.spawn(async move {
                    if let Ok(session) = server::run_stream(config, socket, handler).await {
                        let _ = session.await;
                    }
                });
            },
            Some(_) = sessions.join_next(), if !sessions.is_empty() => {}
        }
    }
}

#[derive(Clone)]
enum ServerCredential {
    Password(String),
    Ed25519(PublicKey),
}

fn load_server_credential(auth: ServerAuth) -> Result<ServerCredential, ()> {
    match auth {
        ServerAuth::Password { password } => Ok(ServerCredential::Password(password)),
        ServerAuth::Ed25519 { public_key } => russh::keys::load_public_key(public_key)
            .map(ServerCredential::Ed25519)
            .map_err(|_| ()),
    }
}

struct ServerHandler {
    username: String,
    credential: ServerCredential,
    channels: HashMap<ChannelId, Channel<server::Msg>>,
    events: SyncSender<WorkerEvent>,
    queue_chunks: usize,
    chunk_bytes: usize,
}

impl server::Handler for ServerHandler {
    type Error = russh::Error;

    async fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> Result<server::Auth, Self::Error> {
        Ok(match &self.credential {
            ServerCredential::Password(expected)
                if user == self.username && password == expected =>
            {
                server::Auth::Accept
            }
            _ => server::Auth::reject(),
        })
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<server::Auth, Self::Error> {
        Ok(match &self.credential {
            ServerCredential::Ed25519(expected)
                if user == self.username && public_key == expected =>
            {
                server::Auth::Accept
            }
            _ => server::Auth::reject(),
        })
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<server::Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        if self.channels.is_empty() {
            let id = channel.id();
            self.channels.insert(id, channel);
            reply.accept().await;
        }
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        let Some(channel) = self.channels.remove(&channel) else {
            session.channel_failure(channel)?;
            return Ok(());
        };
        if name != "snolc" {
            session.channel_failure(channel.id())?;
            let _ = channel.close().await;
            return Ok(());
        }
        let (engine, mut worker) = pair(self.queue_chunks, self.chunk_bytes);
        if self.events.try_send(WorkerEvent::Ready(engine)).is_err() {
            session.channel_failure(channel.id())?;
            let _ = channel.close().await;
            return Ok(());
        }
        session.channel_success(channel.id())?;
        tokio::spawn(async move {
            let mut channel = channel.into_stream();
            let _ = copy_bidirectional(&mut channel, &mut worker).await;
        });
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(Pty, u32)],
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(channel)?;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        _data: &[u8],
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(channel)?;
        Ok(())
    }

    async fn agent_request(
        &mut self,
        channel: ChannelId,
        session: &mut server::Session,
    ) -> Result<bool, Self::Error> {
        session.channel_failure(channel)?;
        Ok(false)
    }
}

static BYTE_IO: SnolByteIoV1 = SnolByteIoV1 {
    struct_size: size_of::<SnolByteIoV1>() as u32,
    reserved: 0,
    read: Some(read),
    write: Some(write),
    flush: Some(flush),
    shutdown_write: Some(shutdown_write),
    close: Some(close),
};

static CARRIER: SnolCarrierApiV1 = SnolCarrierApiV1 {
    struct_size: size_of::<SnolCarrierApiV1>() as u32,
    reserved: 0,
    connect: Some(connect),
    accept: Some(accept),
};

static DESCRIPTOR: SnolModuleDescriptor = SnolModuleDescriptor {
    struct_size: size_of::<SnolModuleDescriptor>() as u32,
    wire_version: abi::WIRE_VERSION,
    class_mask: abi::CLASS_CARRIER,
    reserved: 0,
    name: c"carrier-ssh".as_ptr(),
    describe: Some(describe),
    validate_config: Some(validate_config),
    create: Some(create),
    poll: Some(poll),
    control: Some(control),
    shutdown: Some(shutdown),
    destroy: Some(destroy),
    byte_io: &BYTE_IO,
    datagram_io: std::ptr::null(),
    adapter: std::ptr::null(),
    protection: std::ptr::null(),
    carrier: &CARRIER,
    policy: std::ptr::null(),
};

#[unsafe(no_mangle)]
pub extern "C" fn snolc_module_entry() -> *const SnolModuleDescriptor {
    &DESCRIPTOR
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::net::TcpListener;
    use std::time::{Instant, SystemTime, UNIX_EPOCH};

    use futures::io::{AsyncReadExt, AsyncWriteExt};
    use russh::keys::ssh_key::LineEnding;

    use super::*;

    #[test]
    fn ssh_subsystem_moves_bytes_with_password_auth() {
        let root = std::env::temp_dir().join(format!(
            "snolc-carrier-ssh-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        let private_path = root.join("host");
        let public_path = root.join("host.pub");
        let private =
            russh::keys::PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        fs::write(
            &private_path,
            private.to_openssh(LineEnding::LF).unwrap().as_bytes(),
        )
        .unwrap();
        fs::write(&public_path, private.public_key().to_openssh().unwrap()).unwrap();
        let endpoint = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();

        let server = Options::Listen {
            endpoint_ip: endpoint,
            username: "snolc".into(),
            host_key: private_path,
            max_connections: 1,
            queue_chunks: 4,
            chunk_bytes: 4096,
            inactivity_timeout_ms: 5000,
            auth: ServerAuth::Password {
                password: "secret".into(),
            },
        };
        let client = Options::Connect {
            endpoint_ip: endpoint,
            username: "snolc".into(),
            server_host_key: public_path,
            max_connections: 1,
            queue_chunks: 4,
            chunk_bytes: 4096,
            inactivity_timeout_ms: 5000,
            auth: ClientAuth::Password {
                password: "secret".into(),
            },
        };
        let (server_commands, server_rx) = tokio::sync::mpsc::channel(2);
        let (server_events, server_event_rx) = mpsc::sync_channel(2);
        let server_thread = std::thread::spawn(move || {
            worker_main(server, server_rx, server_events);
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        while TcpListener::bind(endpoint).is_ok() {
            assert!(Instant::now() < deadline, "SSH listener did not bind");
            std::thread::yield_now();
        }
        let (client_commands, client_rx) = tokio::sync::mpsc::channel(2);
        let (client_events, client_event_rx) = mpsc::sync_channel(2);
        let client_thread = std::thread::spawn(move || {
            worker_main(client, client_rx, client_events);
        });
        client_commands.try_send(WorkerCommand::Connect).unwrap();

        let mut client = match client_event_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
        {
            WorkerEvent::Ready(stream) => stream,
            _ => panic!("SSH client failed"),
        };
        let mut server = match server_event_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
        {
            WorkerEvent::Ready(stream) => stream,
            _ => panic!("SSH server failed"),
        };
        futures::executor::block_on(async {
            client.write_all(b"client").await.unwrap();
            let mut input = [0; 6];
            server.read_exact(&mut input).await.unwrap();
            assert_eq!(&input, b"client");
            server.write_all(b"server").await.unwrap();
            client.read_exact(&mut input).await.unwrap();
            assert_eq!(&input, b"server");
        });
        drop(client);
        drop(server);
        client_commands.try_send(WorkerCommand::Shutdown).unwrap();
        server_commands.try_send(WorkerCommand::Shutdown).unwrap();
        client_thread.join().unwrap();
        server_thread.join().unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}
