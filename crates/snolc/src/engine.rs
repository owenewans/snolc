use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::c_void;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use async_executor::LocalExecutor;
use futures::channel::{mpsc, oneshot};
use futures::{FutureExt, StreamExt, select};
use thiserror::Error;

use crate::config::{Config, ControlConfig, Role, YamuxConfig};
use crate::events::{Event, EventReceiver, Lifecycle, Snapshot};
use crate::loader::{LoadError, LoadedModule, ModuleByteIo};
use crate::mux::{MuxError, MuxSession};

const HOST_EVENT_LIMIT: usize = 65_536;
const MODULE_POLL_INTERVAL: Duration = Duration::from_millis(10);
type ContextMap = HashMap<(u64, Vec<u8>), Vec<u8>>;

pub type ResponseFuture = Pin<Box<dyn Future<Output = Result<Vec<u8>, EngineError>> + Send>>;

pub trait Host: Send + Sync + 'static {
    fn engine_event(&self, event: &Event);
}

pub struct ValidatedConfig {
    config: Config,
    modules: Vec<LoadedModule>,
    tunnels: Vec<TunnelBinding>,
}

#[derive(Clone)]
struct TunnelBinding {
    name: String,
    role: Role,
    carrier: usize,
    protection: usize,
    policy_family: String,
    yamux: YamuxConfig,
    connect_timeout: Duration,
    handshake_timeout: Duration,
}

struct TunnelRuntime {
    binding: TunnelBinding,
    state: TunnelState,
    deadline: Option<Instant>,
}

enum TunnelState {
    Carrier,
    Protection(Option<ModuleByteIo>),
    Handshake(HandshakeFuture),
    Established(Box<EstablishedSession>),
    Failed,
}

type HandshakeFuture = Pin<Box<dyn Future<Output = Result<EstablishedSession, MuxError>>>>;

struct EstablishedSession {
    mux: MuxSession<ModuleByteIo>,
    _policy_stream: yamux::Stream,
}

pub struct Engine {
    validated: ValidatedConfig,
    host: Arc<dyn Host>,
    bridge: Box<HostBridge>,
    commands: mpsc::Receiver<Command>,
    events: mpsc::Sender<Event>,
    snapshot: Arc<AtomicSnapshot>,
    wake: Arc<WakeState>,
}

#[derive(Clone)]
pub struct EngineHandle {
    commands: mpsc::Sender<Command>,
    events: Arc<Mutex<Option<EventReceiver>>>,
    snapshot: Arc<AtomicSnapshot>,
}

struct AtomicSnapshot {
    lifecycle: AtomicU8,
    sessions: AtomicUsize,
    flows: AtomicUsize,
    lost_events: AtomicUsize,
}

struct WakeState {
    woken: AtomicBool,
}

struct HostBridge {
    started: Instant,
    event_limit: usize,
    events: RefCell<VecDeque<Vec<u8>>>,
    timers: RefCell<HashMap<u64, u64>>,
    context: RefCell<ContextMap>,
}

enum Command {
    Control {
        instance: String,
        request: Vec<u8>,
        response: oneshot::Sender<Result<Vec<u8>, EngineError>>,
    },
    Shutdown {
        response: oneshot::Sender<()>,
    },
}

impl Engine {
    pub fn validate(
        config: Config,
        modules: Vec<LoadedModule>,
    ) -> Result<ValidatedConfig, EngineError> {
        config.validate()?;
        let mut instances = HashSet::new();
        let mut classes = 0;
        for module in &modules {
            if !instances.insert(module.instance_name()) {
                return Err(EngineError::DuplicateInstance(
                    module.instance_name().to_owned(),
                ));
            }
            classes |= module.class_mask();
        }
        let required = snolc_abi::CLASS_ADAPTER
            | snolc_abi::CLASS_PROTECTION
            | snolc_abi::CLASS_CARRIER
            | snolc_abi::CLASS_POLICY;
        if classes & required != required {
            return Err(EngineError::MissingModuleClass(required & !classes));
        }
        let mut tunnels = Vec::with_capacity(config.tunnels.len());
        for tunnel in &config.tunnels {
            for adapter in &tunnel.adapters {
                find_module(&modules, adapter, snolc_abi::CLASS_ADAPTER)?;
            }
            let protection =
                find_module(&modules, &tunnel.protection, snolc_abi::CLASS_PROTECTION)?;
            let carrier = find_module(&modules, &tunnel.carrier, snolc_abi::CLASS_CARRIER)?;
            let policy = find_module(&modules, &tunnel.policy, snolc_abi::CLASS_POLICY)?;
            tunnels.push(TunnelBinding {
                name: tunnel.name.clone(),
                role: tunnel.role,
                carrier,
                protection,
                policy_family: modules[policy].name().to_owned(),
                yamux: config.yamux.clone(),
                connect_timeout: Duration::from_millis(config.engine.connect_timeout_ms),
                handshake_timeout: Duration::from_millis(config.engine.handshake_timeout_ms),
            });
        }
        Ok(ValidatedConfig {
            config,
            modules,
            tunnels,
        })
    }

    pub fn build<H: Host>(
        validated: ValidatedConfig,
        host: H,
    ) -> Result<(Self, EngineHandle), EngineError> {
        let (command_tx, command_rx) = mpsc::channel(validated.config.engine.max_commands);
        let (event_tx, event_rx) = mpsc::channel(validated.config.engine.max_events);
        let snapshot = Arc::new(AtomicSnapshot {
            lifecycle: AtomicU8::new(Lifecycle::Configured as u8),
            sessions: AtomicUsize::new(0),
            flows: AtomicUsize::new(0),
            lost_events: AtomicUsize::new(0),
        });
        let handle = EngineHandle {
            commands: command_tx,
            events: Arc::new(Mutex::new(Some(event_rx))),
            snapshot: Arc::clone(&snapshot),
        };
        let engine = Self {
            validated,
            host: Arc::new(host),
            bridge: Box::new(HostBridge {
                started: Instant::now(),
                event_limit: HOST_EVENT_LIMIT,
                events: RefCell::new(VecDeque::new()),
                timers: RefCell::new(HashMap::new()),
                context: RefCell::new(HashMap::new()),
            }),
            commands: command_rx,
            events: event_tx,
            snapshot,
            wake: Arc::new(WakeState {
                woken: AtomicBool::new(true),
            }),
        };
        Ok((engine, handle))
    }

    pub fn run(self) -> Result<(), EngineError> {
        let executor = LocalExecutor::new();
        async_io::block_on(executor.run(self.run_loop()))
    }

    async fn run_loop(mut self) -> Result<(), EngineError> {
        self.emit(Event::Lifecycle(Lifecycle::Starting));
        let host_api = self.host_api();
        for module in &mut self.validated.modules {
            if let Err(error) = module.create(&host_api) {
                self.snapshot
                    .lifecycle
                    .store(Lifecycle::Failed as u8, Ordering::Release);
                return Err(error.into());
            }
        }
        let mut tunnels: Vec<_> = self
            .validated
            .tunnels
            .iter()
            .cloned()
            .map(TunnelRuntime::new)
            .collect();
        self.emit(Event::Lifecycle(Lifecycle::Running));

        loop {
            let command = FutureExt::fuse(self.commands.next());
            let timer = FutureExt::fuse(async_io::Timer::after(MODULE_POLL_INTERVAL));
            futures::pin_mut!(command, timer);
            select! {
                command = command => match command {
                    Some(Command::Control { instance, request, response }) => {
                        let result = self.control(&instance, &request);
                        let _ = response.send(result);
                    }
                    Some(Command::Shutdown { response }) => {
                        self.emit(Event::Lifecycle(Lifecycle::Stopping));
                        let _ = response.send(());
                        break;
                    }
                    None => {
                        self.emit(Event::Lifecycle(Lifecycle::Stopping));
                        break;
                    }
                },
                _ = timer => {
                    self.poll_modules();
                    self.poll_tunnels(&mut tunnels);
                    self.drain_module_events();
                }
            }
        }

        drop(tunnels);
        self.snapshot.sessions.store(0, Ordering::Release);
        let mut errors = Vec::new();
        for module in self.validated.modules.iter_mut().rev() {
            if let Err(error) = module.shutdown() {
                errors.push(Event::ModuleError {
                    instance: module.instance_name().to_owned(),
                    message: error.to_string(),
                });
            }
        }
        for event in errors {
            self.emit(event);
        }
        self.emit(Event::Lifecycle(Lifecycle::Stopped));
        Ok(())
    }

    fn control(&mut self, instance: &str, request: &[u8]) -> Result<Vec<u8>, EngineError> {
        let max_response = match &self.validated.config.control {
            ControlConfig::Off => 65_536,
            ControlConfig::Unix {
                max_request_bytes, ..
            } => *max_request_bytes,
        };
        let module = self
            .validated
            .modules
            .iter_mut()
            .find(|module| module.instance_name() == instance)
            .ok_or_else(|| EngineError::InstanceNotFound(instance.to_owned()))?;
        module.control(request, max_response).map_err(Into::into)
    }

    fn poll_modules(&mut self) {
        let wake = wake_handle(&self.wake);
        self.wake.woken.store(false, Ordering::Release);
        let mut errors = Vec::new();
        for module in &mut self.validated.modules {
            if let Err(error) = module.poll(wake) {
                errors.push(Event::ModuleError {
                    instance: module.instance_name().to_owned(),
                    message: error.to_string(),
                });
            }
        }
        for event in errors {
            self.emit(event);
        }
    }

    fn poll_tunnels(&mut self, tunnels: &mut [TunnelRuntime]) {
        let mut established = 0;
        let mut closed = 0;
        let mut failures = Vec::new();
        for tunnel in tunnels {
            match tunnel.poll(&self.validated.modules) {
                Ok(new_session) => established += usize::from(new_session),
                Err((message, was_established)) => {
                    closed += usize::from(was_established);
                    failures.push((tunnel.binding.name.clone(), message));
                }
            }
        }
        if established != 0 {
            self.snapshot
                .sessions
                .fetch_add(established, Ordering::Relaxed);
        }
        if closed != 0 {
            self.snapshot.sessions.fetch_sub(closed, Ordering::Relaxed);
        }
        for (instance, message) in failures {
            self.emit(Event::ModuleError { instance, message });
        }
    }

    fn drain_module_events(&mut self) {
        let events: Vec<_> = self.bridge.events.borrow_mut().drain(..).collect();
        for payload in events {
            self.emit(Event::Module {
                instance: String::new(),
                payload,
            });
        }
    }

    fn emit(&mut self, event: Event) {
        if let Event::Lifecycle(lifecycle) = event {
            self.snapshot
                .lifecycle
                .store(lifecycle as u8, Ordering::Release);
        }
        self.host.engine_event(&event);
        if self.events.try_send(event).is_err() {
            self.snapshot.lost_events.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn host_api(&mut self) -> snolc_abi::SnolHostApiV1 {
        snolc_abi::SnolHostApiV1 {
            struct_size: size_of::<snolc_abi::SnolHostApiV1>() as u32,
            reserved: 0,
            context: (&mut *self.bridge as *mut HostBridge).cast(),
            now_monotonic_nanos: Some(host_now),
            set_timer: Some(host_set_timer),
            emit_event: Some(host_emit_event),
            context_get: Some(host_context_get),
            context_set: Some(host_context_set),
        }
    }
}

fn find_module(
    modules: &[LoadedModule],
    source: &std::path::Path,
    class: u32,
) -> Result<usize, EngineError> {
    let matches: Vec<_> = modules
        .iter()
        .enumerate()
        .filter(|(_, module)| module.source_config() == source && module.class_mask() & class != 0)
        .map(|(index, _)| index)
        .collect();
    match matches.as_slice() {
        [index] => Ok(*index),
        _ => Err(EngineError::ModuleBinding {
            path: source.display().to_string(),
            class,
        }),
    }
}

impl TunnelRuntime {
    fn new(binding: TunnelBinding) -> Self {
        let deadline = match binding.role {
            Role::Client => Some(Instant::now() + binding.connect_timeout),
            Role::Server => None,
        };
        Self {
            binding,
            state: TunnelState::Carrier,
            deadline,
        }
    }

    fn poll(&mut self, modules: &[LoadedModule]) -> Result<bool, (String, bool)> {
        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            self.state = TunnelState::Failed;
            self.deadline = None;
            return Err(("tunnel establishment timed out".into(), false));
        }
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        match &mut self.state {
            TunnelState::Carrier => {
                let carrier = &modules[self.binding.carrier];
                let result = match self.binding.role {
                    Role::Client => carrier.carrier_connect(&[], &mut context),
                    Role::Server => carrier.carrier_accept(&mut context),
                };
                match result {
                    Poll::Ready(Ok(io)) => {
                        self.state = TunnelState::Protection(Some(io));
                        self.deadline = Some(Instant::now() + self.binding.handshake_timeout);
                    }
                    Poll::Ready(Err(error)) => return self.fail(error.to_string(), false),
                    Poll::Pending => {}
                }
            }
            TunnelState::Protection(lower) => {
                let role = match self.binding.role {
                    Role::Client => b"role = \"client\"\n".as_slice(),
                    Role::Server => b"role = \"server\"\n".as_slice(),
                };
                match modules[self.binding.protection].protection_wrap(lower, role, &mut context) {
                    Poll::Ready(Ok(io)) => {
                        let role = self.binding.role;
                        let family = self.binding.policy_family.clone();
                        let config = self.binding.yamux.clone();
                        self.state = TunnelState::Handshake(Box::pin(async move {
                            let mode = match role {
                                Role::Client => yamux::Mode::Client,
                                Role::Server => yamux::Mode::Server,
                            };
                            let mut mux = MuxSession::new(io, mode, &config);
                            let policy_stream = match role {
                                Role::Client => mux.open_policy(&family).await?,
                                Role::Server => mux.accept_policy(&family).await?,
                            };
                            Ok(EstablishedSession {
                                mux,
                                _policy_stream: policy_stream,
                            })
                        }));
                    }
                    Poll::Ready(Err(error)) => return self.fail(error.to_string(), false),
                    Poll::Pending => {}
                }
            }
            TunnelState::Handshake(handshake) => match handshake.as_mut().poll(&mut context) {
                Poll::Ready(Ok(session)) => {
                    self.state = TunnelState::Established(Box::new(session));
                    self.deadline = None;
                    return Ok(true);
                }
                Poll::Ready(Err(error)) => return self.fail(error.to_string(), false),
                Poll::Pending => {}
            },
            TunnelState::Established(session) => {
                if let Poll::Ready(Err(error)) = session.mux.poll_drive(&mut context) {
                    return self.fail(error.to_string(), true);
                }
            }
            TunnelState::Failed => {}
        }
        Ok(false)
    }

    fn fail(&mut self, message: String, was_established: bool) -> Result<bool, (String, bool)> {
        self.state = TunnelState::Failed;
        self.deadline = None;
        Err((message, was_established))
    }
}

impl EngineHandle {
    pub fn control(&self, instance: impl Into<String>, request: Vec<u8>) -> ResponseFuture {
        let mut commands = self.commands.clone();
        let instance = instance.into();
        Box::pin(async move {
            let (response_tx, response_rx) = oneshot::channel();
            commands
                .try_send(Command::Control {
                    instance,
                    request,
                    response: response_tx,
                })
                .map_err(|_| EngineError::CommandQueue)?;
            response_rx.await.map_err(|_| EngineError::Stopped)?
        })
    }

    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            lifecycle: Lifecycle::from_u8(self.snapshot.lifecycle.load(Ordering::Acquire)),
            sessions: self.snapshot.sessions.load(Ordering::Acquire),
            flows: self.snapshot.flows.load(Ordering::Acquire),
            lost_events: self.snapshot.lost_events.load(Ordering::Acquire),
        }
    }

    pub fn subscribe(&self) -> Result<EventReceiver, EngineError> {
        self.events
            .lock()
            .map_err(|_| EngineError::EventReceiver)?
            .take()
            .ok_or(EngineError::EventReceiver)
    }

    pub fn shutdown(&self) -> Result<(), EngineError> {
        let (response_tx, response_rx) = oneshot::channel();
        let mut commands = self.commands.clone();
        commands
            .try_send(Command::Shutdown {
                response: response_tx,
            })
            .map_err(|_| EngineError::CommandQueue)?;
        async_io::block_on(response_rx).map_err(|_| EngineError::Stopped)
    }
}

fn wake_handle(wake: &Arc<WakeState>) -> snolc_abi::SnolWakeHandle {
    snolc_abi::SnolWakeHandle {
        context: Arc::as_ptr(wake).cast_mut().cast(),
        wake: Some(module_wake),
        retain: Some(module_wake_retain),
        release: Some(module_wake_release),
    }
}

unsafe extern "C" fn module_wake(context: *mut c_void) {
    if let Some(wake) = unsafe { (context as *const WakeState).as_ref() } {
        wake.woken.store(true, Ordering::Release);
    }
}

unsafe extern "C" fn module_wake_retain(context: *mut c_void) -> u32 {
    if context.is_null() {
        return snolc_abi::STATUS_INVALID;
    }
    // context was created from Arc::as_ptr and retains the same allocation.
    unsafe { Arc::increment_strong_count(context as *const WakeState) };
    snolc_abi::STATUS_OK
}

unsafe extern "C" fn module_wake_release(context: *mut c_void) {
    if !context.is_null() {
        // each successful retain owns one strong count.
        unsafe { Arc::decrement_strong_count(context as *const WakeState) };
    }
}

unsafe extern "C" fn host_now(context: *mut c_void) -> u64 {
    let Some(bridge) = (unsafe { (context as *const HostBridge).as_ref() }) else {
        return 0;
    };
    u64::try_from(bridge.started.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

unsafe extern "C" fn host_set_timer(context: *mut c_void, handle: u64, deadline: u64) -> u32 {
    let Some(bridge) = (unsafe { (context as *const HostBridge).as_ref() }) else {
        return snolc_abi::STATUS_INVALID;
    };
    bridge.timers.borrow_mut().insert(handle, deadline);
    snolc_abi::STATUS_OK
}

unsafe extern "C" fn host_emit_event(context: *mut c_void, event: snolc_abi::SnolBytes) -> u32 {
    let Some(bridge) = (unsafe { (context as *const HostBridge).as_ref() }) else {
        return snolc_abi::STATUS_INVALID;
    };
    if event.length > bridge.event_limit || (event.pointer.is_null() && event.length != 0) {
        return snolc_abi::STATUS_RESOURCE;
    }
    // the module guarantees readable borrowed bytes for this call.
    let payload = if event.length == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(event.pointer, event.length) }.to_vec()
    };
    bridge.events.borrow_mut().push_back(payload);
    snolc_abi::STATUS_OK
}

unsafe extern "C" fn host_context_get(
    context: *mut c_void,
    session: u64,
    name: snolc_abi::SnolBytes,
    output: snolc_abi::SnolBytesMut,
    written: *mut usize,
) -> u32 {
    let Some(bridge) = (unsafe { (context as *const HostBridge).as_ref() }) else {
        return snolc_abi::STATUS_INVALID;
    };
    let (Some(name), Some(written)) = (unsafe { read_bytes(name) }, unsafe { written.as_mut() })
    else {
        return snolc_abi::STATUS_INVALID;
    };
    let values = bridge.context.borrow();
    let Some(value) = values.get(&(session, name.to_vec())) else {
        return snolc_abi::STATUS_UNSUPPORTED;
    };
    *written = value.len();
    if output.length < value.len() {
        return snolc_abi::STATUS_RESOURCE;
    }
    if output.pointer.is_null() && !value.is_empty() {
        return snolc_abi::STATUS_INVALID;
    }
    // output is writable for output.length bytes by contract.
    unsafe { std::ptr::copy_nonoverlapping(value.as_ptr(), output.pointer, value.len()) };
    snolc_abi::STATUS_OK
}

unsafe extern "C" fn host_context_set(
    context: *mut c_void,
    session: u64,
    name: snolc_abi::SnolBytes,
    value: snolc_abi::SnolBytes,
) -> u32 {
    let Some(bridge) = (unsafe { (context as *const HostBridge).as_ref() }) else {
        return snolc_abi::STATUS_INVALID;
    };
    let (Some(name), Some(value)) = (unsafe { read_bytes(name) }, unsafe { read_bytes(value) })
    else {
        return snolc_abi::STATUS_INVALID;
    };
    if name.len() > 128 || value.len() > 4096 {
        return snolc_abi::STATUS_RESOURCE;
    }
    bridge
        .context
        .borrow_mut()
        .insert((session, name.to_vec()), value.to_vec());
    snolc_abi::STATUS_OK
}

unsafe fn read_bytes<'a>(bytes: snolc_abi::SnolBytes) -> Option<&'a [u8]> {
    if bytes.pointer.is_null() && bytes.length != 0 {
        return None;
    }
    if bytes.length == 0 {
        return Some(&[]);
    }
    // the caller guarantees readable borrowed bytes for the complete call.
    Some(unsafe { std::slice::from_raw_parts(bytes.pointer, bytes.length) })
}

#[derive(Debug, Error)]
pub enum EngineError {
    #[error(transparent)]
    Config(#[from] crate::config::ConfigError),
    #[error(transparent)]
    Module(#[from] LoadError),
    #[error("module instance {0} is duplicated")]
    DuplicateInstance(String),
    #[error("required module class mask {0:#x} is missing")]
    MissingModuleClass(u32),
    #[error("module config {path} does not resolve exactly once for class {class:#x}")]
    ModuleBinding { path: String, class: u32 },
    #[error("module instance {0} was not found")]
    InstanceNotFound(String),
    #[error("command queue is full or closed")]
    CommandQueue,
    #[error("engine stopped before acknowledging the command")]
    Stopped,
    #[error("event receiver was already taken")]
    EventReceiver,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wake_handle_retains_and_releases_arc() {
        let wake = Arc::new(WakeState {
            woken: AtomicBool::new(false),
        });
        let handle = wake_handle(&wake);
        assert_eq!(Arc::strong_count(&wake), 1);
        unsafe { handle.retain.unwrap()(handle.context) };
        assert_eq!(Arc::strong_count(&wake), 2);
        unsafe { handle.wake.unwrap()(handle.context) };
        assert!(wake.woken.load(Ordering::Acquire));
        unsafe { handle.release.unwrap()(handle.context) };
        assert_eq!(Arc::strong_count(&wake), 1);
    }
}
