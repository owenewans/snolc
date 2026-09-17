use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::env;
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

use crate::config::{
    Config, ControlConfig, LogLevel, LogSource, LoggingConfig, Role, YamuxConfig, parse_size,
};
use crate::control::{ControlError, UnixControlServer};
use crate::core_io::{MuxDatagramIo, RegisteredDatagramIo, RegisteredIo, is_registered};
use crate::events::{Event, EventReceiver, Lifecycle, PlatformEvent, Snapshot};
use crate::loader::{LoadError, LoadedModule, ModuleByteIo};
use crate::logging::{FileLogger, LogError};
use crate::mux::{MuxError, MuxSession};
use crate::stack::{
    FlowMetadata, PacketTcpPort, PacketUdpPort, SharedStackBridge, StackError, TcpStreamPort,
    UdpDatagramPort,
};
use crate::wire::{Destination, OpenRequest, OpenResponse, OpenStatus, StreamKind};

const HOST_EVENT_LIMIT: usize = 65_536;
const MODULE_POLL_INTERVAL: Duration = Duration::from_millis(10);
type ContextMap = HashMap<(u64, Vec<u8>), Vec<u8>>;

pub type ResponseFuture = Pin<Box<dyn Future<Output = Result<Vec<u8>, EngineError>> + Send>>;
type ControlSender = oneshot::Sender<Result<Vec<u8>, EngineError>>;

pub trait Host: Send + Sync + 'static {
    fn engine_event(&self, event: &Event);

    fn protect_socket(&self, _socket: i64) -> bool {
        !cfg!(target_os = "android")
    }
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
    adapters: Vec<usize>,
    carrier: usize,
    protection: usize,
    policy: usize,
    policy_family: String,
    policy_context: Vec<u8>,
    core_io_limit: usize,
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
    PolicyAttach(Box<PolicyAttachState>),
    Established(Box<EstablishedSession>),
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum TunnelUpdate {
    None,
    CarrierReady,
    Protected,
    PolicyOpen,
    Established,
}

type HandshakeFuture = Pin<Box<dyn Future<Output = Result<PendingPolicySession, MuxError>>>>;

struct PendingPolicySession {
    mux: MuxSession<ModuleByteIo>,
    policy_stream: yamux::Stream,
}

struct PolicyAttachState {
    mux: Option<MuxSession<ModuleByteIo>>,
    stream: Option<RegisteredIo>,
}

struct EstablishedSession {
    mux: Option<MuxSession<ModuleByteIo>>,
    policy_session: u64,
    accepting: Option<AcceptFlowFuture>,
    responding: Option<RespondFlowFuture>,
    opening: Option<OpenClientFuture>,
    pending: Option<PendingServerFlow>,
    client_pending: Option<PendingClientFlow>,
    active: Vec<ActiveServerFlow>,
    next_operation: u64,
}

type AcceptFlowFuture = Pin<
    Box<
        dyn Future<
            Output = (
                MuxSession<ModuleByteIo>,
                Result<(OpenRequest, yamux::Stream), MuxError>,
            ),
        >,
    >,
>;
type RespondFlowFuture = Pin<
    Box<
        dyn Future<
            Output = (
                MuxSession<ModuleByteIo>,
                yamux::Stream,
                Result<(), MuxError>,
            ),
        >,
    >,
>;
type OpenClientFuture = Pin<
    Box<
        dyn Future<
            Output = (
                MuxSession<ModuleByteIo>,
                Result<(OpenResponse, yamux::Stream), MuxError>,
            ),
        >,
    >,
>;

struct PendingServerFlow {
    request: OpenRequest,
    metadata: OwnedFlowMetadata,
    stream: Option<yamux::Stream>,
    operation: u64,
    admitted: bool,
    adapter_cursor: usize,
    resolved_addresses: Option<Vec<std::net::IpAddr>>,
    resolved_cursor: usize,
    resolution_complete: bool,
    adapter_flow: Option<(usize, u64)>,
    ports: Option<PendingPorts>,
    response_sent: bool,
    accepted: bool,
}

struct ActiveServerFlow {
    adapter_flow: Option<(usize, u64)>,
    mux_handle: u64,
}

struct PendingClientFlow {
    request: OpenRequest,
    metadata: OwnedFlowMetadata,
    adapter_flow: Option<(usize, u64)>,
    admitted: bool,
    policy_port: Option<ClientPolicyPort>,
}

enum PendingPorts {
    Tcp(TcpStreamPort, TcpStreamPort),
    Udp(UdpDatagramPort, UdpDatagramPort),
}

enum ClientPolicyPort {
    Tcp(TcpStreamPort),
    PacketTcp(PacketTcpPort),
    PacketUdp(PacketUdpPort),
    Udp(UdpDatagramPort),
}

struct OwnedFlowMetadata {
    kind: u32,
    address_type: u32,
    address: Vec<u8>,
    port: u16,
    opaque: Vec<u8>,
}

impl OwnedFlowMetadata {
    fn from_request(request: &OpenRequest) -> Self {
        let (address_type, address) = match &request.destination {
            Destination::Ipv4(address) => (snolc_abi::ADDRESS_IPV4, address.octets().to_vec()),
            Destination::Ipv6(address) => (snolc_abi::ADDRESS_IPV6, address.octets().to_vec()),
            Destination::Domain(address) => {
                (snolc_abi::ADDRESS_DOMAIN, address.as_bytes().to_vec())
            }
        };
        Self {
            kind: match request.kind {
                StreamKind::Tcp => snolc_abi::FLOW_TCP,
                StreamKind::Udp => snolc_abi::FLOW_UDP,
                StreamKind::Policy => 0,
            },
            address_type,
            address,
            port: request.port,
            opaque: request.metadata.clone(),
        }
    }

    fn abi(&self) -> snolc_abi::SnolFlowMetadataV1 {
        snolc_abi::SnolFlowMetadataV1 {
            struct_size: size_of::<snolc_abi::SnolFlowMetadataV1>() as u32,
            kind: self.kind,
            address_type: self.address_type,
            reserved: 0,
            address: snolc_abi::SnolBytes {
                pointer: self.address.as_ptr(),
                length: self.address.len(),
            },
            port: self.port,
            reserved2: [0; 6],
            metadata: snolc_abi::SnolBytes {
                pointer: self.opaque.as_ptr(),
                length: self.opaque.len(),
            },
        }
    }

    fn resolved(&self, address: std::net::IpAddr) -> Self {
        let (address_type, address) = match address {
            std::net::IpAddr::V4(address) => (snolc_abi::ADDRESS_IPV4, address.octets().to_vec()),
            std::net::IpAddr::V6(address) => (snolc_abi::ADDRESS_IPV6, address.octets().to_vec()),
        };
        Self {
            kind: self.kind,
            address_type,
            address,
            port: self.port,
            opaque: self.opaque.clone(),
        }
    }
}

pub struct Engine {
    validated: ValidatedConfig,
    host: Arc<dyn Host>,
    bridge: Box<HostBridge>,
    commands: mpsc::Receiver<Command>,
    events: mpsc::Sender<Event>,
    snapshot: Arc<AtomicSnapshot>,
    wake: Arc<WakeState>,
    logger: Option<EngineLogger>,
    log_errors: Arc<Mutex<VecDeque<String>>>,
    pending_controls: VecDeque<PendingControl>,
    control_server: Option<UnixControlServer>,
}

struct EngineLogger {
    file: FileLogger,
    levels: HashSet<LogLevel>,
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
    host: Arc<dyn Host>,
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
        response: ControlSender,
    },
    Shutdown {
        response: Option<oneshot::Sender<()>>,
    },
    Platform {
        event: PlatformEvent,
        response: Option<oneshot::Sender<()>>,
    },
}

struct PendingControl {
    module: usize,
    request: Vec<u8>,
    max_response: usize,
    response: ControlSender,
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
            let adapters = tunnel
                .adapters
                .iter()
                .map(|adapter| find_module(&modules, adapter, snolc_abi::CLASS_ADAPTER))
                .collect::<Result<Vec<_>, _>>()?;
            let protection =
                find_module(&modules, &tunnel.protection, snolc_abi::CLASS_PROTECTION)?;
            let carrier = find_module(&modules, &tunnel.carrier, snolc_abi::CLASS_CARRIER)?;
            let policy = find_module(&modules, &tunnel.policy, snolc_abi::CLASS_POLICY)?;
            let policy_context = channel_security_context(&modules[protection], tunnel.role)?;
            let core_io_limit = config
                .engine
                .max_flows
                .checked_mul(3)
                .and_then(|flows| config.engine.max_sessions.checked_add(flows))
                .ok_or(EngineError::ResourceOverflow)?;
            tunnels.push(TunnelBinding {
                name: tunnel.name.clone(),
                role: tunnel.role,
                adapters,
                carrier,
                protection,
                policy,
                policy_family: modules[policy].name().to_owned(),
                policy_context,
                core_io_limit,
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
        let log_errors = Arc::new(Mutex::new(VecDeque::new()));
        let logger = configure_logging(&validated.config.logging, Arc::clone(&log_errors))?;
        let control_server = match &validated.config.control {
            ControlConfig::Off => None,
            ControlConfig::Unix {
                path,
                max_request_bytes,
                max_connections,
            } => Some(UnixControlServer::bind(
                path,
                *max_request_bytes,
                *max_connections,
            )?),
        };
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
        let host: Arc<dyn Host> = Arc::new(host);
        let engine = Self {
            validated,
            host: Arc::clone(&host),
            bridge: Box::new(HostBridge {
                host,
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
            logger,
            log_errors,
            pending_controls: VecDeque::new(),
            control_server,
        };
        Ok((engine, handle))
    }

    pub fn run(self) -> Result<(), EngineError> {
        let executor = LocalExecutor::new();
        async_io::block_on(executor.run(self.run_loop()))
    }

    async fn run_loop(mut self) -> Result<(), EngineError> {
        self.emit(Event::Lifecycle(Lifecycle::Starting));
        let host_api = Box::new(self.host_api());
        for module in &mut self.validated.modules {
            if let Err(error) = module.create(&host_api) {
                self.snapshot
                    .lifecycle
                    .store(Lifecycle::Failed as u8, Ordering::Release);
                return Err(error.into());
            }
        }
        let stack = SharedStackBridge::new(
            self.validated.config.stack.clone(),
            self.validated.config.engine.max_flows,
            self.validated.config.engine.max_managed_bytes,
            self.validated.config.engine.max_ingress_packets_per_tick,
        )?;
        let adapters: HashSet<usize> = self
            .validated
            .tunnels
            .iter()
            .flat_map(|tunnel| tunnel.adapters.iter().copied())
            .collect();
        let packet_io_limit = self
            .validated
            .tunnels
            .iter()
            .map(|tunnel| tunnel.core_io_limit)
            .max()
            .unwrap_or(0)
            .checked_add(adapters.len())
            .ok_or(EngineError::ResourceOverflow)?;
        for adapter in adapters {
            let packet_port = RegisteredDatagramIo::register(stack.packet_port(), packet_io_limit)
                .map_err(|_| EngineError::CoreIo)?;
            let (packet_handle, packet_table) = packet_port.raw_parts();
            match unsafe {
                self.validated.modules[adapter]
                    .adapter_attach_packet_port(packet_handle, packet_table)
            } {
                Ok(()) => packet_port.transfer(),
                Err(LoadError::Unsupported) => {}
                Err(error) => return Err(error.into()),
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
                        match self.start_control(&instance, request, response) {
                            Ok(()) => self.poll_controls(),
                            Err((error, response)) => {
                                let _ = response.send(Err(error));
                            }
                        }
                    }
                    Some(Command::Shutdown { response }) => {
                        self.emit(Event::Lifecycle(Lifecycle::Stopping));
                        if let Some(response) = response {
                            let _ = response.send(());
                        }
                        break;
                    }
                    Some(Command::Platform { event, response }) => {
                        self.emit(Event::Platform(event));
                        match event {
                            PlatformEvent::NetworkChanged => {
                                for tunnel in &mut tunnels {
                                    tunnel.reset();
                                }
                                self.snapshot.sessions.store(0, Ordering::Release);
                                self.snapshot.flows.store(0, Ordering::Release);
                                if let Some(response) = response {
                                    let _ = response.send(());
                                }
                            }
                            PlatformEvent::VpnPermissionRevoked => {
                                self.emit(Event::Lifecycle(Lifecycle::Stopping));
                                if let Some(response) = response {
                                    let _ = response.send(());
                                }
                                break;
                            }
                        }
                    }
                    None => {
                        self.emit(Event::Lifecycle(Lifecycle::Stopping));
                        break;
                    }
                },
                _ = timer => {
                    stack.poll();
                    self.poll_modules();
                    self.poll_local_control();
                    self.poll_tunnels(&mut tunnels, &stack);
                    self.drain_module_events();
                    self.drain_log_errors();
                }
            }
        }

        drop(tunnels);
        self.snapshot.sessions.store(0, Ordering::Release);
        let mut errors = Vec::new();
        let shutdown_timeout =
            Duration::from_millis(self.validated.config.engine.shutdown_timeout_ms);
        let shutdown_deadline = Instant::now() + shutdown_timeout;
        let mut stopped = vec![false; self.validated.modules.len()];
        loop {
            let wake = wake_handle(&self.wake);
            for index in (0..self.validated.modules.len()).rev() {
                if stopped[index] {
                    continue;
                }
                let module = &mut self.validated.modules[index];
                match module.poll_shutdown() {
                    Poll::Ready(Ok(())) => stopped[index] = true,
                    Poll::Ready(Err(error)) => {
                        errors.push(Event::ModuleError {
                            instance: module.instance_name().to_owned(),
                            message: error.to_string(),
                        });
                        stopped[index] = true;
                    }
                    Poll::Pending => {
                        if let Err(error) = module.poll(wake) {
                            errors.push(Event::ModuleError {
                                instance: module.instance_name().to_owned(),
                                message: error.to_string(),
                            });
                            stopped[index] = true;
                        }
                    }
                }
            }
            if stopped.iter().all(|stopped| *stopped) {
                break;
            }
            if Instant::now() >= shutdown_deadline {
                for (index, module) in self.validated.modules.iter().enumerate() {
                    if !stopped[index] {
                        errors.push(Event::ModuleError {
                            instance: module.instance_name().to_owned(),
                            message: "module shutdown timed out".into(),
                        });
                    }
                }
                break;
            }
            async_io::Timer::after(MODULE_POLL_INTERVAL).await;
        }
        for event in errors {
            self.emit(event);
        }
        self.emit(Event::Lifecycle(Lifecycle::Stopped));
        Ok(())
    }

    fn start_control(
        &mut self,
        instance: &str,
        request: Vec<u8>,
        response: ControlSender,
    ) -> Result<(), (EngineError, ControlSender)> {
        let max_response = match &self.validated.config.control {
            ControlConfig::Off => 65_536,
            ControlConfig::Unix {
                max_request_bytes, ..
            } => *max_request_bytes,
        };
        let module = self
            .validated
            .modules
            .iter()
            .position(|module| module.instance_name() == instance);
        let Some(module) = module else {
            return Err((EngineError::InstanceNotFound(instance.to_owned()), response));
        };
        self.pending_controls.push_back(PendingControl {
            module,
            request,
            max_response,
            response,
        });
        Ok(())
    }

    fn poll_controls(&mut self) {
        let count = self.pending_controls.len();
        for _ in 0..count {
            let Some(control) = self.pending_controls.pop_front() else {
                break;
            };
            match self.validated.modules[control.module]
                .poll_control(&control.request, control.max_response)
            {
                Poll::Ready(result) => {
                    let _ = control.response.send(result.map_err(Into::into));
                }
                Poll::Pending => self.pending_controls.push_back(control),
            }
        }
    }

    fn poll_local_control(&mut self) {
        let requests = self
            .control_server
            .as_mut()
            .map(UnixControlServer::poll)
            .unwrap_or_default();
        for request in requests {
            let (sender, receiver) = oneshot::channel();
            match self.start_control(&request.instance, request.request, sender) {
                Ok(()) => {
                    if let Some(server) = &mut self.control_server {
                        server.wait_for(request.connection, receiver);
                    }
                }
                Err((error, sender)) => {
                    drop(sender);
                    if let Some(server) = &mut self.control_server {
                        server.reject(request.connection, &error);
                    }
                }
            }
        }
        self.poll_controls();
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

    fn poll_tunnels(&mut self, tunnels: &mut [TunnelRuntime], stack: &SharedStackBridge) {
        let mut established = 0;
        let mut closed = 0;
        let mut failures = Vec::new();
        let mut transitions = Vec::new();
        for tunnel in &mut *tunnels {
            match tunnel.poll(&self.validated.modules, stack) {
                Ok(update) => {
                    established += usize::from(update == TunnelUpdate::Established);
                    let state = match update {
                        TunnelUpdate::None => None,
                        TunnelUpdate::CarrierReady => Some("carrier-ready"),
                        TunnelUpdate::Protected => Some("protected"),
                        TunnelUpdate::PolicyOpen => Some("policy-open"),
                        TunnelUpdate::Established => Some("established"),
                    };
                    if let Some(state) = state {
                        transitions.push((tunnel.binding.name.clone(), state));
                    }
                }
                Err((message, was_established)) => {
                    closed += usize::from(was_established);
                    failures.push((tunnel.binding.name.clone(), message));
                }
            }
        }
        let flows = tunnels.iter().map(TunnelRuntime::flow_count).sum();
        self.snapshot.flows.store(flows, Ordering::Release);
        if established != 0 {
            self.snapshot
                .sessions
                .fetch_add(established, Ordering::Relaxed);
        }
        if closed != 0 {
            self.snapshot.sessions.fetch_sub(closed, Ordering::Relaxed);
        }
        for (name, state) in transitions {
            self.emit(Event::Tunnel { name, state });
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

    fn drain_log_errors(&mut self) {
        let errors: Vec<_> = match self.log_errors.lock() {
            Ok(mut errors) => errors.drain(..).collect(),
            Err(_) => return,
        };
        for message in errors {
            self.emit_unlogged(Event::ModuleError {
                instance: "logging".into(),
                message,
            });
        }
    }

    fn emit(&mut self, event: Event) {
        if let Event::Lifecycle(lifecycle) = event {
            self.snapshot
                .lifecycle
                .store(lifecycle as u8, Ordering::Release);
        }
        if let Some(logger) = &self.logger {
            let level = event_level(&event);
            if logger.levels.contains(&level) {
                logger.file.write(&format!("{event:?}"));
            }
        }
        self.emit_unlogged(event);
    }

    fn emit_unlogged(&mut self, event: Event) {
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
            protect_socket: Some(host_protect_socket),
        }
    }
}

fn configure_logging(
    config: &LoggingConfig,
    errors: Arc<Mutex<VecDeque<String>>>,
) -> Result<Option<EngineLogger>, EngineError> {
    let LoggingConfig::File {
        source,
        levels,
        file,
        limit,
        logs,
        queue_bytes,
        max_record_bytes,
        flush_interval_ms,
        ..
    } = config
    else {
        return Ok(None);
    };
    let (levels, file, limit) = match source {
        LogSource::Toml => (
            levels.clone().ok_or(EngineError::LoggingEnvironment)?,
            file.clone(),
            parse_size(limit)?,
        ),
        LogSource::Env => {
            let levels = env::var(logs.as_ref().ok_or(EngineError::LoggingEnvironment)?)
                .map_err(|_| EngineError::LoggingEnvironment)?;
            let file = env::var(file).map_err(|_| EngineError::LoggingEnvironment)?;
            let limit = env::var(limit).map_err(|_| EngineError::LoggingEnvironment)?;
            (parse_log_levels(&levels)?, file, parse_size(&limit)?)
        }
    };
    let levels: HashSet<_> = levels.into_iter().collect();
    let file = FileLogger::start(
        file.into(),
        limit,
        *queue_bytes,
        *max_record_bytes,
        Duration::from_millis(*flush_interval_ms),
        move |message| {
            if let Ok(mut errors) = errors.lock() {
                errors.push_back(message);
            }
        },
    )?;
    Ok(Some(EngineLogger { file, levels }))
}

fn parse_log_levels(input: &str) -> Result<Vec<LogLevel>, EngineError> {
    let mut levels = Vec::new();
    for level in input.split(',') {
        let level = match level.trim().to_ascii_lowercase().as_str() {
            "warning" => LogLevel::Warning,
            "error" => LogLevel::Error,
            "debug" => LogLevel::Debug,
            _ => return Err(EngineError::LoggingEnvironment),
        };
        if levels.contains(&level) {
            return Err(EngineError::LoggingEnvironment);
        }
        levels.push(level);
    }
    if levels.is_empty() {
        return Err(EngineError::LoggingEnvironment);
    }
    Ok(levels)
}

fn event_level(event: &Event) -> LogLevel {
    match event {
        Event::ModuleError { .. } | Event::Lifecycle(Lifecycle::Failed) => LogLevel::Error,
        Event::ResourceExhausted { .. } => LogLevel::Warning,
        _ => LogLevel::Debug,
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

fn channel_security_context(module: &LoadedModule, role: Role) -> Result<Vec<u8>, EngineError> {
    let description = module.describe()?;
    let description =
        std::str::from_utf8(&description).map_err(|_| EngineError::ModuleDescription)?;
    let description: toml::Value =
        toml::from_str(description).map_err(|_| EngineError::ModuleDescription)?;
    let confidentiality = description
        .get("confidentiality")
        .and_then(toml::Value::as_bool)
        .ok_or(EngineError::ModuleDescription)?;
    let integrity = description
        .get("integrity")
        .and_then(toml::Value::as_bool)
        .ok_or(EngineError::ModuleDescription)?;
    let authentication = match role {
        Role::Client => "server_authenticated",
        Role::Server => "client_authenticated",
    };
    let peer_authenticated = description
        .get(authentication)
        .and_then(toml::Value::as_bool)
        .ok_or(EngineError::ModuleDescription)?;
    let mut context = format!(
        "role = \"{}\"\nconfidentiality = {confidentiality}\nintegrity = {integrity}\npeer_authenticated = {peer_authenticated}\n",
        match role {
            Role::Client => "client",
            Role::Server => "server",
        }
    );
    if peer_authenticated {
        context.push_str("peer_identity = \"protection-peer\"\n");
    }
    Ok(context.into_bytes())
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

    fn poll(
        &mut self,
        modules: &[LoadedModule],
        stack: &SharedStackBridge,
    ) -> Result<TunnelUpdate, (String, bool)> {
        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            let stage = match &self.state {
                TunnelState::Carrier => "carrier",
                TunnelState::Protection(_) => "protection",
                TunnelState::Handshake(_) => "yamux policy handshake",
                TunnelState::PolicyAttach(_) => "policy attach",
                TunnelState::Established(_) => "established",
            };
            self.reset();
            return Err((
                format!("tunnel establishment timed out during {stage}"),
                false,
            ));
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
                        return Ok(TunnelUpdate::CarrierReady);
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
                            Ok(PendingPolicySession { mux, policy_stream })
                        }));
                        return Ok(TunnelUpdate::Protected);
                    }
                    Poll::Ready(Err(error)) => return self.fail(error.to_string(), false),
                    Poll::Pending => {}
                }
            }
            TunnelState::Handshake(handshake) => match handshake.as_mut().poll(&mut context) {
                Poll::Ready(Ok(session)) => {
                    let stream = match RegisteredIo::register(
                        session.policy_stream,
                        self.binding.core_io_limit,
                    ) {
                        Ok(stream) => stream,
                        Err(error) => return self.fail(error.to_string(), false),
                    };
                    self.state = TunnelState::PolicyAttach(Box::new(PolicyAttachState {
                        mux: Some(session.mux),
                        stream: Some(stream),
                    }));
                    return Ok(TunnelUpdate::PolicyOpen);
                }
                Poll::Ready(Err(error)) => return self.fail(error.to_string(), false),
                Poll::Pending => {}
            },
            TunnelState::PolicyAttach(state) => {
                let (stream, io) = match state.stream.as_ref() {
                    Some(stream) => stream.raw_parts(),
                    None => return self.fail("policy stream is unavailable".into(), false),
                };
                match modules[self.binding.policy].policy_attach_session(
                    stream,
                    io,
                    &self.binding.policy_context,
                    &mut context,
                ) {
                    Poll::Ready(Ok(policy_session)) => {
                        if let Some(stream) = state.stream.take() {
                            stream.transfer();
                        }
                        let mux = match state.mux.take() {
                            Some(mux) => mux,
                            None => return self.fail("yamux session is unavailable".into(), false),
                        };
                        self.state = TunnelState::Established(Box::new(EstablishedSession {
                            mux: Some(mux),
                            policy_session,
                            accepting: None,
                            responding: None,
                            opening: None,
                            pending: None,
                            client_pending: None,
                            active: Vec::new(),
                            next_operation: 1,
                        }));
                        self.deadline = None;
                        return Ok(TunnelUpdate::Established);
                    }
                    Poll::Ready(Err(error)) => return self.fail(error.to_string(), false),
                    Poll::Pending => {}
                }
            }
            TunnelState::Established(session) => {
                if let Err(error) = session.poll(&self.binding, modules, stack, &mut context) {
                    return self.fail(error.to_string(), true);
                }
            }
        }
        Ok(TunnelUpdate::None)
    }

    fn flow_count(&self) -> usize {
        match &self.state {
            TunnelState::Established(session) => session.active.len(),
            _ => 0,
        }
    }

    fn reset(&mut self) {
        self.state = TunnelState::Carrier;
        self.deadline = match self.binding.role {
            Role::Client => Some(Instant::now() + self.binding.connect_timeout),
            Role::Server => None,
        };
    }

    fn fail(
        &mut self,
        message: String,
        was_established: bool,
    ) -> Result<TunnelUpdate, (String, bool)> {
        self.reset();
        Err((message, was_established))
    }
}

impl EstablishedSession {
    fn poll(
        &mut self,
        binding: &TunnelBinding,
        modules: &[LoadedModule],
        stack: &SharedStackBridge,
        context: &mut Context<'_>,
    ) -> Result<(), SessionFlowError> {
        self.reap_closed(modules);

        if binding.role == Role::Client {
            return self.poll_client(binding, modules, stack, context);
        }

        if let Some(future) = &mut self.responding {
            if let Poll::Ready((mux, stream, result)) = future.as_mut().poll(context) {
                self.responding = None;
                self.mux = Some(mux);
                result?;
                let pending = self.pending.as_mut().ok_or(SessionFlowError::State)?;
                pending.stream = Some(stream);
                pending.response_sent = true;
                if !pending.accepted {
                    self.reject_pending(modules);
                    return Ok(());
                }
            } else {
                return Ok(());
            }
        }

        if self.pending.is_some() {
            self.poll_pending(binding, modules, stack, context)?;
            return Ok(());
        }

        if let Some(future) = &mut self.accepting {
            if let Poll::Ready((mux, result)) = future.as_mut().poll(context) {
                self.accepting = None;
                self.mux = Some(mux);
                let (request, stream) = result?;
                let operation = self.next_operation;
                self.next_operation = self
                    .next_operation
                    .checked_add(1)
                    .ok_or(SessionFlowError::Operation)?;
                self.pending = Some(PendingServerFlow {
                    metadata: OwnedFlowMetadata::from_request(&request),
                    request,
                    stream: Some(stream),
                    operation,
                    admitted: false,
                    adapter_cursor: 0,
                    resolved_addresses: None,
                    resolved_cursor: 0,
                    resolution_complete: false,
                    adapter_flow: None,
                    ports: None,
                    response_sent: false,
                    accepted: false,
                });
                self.poll_pending(binding, modules, stack, context)?;
            }
            return Ok(());
        }

        let mut mux = self.mux.take().ok_or(SessionFlowError::State)?;
        self.accepting = Some(Box::pin(async move {
            let result = mux.accept_flow().await;
            (mux, result)
        }));
        Ok(())
    }

    fn poll_client(
        &mut self,
        binding: &TunnelBinding,
        modules: &[LoadedModule],
        stack: &SharedStackBridge,
        context: &mut Context<'_>,
    ) -> Result<(), SessionFlowError> {
        if let Some(future) = &mut self.opening {
            if let Poll::Ready((mux, result)) = future.as_mut().poll(context) {
                self.opening = None;
                self.mux = Some(mux);
                let mut pending = self.client_pending.take().ok_or(SessionFlowError::State)?;
                match result {
                    Ok((response, stream)) if response.status == OpenStatus::Ok => {
                        let policy_port =
                            pending.policy_port.take().ok_or(SessionFlowError::State)?;
                        let mux_handle = match policy_port {
                            ClientPolicyPort::Tcp(policy_port) => {
                                let policy_io =
                                    RegisteredIo::register(policy_port, binding.core_io_limit)?;
                                let mux_io = RegisteredIo::register(stream, binding.core_io_limit)?;
                                let (policy_handle, policy_table) = policy_io.raw_parts();
                                let (mux_handle, mux_table) = mux_io.raw_parts();
                                unsafe {
                                    modules[binding.policy].policy_attach_flow(
                                        self.policy_session,
                                        policy_handle,
                                        policy_table,
                                        mux_handle,
                                        mux_table,
                                    )?;
                                }
                                policy_io.transfer();
                                mux_io.transfer();
                                mux_handle
                            }
                            ClientPolicyPort::PacketTcp(policy_port) => {
                                let policy_io =
                                    RegisteredIo::register(policy_port, binding.core_io_limit)?;
                                let mux_io = RegisteredIo::register(stream, binding.core_io_limit)?;
                                let (policy_handle, policy_table) = policy_io.raw_parts();
                                let (mux_handle, mux_table) = mux_io.raw_parts();
                                unsafe {
                                    modules[binding.policy].policy_attach_flow(
                                        self.policy_session,
                                        policy_handle,
                                        policy_table,
                                        mux_handle,
                                        mux_table,
                                    )?;
                                }
                                policy_io.transfer();
                                mux_io.transfer();
                                mux_handle
                            }
                            ClientPolicyPort::Udp(policy_port) => {
                                let policy_io = RegisteredDatagramIo::register(
                                    policy_port,
                                    binding.core_io_limit,
                                )?;
                                let mux_io = RegisteredDatagramIo::register(
                                    MuxDatagramIo::new(stream),
                                    binding.core_io_limit,
                                )?;
                                let (policy_handle, policy_table) = policy_io.raw_parts();
                                let (mux_handle, mux_table) = mux_io.raw_parts();
                                unsafe {
                                    modules[binding.policy].policy_attach_datagram_flow(
                                        self.policy_session,
                                        policy_handle,
                                        policy_table,
                                        mux_handle,
                                        mux_table,
                                    )?;
                                }
                                policy_io.transfer();
                                mux_io.transfer();
                                mux_handle
                            }
                            ClientPolicyPort::PacketUdp(policy_port) => {
                                let policy_io = RegisteredDatagramIo::register(
                                    policy_port,
                                    binding.core_io_limit,
                                )?;
                                let mux_io = RegisteredDatagramIo::register(
                                    MuxDatagramIo::new(stream),
                                    binding.core_io_limit,
                                )?;
                                let (policy_handle, policy_table) = policy_io.raw_parts();
                                let (mux_handle, mux_table) = mux_io.raw_parts();
                                unsafe {
                                    modules[binding.policy].policy_attach_datagram_flow(
                                        self.policy_session,
                                        policy_handle,
                                        policy_table,
                                        mux_handle,
                                        mux_table,
                                    )?;
                                }
                                policy_io.transfer();
                                mux_io.transfer();
                                mux_handle
                            }
                        };
                        if let Some((adapter, flow)) = pending.adapter_flow {
                            modules[adapter].adapter_complete_flow(
                                flow,
                                snolc_abi::STATUS_OK,
                                &[],
                            )?;
                        }
                        self.active.push(ActiveServerFlow {
                            adapter_flow: pending.adapter_flow,
                            mux_handle,
                        });
                    }
                    Ok((response, _)) => {
                        if let Some((adapter, flow)) = pending.adapter_flow {
                            modules[adapter].adapter_complete_flow(
                                flow,
                                abi_status(response.status),
                                response.reason.as_bytes(),
                            )?;
                        }
                        if let Some(mux) = &mut self.mux {
                            mux.release_flow();
                        }
                    }
                    Err(error) => {
                        if let Some((adapter, flow)) = pending.adapter_flow {
                            let _ = modules[adapter].adapter_complete_flow(
                                flow,
                                snolc_abi::STATUS_IO,
                                b"tunnel stream failed",
                            );
                        }
                        return Err(error.into());
                    }
                }
            }
            return Ok(());
        }

        if self.client_pending.is_none()
            && binding
                .adapters
                .iter()
                .copied()
                .any(|adapter| modules[adapter].supports_packet_port())
            && let Some((metadata, policy_port)) = stack.accept_packet_tcp()?
        {
            let request = OpenRequest {
                kind: StreamKind::Tcp,
                destination: metadata.destination,
                port: metadata.port,
                metadata: metadata.opaque,
            };
            self.client_pending = Some(PendingClientFlow {
                metadata: OwnedFlowMetadata::from_request(&request),
                request,
                adapter_flow: None,
                admitted: false,
                policy_port: Some(ClientPolicyPort::PacketTcp(policy_port)),
            });
        }

        if self.client_pending.is_none()
            && binding
                .adapters
                .iter()
                .copied()
                .any(|adapter| modules[adapter].supports_packet_port())
            && let Some((metadata, policy_port)) = stack.accept_packet_udp()?
        {
            let request = OpenRequest {
                kind: StreamKind::Udp,
                destination: metadata.destination,
                port: metadata.port,
                metadata: metadata.opaque,
            };
            self.client_pending = Some(PendingClientFlow {
                metadata: OwnedFlowMetadata::from_request(&request),
                request,
                adapter_flow: None,
                admitted: false,
                policy_port: Some(ClientPolicyPort::PacketUdp(policy_port)),
            });
        }

        if self.client_pending.is_none() {
            for adapter in &binding.adapters {
                match modules[*adapter].adapter_accept(context) {
                    Poll::Ready(Ok((adapter_flow, request))) => {
                        self.client_pending = Some(PendingClientFlow {
                            metadata: OwnedFlowMetadata::from_request(&request),
                            request,
                            adapter_flow: Some((*adapter, adapter_flow)),
                            admitted: false,
                            policy_port: None,
                        });
                        break;
                    }
                    Poll::Ready(Err(LoadError::ModuleStatus(snolc_abi::STATUS_UNSUPPORTED)))
                    | Poll::Pending => {}
                    Poll::Ready(Err(error)) => return Err(error.into()),
                }
            }
        }

        let Some(pending) = self.client_pending.as_mut() else {
            if let Some(mux) = &mut self.mux
                && let Poll::Ready(Err(error)) = mux.poll_drive(context)
            {
                return Err(error.into());
            }
            return Ok(());
        };
        if !pending.admitted {
            let metadata = pending.metadata.abi();
            match modules[binding.policy].policy_admit_flow(self.policy_session, &metadata, context)
            {
                Poll::Ready(Ok(())) => pending.admitted = true,
                Poll::Ready(Err(error)) => {
                    let (status, reason) = open_error(&error);
                    if let Some((adapter, flow)) = pending.adapter_flow {
                        modules[adapter].adapter_complete_flow(
                            flow,
                            abi_status(status),
                            reason.as_bytes(),
                        )?;
                    }
                    self.client_pending = None;
                    return Ok(());
                }
                Poll::Pending => return Ok(()),
            }
        }
        if pending.policy_port.is_none() {
            let (adapter, adapter_flow) = pending.adapter_flow.ok_or(SessionFlowError::State)?;
            let metadata = FlowMetadata {
                destination: pending.request.destination.clone(),
                port: pending.request.port,
                opaque: pending.request.metadata.clone(),
            };
            pending.policy_port = Some(match pending.request.kind {
                StreamKind::Tcp => {
                    let (adapter_port, policy_port) = stack.open_tcp(metadata)?;
                    let adapter_io = RegisteredIo::register(adapter_port, binding.core_io_limit)?;
                    let (adapter_handle, adapter_table) = adapter_io.raw_parts();
                    unsafe {
                        modules[adapter].adapter_attach_flow(
                            adapter_flow,
                            adapter_handle,
                            adapter_table,
                        )?;
                    }
                    adapter_io.transfer();
                    ClientPolicyPort::Tcp(policy_port)
                }
                StreamKind::Udp => {
                    let (adapter_port, policy_port) = stack.open_udp(metadata)?;
                    let adapter_io =
                        RegisteredDatagramIo::register(adapter_port, binding.core_io_limit)?;
                    let (adapter_handle, adapter_table) = adapter_io.raw_parts();
                    unsafe {
                        modules[adapter].adapter_attach_datagram(
                            adapter_flow,
                            adapter_handle,
                            adapter_table,
                        )?;
                    }
                    adapter_io.transfer();
                    ClientPolicyPort::Udp(policy_port)
                }
                StreamKind::Policy => return Err(SessionFlowError::State),
            });
        }
        let request = pending.request.clone();
        let mut mux = self.mux.take().ok_or(SessionFlowError::State)?;
        self.opening = Some(Box::pin(async move {
            let result = mux.open_flow_confirmed(&request).await;
            (mux, result)
        }));
        Ok(())
    }

    fn poll_pending(
        &mut self,
        binding: &TunnelBinding,
        modules: &[LoadedModule],
        stack: &SharedStackBridge,
        context: &mut Context<'_>,
    ) -> Result<(), SessionFlowError> {
        let pending = self.pending.as_mut().ok_or(SessionFlowError::State)?;
        if pending.response_sent {
            return self.attach_pending(binding, modules);
        }
        let metadata = pending.metadata.abi();
        if !pending.admitted {
            match modules[binding.policy].policy_admit_flow(self.policy_session, &metadata, context)
            {
                Poll::Ready(Ok(())) => pending.admitted = true,
                Poll::Ready(Err(error)) => {
                    let (status, reason) = open_error(&error);
                    return self.start_response(status, reason);
                }
                Poll::Pending => return Ok(()),
            }
        }
        if pending.adapter_cursor >= binding.adapters.len() {
            return self.start_response(OpenStatus::Unsupported, "no adapter accepted the flow");
        }
        let adapter = binding.adapters[pending.adapter_cursor];
        if !pending.resolution_complete {
            if pending.resolved_addresses.is_none() {
                match modules[adapter].adapter_resolve(pending.operation, &metadata, context) {
                    Poll::Ready(Ok(Some(addresses))) => {
                        pending.resolved_addresses = Some(addresses);
                    }
                    Poll::Ready(Ok(None)) => pending.resolution_complete = true,
                    Poll::Ready(Err(error)) => {
                        let (status, reason) = open_error(&error);
                        return self.start_response(status, reason);
                    }
                    Poll::Pending => return Ok(()),
                }
            }
            if let Some(addresses) = &pending.resolved_addresses {
                if let Some(address) = addresses.get(pending.resolved_cursor).copied() {
                    let resolved = pending.metadata.resolved(address);
                    match modules[binding.policy].policy_admit_resolved(
                        self.policy_session,
                        &resolved.abi(),
                        context,
                    ) {
                        Poll::Ready(Ok(())) => pending.resolved_cursor += 1,
                        Poll::Ready(Err(error)) => {
                            let (status, reason) = open_error(&error);
                            return self.start_response(status, reason);
                        }
                        Poll::Pending => return Ok(()),
                    }
                }
                if pending.resolved_cursor >= addresses.len() {
                    pending.resolution_complete = true;
                } else {
                    return Ok(());
                }
            }
        }
        match modules[adapter].adapter_open(pending.operation, &metadata, context) {
            Poll::Ready(Ok(flow)) => {
                pending.adapter_flow = Some((adapter, flow));
                let metadata = FlowMetadata {
                    destination: pending.request.destination.clone(),
                    port: pending.request.port,
                    opaque: pending.request.metadata.clone(),
                };
                let ports = match pending.request.kind {
                    StreamKind::Tcp => stack
                        .open_tcp(metadata)
                        .map(|(adapter, policy)| PendingPorts::Tcp(adapter, policy)),
                    StreamKind::Udp => stack
                        .open_udp(metadata)
                        .map(|(adapter, policy)| PendingPorts::Udp(adapter, policy)),
                    StreamKind::Policy => Err(StackError::Metadata),
                };
                match ports {
                    Ok(ports) => pending.ports = Some(ports),
                    Err(_) => {
                        return self.start_response(
                            OpenStatus::ResourceLimit,
                            "stack flow budget exhausted",
                        );
                    }
                }
                self.start_response(OpenStatus::Ok, "")
            }
            Poll::Ready(Err(LoadError::ModuleStatus(snolc_abi::STATUS_UNSUPPORTED)))
                if pending.adapter_cursor + 1 < binding.adapters.len() =>
            {
                pending.adapter_cursor += 1;
                pending.resolved_addresses = None;
                pending.resolved_cursor = 0;
                pending.resolution_complete = false;
                Ok(())
            }
            Poll::Ready(Err(error)) => {
                let (status, reason) = open_error(&error);
                self.start_response(status, reason)
            }
            Poll::Pending => Ok(()),
        }
    }

    fn start_response(
        &mut self,
        status: OpenStatus,
        reason: &'static str,
    ) -> Result<(), SessionFlowError> {
        let pending = self.pending.as_mut().ok_or(SessionFlowError::State)?;
        pending.accepted = status == OpenStatus::Ok;
        let mut stream = pending.stream.take().ok_or(SessionFlowError::State)?;
        let mut mux = self.mux.take().ok_or(SessionFlowError::State)?;
        let response = OpenResponse {
            status,
            reason: reason.to_owned(),
        };
        self.responding = Some(Box::pin(async move {
            let result = mux.respond_flow(&mut stream, &response).await;
            (mux, stream, result)
        }));
        Ok(())
    }

    fn attach_pending(
        &mut self,
        binding: &TunnelBinding,
        modules: &[LoadedModule],
    ) -> Result<(), SessionFlowError> {
        let mut pending = self.pending.take().ok_or(SessionFlowError::State)?;
        let (adapter, adapter_flow) = pending.adapter_flow.ok_or(SessionFlowError::State)?;
        let ports = pending.ports.take().ok_or(SessionFlowError::State)?;
        let stream = pending.stream.take().ok_or(SessionFlowError::State)?;
        let mux_handle = match ports {
            PendingPorts::Tcp(adapter_port, policy_port) => {
                let adapter_io = RegisteredIo::register(adapter_port, binding.core_io_limit)?;
                let policy_io = RegisteredIo::register(policy_port, binding.core_io_limit)?;
                let mux_io = RegisteredIo::register(stream, binding.core_io_limit)?;
                let (adapter_handle, adapter_table) = adapter_io.raw_parts();
                let (policy_handle, policy_table) = policy_io.raw_parts();
                let (mux_handle, mux_table) = mux_io.raw_parts();
                unsafe {
                    modules[adapter].adapter_attach_flow(
                        adapter_flow,
                        adapter_handle,
                        adapter_table,
                    )?;
                    modules[binding.policy].policy_attach_flow(
                        self.policy_session,
                        policy_handle,
                        policy_table,
                        mux_handle,
                        mux_table,
                    )?;
                }
                adapter_io.transfer();
                policy_io.transfer();
                mux_io.transfer();
                mux_handle
            }
            PendingPorts::Udp(adapter_port, policy_port) => {
                let adapter_io =
                    RegisteredDatagramIo::register(adapter_port, binding.core_io_limit)?;
                let policy_io = RegisteredDatagramIo::register(policy_port, binding.core_io_limit)?;
                let mux_io = RegisteredDatagramIo::register(
                    MuxDatagramIo::new(stream),
                    binding.core_io_limit,
                )?;
                let (adapter_handle, adapter_table) = adapter_io.raw_parts();
                let (policy_handle, policy_table) = policy_io.raw_parts();
                let (mux_handle, mux_table) = mux_io.raw_parts();
                unsafe {
                    modules[adapter].adapter_attach_datagram(
                        adapter_flow,
                        adapter_handle,
                        adapter_table,
                    )?;
                    modules[binding.policy].policy_attach_datagram_flow(
                        self.policy_session,
                        policy_handle,
                        policy_table,
                        mux_handle,
                        mux_table,
                    )?;
                }
                adapter_io.transfer();
                policy_io.transfer();
                mux_io.transfer();
                mux_handle
            }
        };
        modules[adapter].adapter_complete_flow(adapter_flow, snolc_abi::STATUS_OK, &[])?;
        self.active.push(ActiveServerFlow {
            adapter_flow: Some((adapter, adapter_flow)),
            mux_handle,
        });
        Ok(())
    }

    fn reject_pending(&mut self, modules: &[LoadedModule]) {
        if let Some(mut pending) = self.pending.take() {
            if let Some((adapter, flow)) = pending.adapter_flow.take() {
                let _ = modules[adapter].adapter_close_flow(flow);
            }
            if let Some(mux) = &mut self.mux {
                mux.release_flow();
            }
        }
    }

    fn reap_closed(&mut self, modules: &[LoadedModule]) {
        let mut closed = Vec::new();
        self.active.retain(|flow| {
            if is_registered(flow.mux_handle) {
                true
            } else {
                if let Some(adapter_flow) = flow.adapter_flow {
                    closed.push(adapter_flow);
                }
                false
            }
        });
        if let Some(mux) = &mut self.mux {
            for (adapter, flow) in closed {
                let _ = modules[adapter].adapter_close_flow(flow);
                mux.release_flow();
            }
        }
    }
}

fn open_error(error: &LoadError) -> (OpenStatus, &'static str) {
    match error {
        LoadError::ModuleStatus(snolc_abi::STATUS_DENIED) => (OpenStatus::Denied, "flow denied"),
        LoadError::ModuleStatus(snolc_abi::STATUS_UNSUPPORTED) => {
            (OpenStatus::Unsupported, "flow unsupported")
        }
        LoadError::ModuleStatus(snolc_abi::STATUS_RESOURCE) => {
            (OpenStatus::ResourceLimit, "flow resource limit")
        }
        LoadError::ModuleStatus(snolc_abi::STATUS_IO) => {
            (OpenStatus::ConnectFailed, "endpoint connect failed")
        }
        LoadError::ModuleStatus(snolc_abi::STATUS_INVALID) => {
            (OpenStatus::ProtocolError, "invalid flow metadata")
        }
        _ => (OpenStatus::InternalError, "flow setup failed"),
    }
}

fn abi_status(status: OpenStatus) -> u32 {
    match status {
        OpenStatus::Ok => snolc_abi::STATUS_OK,
        OpenStatus::Denied => snolc_abi::STATUS_DENIED,
        OpenStatus::Unsupported => snolc_abi::STATUS_UNSUPPORTED,
        OpenStatus::ResourceLimit => snolc_abi::STATUS_RESOURCE,
        OpenStatus::ConnectFailed => snolc_abi::STATUS_IO,
        OpenStatus::ProtocolError => snolc_abi::STATUS_INVALID,
        OpenStatus::InternalError => snolc_abi::STATUS_INTERNAL,
    }
}

#[derive(Debug, Error)]
enum SessionFlowError {
    #[error(transparent)]
    Mux(#[from] MuxError),
    #[error(transparent)]
    Module(#[from] LoadError),
    #[error(transparent)]
    CoreIo(#[from] crate::core_io::CoreIoError),
    #[error(transparent)]
    Stack(#[from] StackError),
    #[error("flow state is inconsistent")]
    State,
    #[error("flow operation handle exhausted")]
    Operation,
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
                response: Some(response_tx),
            })
            .map_err(|_| EngineError::CommandQueue)?;
        async_io::block_on(response_rx).map_err(|_| EngineError::Stopped)
    }

    pub fn request_shutdown(&self) -> Result<(), EngineError> {
        let mut commands = self.commands.clone();
        commands
            .try_send(Command::Shutdown { response: None })
            .map_err(|_| EngineError::CommandQueue)
    }

    pub fn platform_event(&self, event: PlatformEvent) -> Result<(), EngineError> {
        let (response_tx, response_rx) = oneshot::channel();
        let mut commands = self.commands.clone();
        commands
            .try_send(Command::Platform {
                event,
                response: Some(response_tx),
            })
            .map_err(|_| EngineError::CommandQueue)?;
        async_io::block_on(response_rx).map_err(|_| EngineError::Stopped)
    }

    pub fn request_platform_event(&self, event: PlatformEvent) -> Result<(), EngineError> {
        let mut commands = self.commands.clone();
        commands
            .try_send(Command::Platform {
                event,
                response: None,
            })
            .map_err(|_| EngineError::CommandQueue)
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

unsafe extern "C" fn host_protect_socket(context: *mut c_void, socket: i64) -> u32 {
    let Some(bridge) = (unsafe { (context as *const HostBridge).as_ref() }) else {
        return snolc_abi::STATUS_INVALID;
    };
    if socket < 0 {
        return snolc_abi::STATUS_INVALID;
    }
    if bridge.host.protect_socket(socket) {
        snolc_abi::STATUS_OK
    } else {
        snolc_abi::STATUS_DENIED
    }
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
    #[error(transparent)]
    Stack(#[from] StackError),
    #[error("core I/O registry is exhausted")]
    CoreIo,
    #[error("module instance {0} is duplicated")]
    DuplicateInstance(String),
    #[error("required module class mask {0:#x} is missing")]
    MissingModuleClass(u32),
    #[error("module config {path} does not resolve exactly once for class {class:#x}")]
    ModuleBinding { path: String, class: u32 },
    #[error("module description is missing required security capabilities")]
    ModuleDescription,
    #[error("engine resource arithmetic overflow")]
    ResourceOverflow,
    #[error(transparent)]
    Logging(#[from] LogError),
    #[error(transparent)]
    Control(#[from] ControlError),
    #[error("logging environment is missing or invalid")]
    LoggingEnvironment,
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

    #[test]
    fn environment_log_levels_are_strict_and_unique() {
        assert_eq!(
            parse_log_levels("warning,error,debug").unwrap(),
            [LogLevel::Warning, LogLevel::Error, LogLevel::Debug]
        );
        assert!(parse_log_levels("debug,debug").is_err());
        assert!(parse_log_levels("info").is_err());
        assert!(parse_log_levels("").is_err());
    }
}
