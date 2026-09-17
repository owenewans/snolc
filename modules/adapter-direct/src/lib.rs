#![deny(unsafe_op_in_unsafe_fn)]

use std::cell::RefCell;
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket,
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, TrySendError, sync_channel};
use std::task::{Context, Poll, Waker};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde::Deserialize;
use snolc_sdk::abi::{
    self, SnolAdapterApiV1, SnolByteIoV1, SnolBytes, SnolDatagramIoV1, SnolWakeHandle,
};
use snolc_sdk::{
    ByteIo, DatagramIo, DatagramPump, DatagramRecv, ForeignByteIo, ForeignDatagramIo, Pump,
};

const MAX_UDP_PAYLOAD: usize = 65_507;

pub trait SocketProtector: Send + Sync {
    fn protect(&self, socket: &TcpStream) -> io::Result<()>;
}

pub struct NoopProtector;

impl SocketProtector for NoopProtector {
    fn protect(&self, _socket: &TcpStream) -> io::Result<()> {
        Ok(())
    }
}

struct Request {
    generation: u64,
    domain: String,
    port: u16,
    response: SyncSender<Response>,
}

struct Response {
    generation: u64,
    result: io::Result<Vec<SocketAddr>>,
}

pub struct SystemResolver {
    sender: Option<SyncSender<Request>>,
    worker: Option<JoinHandle<()>>,
    generation: AtomicU64,
}

impl SystemResolver {
    pub fn new(queue_capacity: usize) -> Result<Self, DirectError> {
        if queue_capacity == 0 {
            return Err(DirectError::InvalidConfig);
        }
        let (sender, receiver) = sync_channel(queue_capacity);
        let worker = thread::Builder::new()
            .name("snolc-dns".into())
            .spawn(move || resolver_worker(receiver))?;
        Ok(Self {
            sender: Some(sender),
            worker: Some(worker),
            generation: AtomicU64::new(1),
        })
    }

    pub fn resolve(
        &self,
        domain: &str,
        port: u16,
        timeout: Duration,
    ) -> Result<Vec<SocketAddr>, DirectError> {
        if domain.is_empty() || port == 0 || timeout.is_zero() {
            return Err(DirectError::InvalidDestination);
        }
        let generation = self.generation.fetch_add(1, Ordering::Relaxed);
        if generation == 0 {
            return Err(DirectError::Resource);
        }
        let (response_tx, response_rx) = sync_channel(1);
        self.sender
            .as_ref()
            .ok_or(DirectError::Stopped)?
            .try_send(Request {
                generation,
                domain: domain.to_owned(),
                port,
                response: response_tx,
            })
            .map_err(|_| DirectError::Resource)?;
        let response = response_rx
            .recv_timeout(timeout)
            .map_err(|_| DirectError::Timeout)?;
        if response.generation != generation {
            return Err(DirectError::Stale);
        }
        let mut addresses = response.result?;
        addresses.sort_unstable();
        addresses.dedup();
        if addresses.is_empty() {
            return Err(DirectError::NoAddress);
        }
        Ok(addresses)
    }
}

impl Drop for SystemResolver {
    fn drop(&mut self) {
        self.sender.take();
        self.worker.take();
    }
}

pub fn connect_domain(
    resolver: &SystemResolver,
    domain: &str,
    port: u16,
    timeout: Duration,
    allowed: impl Fn(IpAddr) -> bool,
    protector: &dyn SocketProtector,
) -> Result<TcpStream, DirectError> {
    let addresses = resolver.resolve(domain, port, timeout)?;
    if !addresses.iter().all(|address| allowed(address.ip())) {
        return Err(DirectError::Denied);
    }
    let mut last_error = None;
    for address in addresses {
        match TcpStream::connect_timeout(&address, timeout) {
            Ok(stream) => {
                protector.protect(&stream)?;
                return Ok(stream);
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.map_or(DirectError::NoAddress, DirectError::Io))
}

fn resolver_worker(receiver: Receiver<Request>) {
    while let Ok(request) = receiver.recv() {
        let result = (request.domain.as_str(), request.port)
            .to_socket_addrs()
            .map(|addresses| addresses.collect());
        let _ = request.response.send(Response {
            generation: request.generation,
            result,
        });
    }
}

#[derive(Debug)]
pub enum DirectError {
    InvalidConfig,
    InvalidDestination,
    Resource,
    Timeout,
    Stale,
    Stopped,
    NoAddress,
    Denied,
    Io(io::Error),
}

impl From<io::Error> for DirectError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum DnsMode {
    System,
    RejectDomains,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Options {
    dns_mode: DnsMode,
    max_pending_opens: usize,
    resolve_timeout_ms: u64,
    connect_timeout_ms: u64,
}

fn validate_config(config: &[u8], _base: &[u8]) -> Result<(), String> {
    parse_options(config).map(|_| ())
}

fn parse_options(config: &[u8]) -> Result<Options, String> {
    let text = std::str::from_utf8(config).map_err(|_| "config is not UTF-8".to_owned())?;
    let options: Options = toml::from_str(text).map_err(|error| error.to_string())?;
    if options.max_pending_opens == 0
        || options.resolve_timeout_ms == 0
        || options.connect_timeout_ms == 0
    {
        return Err("direct adapter options are inconsistent".into());
    }
    Ok(options)
}

enum Destination {
    Ip(SocketAddr),
    Domain(String, u16),
}

struct ConnectRequest {
    kind: u32,
    destination: Destination,
    dns_mode: DnsMode,
    resolve_timeout: Duration,
    connect_timeout: Duration,
    response: SyncSender<Result<Endpoint, DirectError>>,
    wake: WorkerWake,
}

struct WorkerWake(SnolWakeHandle);

unsafe impl Send for WorkerWake {}

impl WorkerWake {
    fn wake(&self) {
        if let Some(wake) = self.0.wake {
            unsafe { wake(self.0.context) };
        }
    }
}

struct PendingOpen {
    response: Receiver<Result<Endpoint, DirectError>>,
    retained_wake: Option<SnolWakeHandle>,
}

impl Drop for PendingOpen {
    fn drop(&mut self) {
        if let Some(wake) = self.retained_wake
            && let Some(release) = wake.release
        {
            unsafe { release(wake.context) };
        }
    }
}

struct State {
    options: Options,
    sender: Option<SyncSender<ConnectRequest>>,
    worker: Option<JoinHandle<()>>,
    pending: HashMap<u64, PendingOpen>,
    ready: HashMap<u64, Endpoint>,
    active: HashMap<u64, DirectFlow<ForeignByteIo>>,
    active_datagrams: HashMap<u64, DirectDatagramFlow<ForeignDatagramIo>>,
}

enum Endpoint {
    Tcp(TcpStream),
    Udp(UdpSocket),
}

impl Drop for State {
    fn drop(&mut self) {
        self.sender.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

struct TcpIo(TcpStream);

impl ByteIo for TcpIo {
    fn poll_read(
        &mut self,
        _context: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        map_nonblocking(self.0.read(output))
    }

    fn poll_write(&mut self, _context: &mut Context<'_>, input: &[u8]) -> Poll<io::Result<usize>> {
        map_nonblocking(self.0.write(input))
    }

    fn poll_flush(&mut self, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        map_nonblocking(self.0.flush())
    }

    fn poll_shutdown_write(&mut self, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(self.0.shutdown(Shutdown::Write))
    }

    fn close(&mut self) -> io::Result<()> {
        self.0.shutdown(Shutdown::Both)
    }
}

fn map_nonblocking<T>(result: io::Result<T>) -> Poll<io::Result<T>> {
    match result {
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
        result => Poll::Ready(result),
    }
}

struct DirectFlow<S> {
    stack: S,
    endpoint: TcpIo,
    upload: Pump,
    download: Pump,
}

struct UdpIo {
    socket: UdpSocket,
    buffer: Vec<u8>,
    pending: Option<usize>,
}

impl DatagramIo for UdpIo {
    fn poll_recv_datagram(
        &mut self,
        _context: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<io::Result<DatagramRecv>> {
        if self.pending.is_none() {
            match self.socket.recv(&mut self.buffer) {
                Ok(length) => self.pending = Some(length),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
                Err(error) => return Poll::Ready(Err(error)),
            }
        }
        let length = self.pending.expect("set above");
        if output.len() < length {
            return Poll::Ready(Ok(DatagramRecv::BufferTooSmall(length)));
        }
        output[..length].copy_from_slice(&self.buffer[..length]);
        self.pending = None;
        Poll::Ready(Ok(DatagramRecv::Datagram(length)))
    }

    fn poll_send_datagram(
        &mut self,
        _context: &mut Context<'_>,
        datagram: &[u8],
    ) -> Poll<io::Result<()>> {
        match self.socket.send(datagram) {
            Ok(length) if length == datagram.len() => Poll::Ready(Ok(())),
            Ok(_) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "UDP socket accepted a partial datagram",
            ))),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            Err(error) => Poll::Ready(Err(error)),
        }
    }

    fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct DirectDatagramFlow<S> {
    stack: S,
    endpoint: UdpIo,
    upload: DatagramPump,
    download: DatagramPump,
}

impl<S: DatagramIo> DirectDatagramFlow<S> {
    fn new(stack: S, socket: UdpSocket) -> Result<Self, DirectError> {
        socket.set_nonblocking(true)?;
        Ok(Self {
            stack,
            endpoint: UdpIo {
                socket,
                buffer: vec![0; MAX_UDP_PAYLOAD],
                pending: None,
            },
            upload: DatagramPump::new(MAX_UDP_PAYLOAD).map_err(|_| DirectError::Resource)?,
            download: DatagramPump::new(MAX_UDP_PAYLOAD).map_err(|_| DirectError::Resource)?,
        })
    }

    fn poll(&mut self, context: &mut Context<'_>) -> Poll<Result<bool, DirectError>> {
        let upload = self
            .upload
            .poll(
                context,
                &mut self.stack,
                &mut self.endpoint,
                MAX_UDP_PAYLOAD,
            )
            .map_err(|error| DirectError::Io(io::Error::other(error.to_string())));
        let download = self
            .download
            .poll(
                context,
                &mut self.endpoint,
                &mut self.stack,
                MAX_UDP_PAYLOAD,
            )
            .map_err(|error| DirectError::Io(io::Error::other(error.to_string())));
        match (upload, download) {
            (Poll::Ready(Ok(upload)), Poll::Ready(Ok(download))) => {
                Poll::Ready(Ok(upload.finished && download.finished))
            }
            (Poll::Ready(Err(error)), _) | (_, Poll::Ready(Err(error))) => Poll::Ready(Err(error)),
            _ => Poll::Pending,
        }
    }
}

impl<S: ByteIo> DirectFlow<S> {
    fn new(stack: S, endpoint: TcpStream) -> Result<Self, DirectError> {
        endpoint.set_nonblocking(true)?;
        Ok(Self {
            stack,
            endpoint: TcpIo(endpoint),
            upload: Pump::new(16_384).map_err(|_| DirectError::Resource)?,
            download: Pump::new(16_384).map_err(|_| DirectError::Resource)?,
        })
    }

    fn poll(&mut self, context: &mut Context<'_>) -> Poll<Result<bool, DirectError>> {
        let upload = self
            .upload
            .poll(context, &mut self.stack, &mut self.endpoint, 16_384)
            .map_err(|error| DirectError::Io(io::Error::other(error.to_string())));
        let download = self
            .download
            .poll(context, &mut self.endpoint, &mut self.stack, 16_384)
            .map_err(|error| DirectError::Io(io::Error::other(error.to_string())));
        match (upload, download) {
            (Poll::Ready(Ok(upload)), Poll::Ready(Ok(download))) => {
                Poll::Ready(Ok(upload.finished && download.finished))
            }
            (Poll::Ready(Err(error)), _) | (_, Poll::Ready(Err(error))) => Poll::Ready(Err(error)),
            _ => Poll::Pending,
        }
    }
}

thread_local! {
    static STATES: RefCell<HashMap<u64, State>> = RefCell::new(HashMap::new());
}

fn initialize(
    instance: u64,
    config: &[u8],
    _base: &[u8],
    _host: *const abi::SnolHostApiV1,
) -> Result<(), u32> {
    let options = parse_options(config).map_err(|_| abi::STATUS_INVALID)?;
    let (sender, receiver) = sync_channel(options.max_pending_opens);
    let worker = thread::Builder::new()
        .name("snolc-direct".into())
        .spawn(move || connect_worker(receiver))
        .map_err(|_| abi::STATUS_IO)?;
    STATES.with(|states| {
        states.borrow_mut().insert(
            instance,
            State {
                options,
                sender: Some(sender),
                worker: Some(worker),
                pending: HashMap::new(),
                ready: HashMap::new(),
                active: HashMap::new(),
                active_datagrams: HashMap::new(),
            },
        );
    });
    Ok(())
}

unsafe extern "C" fn open(
    instance: u64,
    operation: u64,
    metadata: *const abi::SnolFlowMetadataV1,
    _wake: SnolWakeHandle,
    output: *mut u64,
) -> u32 {
    snolc_sdk::catch_status(|| {
        if !INSTANCES.contains(instance) || operation == 0 {
            return abi::STATUS_INVALID;
        }
        let metadata = match unsafe { snolc_sdk::module::flow_metadata(metadata) } {
            Ok(metadata) => metadata,
            Err(status) => return status,
        };
        if !matches!(metadata.kind, abi::FLOW_TCP | abi::FLOW_UDP) {
            return abi::STATUS_UNSUPPORTED;
        }
        let Some(output) = (unsafe { output.as_mut() }) else {
            return abi::STATUS_INVALID;
        };
        STATES.with(|states| {
            let mut states = states.borrow_mut();
            let Some(state) = states.get_mut(&instance) else {
                return abi::STATUS_INVALID;
            };
            if state.ready.contains_key(&operation) {
                *output = operation;
                return abi::STATUS_OK;
            }
            if state.active.contains_key(&operation) {
                return abi::STATUS_INVALID;
            }
            if let Some(pending) = state.pending.remove(&operation) {
                match pending.response.try_recv() {
                    Ok(Ok(stream)) => {
                        state.ready.insert(operation, stream);
                        *output = operation;
                        return abi::STATUS_OK;
                    }
                    Ok(Err(error)) => return error_status(&error),
                    Err(TryRecvError::Empty) => {
                        state.pending.insert(operation, pending);
                        return abi::STATUS_PENDING;
                    }
                    Err(TryRecvError::Disconnected) => return abi::STATUS_IO,
                }
            }
            if state.pending.len() >= state.options.max_pending_opens {
                return abi::STATUS_RESOURCE;
            }
            let destination = match owned_destination(&metadata) {
                Ok(destination) => destination,
                Err(status) => return status,
            };
            let Some(sender) = state.sender.as_ref() else {
                return abi::STATUS_IO;
            };
            let retained_wake = match retain_wake(_wake) {
                Ok(wake) => wake,
                Err(status) => return status,
            };
            let (response_tx, response_rx) = sync_channel(1);
            let request = ConnectRequest {
                kind: metadata.kind,
                destination,
                dns_mode: state.options.dns_mode,
                resolve_timeout: Duration::from_millis(state.options.resolve_timeout_ms),
                connect_timeout: Duration::from_millis(state.options.connect_timeout_ms),
                response: response_tx,
                wake: WorkerWake(_wake),
            };
            match sender.try_send(request) {
                Ok(()) => {
                    state.pending.insert(
                        operation,
                        PendingOpen {
                            response: response_rx,
                            retained_wake,
                        },
                    );
                    abi::STATUS_PENDING
                }
                Err(TrySendError::Full(_)) => {
                    release_wake(retained_wake);
                    abi::STATUS_RESOURCE
                }
                Err(TrySendError::Disconnected(_)) => {
                    release_wake(retained_wake);
                    abi::STATUS_IO
                }
            }
        })
    })
}

fn owned_destination(
    metadata: &snolc_sdk::module::BorrowedFlowMetadata<'_>,
) -> Result<Destination, u32> {
    let port = metadata.port;
    match metadata.address_type {
        abi::ADDRESS_IPV4 => {
            let bytes: [u8; 4] = metadata
                .address
                .try_into()
                .map_err(|_| abi::STATUS_INVALID)?;
            Ok(Destination::Ip(SocketAddr::new(
                Ipv4Addr::from(bytes).into(),
                port,
            )))
        }
        abi::ADDRESS_IPV6 => {
            let bytes: [u8; 16] = metadata
                .address
                .try_into()
                .map_err(|_| abi::STATUS_INVALID)?;
            Ok(Destination::Ip(SocketAddr::new(
                Ipv6Addr::from(bytes).into(),
                port,
            )))
        }
        abi::ADDRESS_DOMAIN => {
            let domain = std::str::from_utf8(metadata.address).map_err(|_| abi::STATUS_INVALID)?;
            Ok(Destination::Domain(domain.to_owned(), port))
        }
        _ => Err(abi::STATUS_INVALID),
    }
}

fn connect_worker(receiver: Receiver<ConnectRequest>) {
    while let Ok(request) = receiver.recv() {
        let result = connect_destination(
            request.kind,
            request.destination,
            request.dns_mode,
            request.resolve_timeout,
            request.connect_timeout,
        );
        let _ = request.response.send(result);
        request.wake.wake();
    }
}

fn connect_destination(
    kind: u32,
    destination: Destination,
    dns_mode: DnsMode,
    _resolve_timeout: Duration,
    connect_timeout: Duration,
) -> Result<Endpoint, DirectError> {
    let addresses = match destination {
        Destination::Ip(address) => vec![address],
        Destination::Domain(_, _) if matches!(dns_mode, DnsMode::RejectDomains) => {
            return Err(DirectError::Denied);
        }
        Destination::Domain(domain, port) => {
            let mut addresses: Vec<_> = (domain.as_str(), port).to_socket_addrs()?.collect();
            addresses.sort_unstable();
            addresses.dedup();
            addresses
        }
    };
    if addresses.is_empty() {
        return Err(DirectError::NoAddress);
    }
    let mut last_error = None;
    for address in addresses {
        let result = match kind {
            abi::FLOW_TCP => {
                TcpStream::connect_timeout(&address, connect_timeout).map(Endpoint::Tcp)
            }
            abi::FLOW_UDP => connect_udp(address).map(Endpoint::Udp),
            _ => return Err(DirectError::InvalidDestination),
        };
        match result {
            Ok(endpoint) => return Ok(endpoint),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.map_or(DirectError::NoAddress, DirectError::Io))
}

fn connect_udp(address: SocketAddr) -> io::Result<UdpSocket> {
    let bind = match address {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    };
    let socket = UdpSocket::bind(bind)?;
    socket.connect(address)?;
    Ok(socket)
}

fn error_status(error: &DirectError) -> u32 {
    match error {
        DirectError::Denied => abi::STATUS_DENIED,
        DirectError::InvalidConfig | DirectError::InvalidDestination | DirectError::Stale => {
            abi::STATUS_INVALID
        }
        DirectError::Resource => abi::STATUS_RESOURCE,
        DirectError::Timeout
        | DirectError::Stopped
        | DirectError::NoAddress
        | DirectError::Io(_) => abi::STATUS_IO,
    }
}

fn retain_wake(wake: SnolWakeHandle) -> Result<Option<SnolWakeHandle>, u32> {
    match (wake.retain, wake.release) {
        (Some(retain), Some(_)) => {
            if unsafe { retain(wake.context) } == abi::STATUS_OK {
                Ok(Some(wake))
            } else {
                Err(abi::STATUS_INTERNAL)
            }
        }
        (None, None) => Ok(None),
        _ => Err(abi::STATUS_INVALID),
    }
}

fn release_wake(wake: Option<SnolWakeHandle>) {
    if let Some(wake) = wake
        && let Some(release) = wake.release
    {
        unsafe { release(wake.context) };
    }
}

unsafe extern "C" fn attach(
    instance: u64,
    flow: u64,
    stack_socket: u64,
    stack_socket_io: *const SnolByteIoV1,
) -> u32 {
    snolc_sdk::catch_status(|| {
        if !INSTANCES.contains(instance) || flow == 0 || stack_socket == 0 {
            return abi::STATUS_INVALID;
        }
        STATES.with(|states| {
            let mut states = states.borrow_mut();
            let Some(state) = states.get_mut(&instance) else {
                return abi::STATUS_INVALID;
            };
            let Some(endpoint) = state.ready.remove(&flow) else {
                return abi::STATUS_INVALID;
            };
            let Endpoint::Tcp(endpoint) = endpoint else {
                state.ready.insert(flow, endpoint);
                return abi::STATUS_INVALID;
            };
            let stack = match unsafe { ForeignByteIo::from_raw(stack_socket, stack_socket_io) } {
                Ok(stack) => stack,
                Err(_) => return abi::STATUS_INVALID,
            };
            let flow_state = match DirectFlow::new(stack, endpoint) {
                Ok(flow) => flow,
                Err(error) => return error_status(&error),
            };
            state.active.insert(flow, flow_state);
            abi::STATUS_OK
        })
    })
}

unsafe extern "C" fn attach_datagram(
    instance: u64,
    flow: u64,
    stack_socket: u64,
    stack_socket_io: *const SnolDatagramIoV1,
) -> u32 {
    snolc_sdk::catch_status(|| {
        if !INSTANCES.contains(instance) || flow == 0 || stack_socket == 0 {
            return abi::STATUS_INVALID;
        }
        STATES.with(|states| {
            let mut states = states.borrow_mut();
            let Some(state) = states.get_mut(&instance) else {
                return abi::STATUS_INVALID;
            };
            let Some(endpoint) = state.ready.remove(&flow) else {
                return abi::STATUS_INVALID;
            };
            let Endpoint::Udp(endpoint) = endpoint else {
                state.ready.insert(flow, endpoint);
                return abi::STATUS_INVALID;
            };
            let stack = match unsafe { ForeignDatagramIo::from_raw(stack_socket, stack_socket_io) }
            {
                Ok(stack) => stack,
                Err(_) => return abi::STATUS_INVALID,
            };
            let flow_state = match DirectDatagramFlow::new(stack, endpoint) {
                Ok(flow) => flow,
                Err(error) => return error_status(&error),
            };
            state.active_datagrams.insert(flow, flow_state);
            abi::STATUS_OK
        })
    })
}

unsafe extern "C" fn complete(instance: u64, flow: u64, status: u32, reason: SnolBytes) -> u32 {
    snolc_sdk::catch_status(|| {
        if !INSTANCES.contains(instance) || flow == 0 || reason.length > 256 {
            return abi::STATUS_INVALID;
        }
        if status == abi::STATUS_OK {
            abi::STATUS_OK
        } else {
            unsafe { close_flow(instance, flow) }
        }
    })
}

unsafe extern "C" fn close_flow(instance: u64, flow: u64) -> u32 {
    snolc_sdk::catch_status(|| {
        if !INSTANCES.contains(instance) || flow == 0 {
            return abi::STATUS_INVALID;
        }
        STATES.with(|states| {
            let mut states = states.borrow_mut();
            let Some(state) = states.get_mut(&instance) else {
                return abi::STATUS_INVALID;
            };
            let removed = state.pending.remove(&flow).is_some()
                | state.ready.remove(&flow).is_some()
                | state.active.remove(&flow).is_some()
                | state.active_datagrams.remove(&flow).is_some();
            if removed {
                abi::STATUS_OK
            } else {
                abi::STATUS_INVALID
            }
        })
    })
}

fn poll_instance(instance: u64, _wake: SnolWakeHandle) -> u32 {
    STATES.with(|states| {
        let mut states = states.borrow_mut();
        let Some(state) = states.get_mut(&instance) else {
            return abi::STATUS_INVALID;
        };
        let mut context = Context::from_waker(Waker::noop());
        let mut finished = Vec::new();
        for (handle, flow) in &mut state.active {
            match flow.poll(&mut context) {
                Poll::Ready(Ok(true)) | Poll::Ready(Err(_)) => finished.push(*handle),
                Poll::Ready(Ok(false)) | Poll::Pending => {}
            }
        }
        for handle in finished {
            state.active.remove(&handle);
        }
        let mut finished = Vec::new();
        for (handle, flow) in &mut state.active_datagrams {
            match flow.poll(&mut context) {
                Poll::Ready(Ok(true)) | Poll::Ready(Err(_)) => finished.push(*handle),
                Poll::Ready(Ok(false)) | Poll::Pending => {}
            }
        }
        for handle in finished {
            state.active_datagrams.remove(&handle);
        }
        abi::STATUS_PENDING
    })
}

fn control_instance(_instance: u64, _request: &[u8]) -> Result<Vec<u8>, u32> {
    Err(abi::STATUS_UNSUPPORTED)
}

fn shutdown_instance(instance: u64) -> u32 {
    if STATES.with(|states| states.borrow_mut().remove(&instance).is_some()) {
        abi::STATUS_OK
    } else {
        abi::STATUS_INVALID
    }
}

fn destroy_instance(instance: u64) {
    STATES.with(|states| states.borrow_mut().remove(&instance));
}

static ADAPTER: SnolAdapterApiV1 = SnolAdapterApiV1 {
    struct_size: size_of::<SnolAdapterApiV1>() as u32,
    reserved: 0,
    open: Some(open),
    accept: Some(snolc_sdk::module::unsupported_adapter_accept),
    attach: Some(attach),
    complete: Some(complete),
    close_flow: Some(close_flow),
    attach_datagram: Some(attach_datagram),
};

snolc_sdk::declare_stateful_module! {
    name: "adapter-direct",
    description: "name = \"adapter-direct\"\nroles = [\"server\"]\ndns_modes = [\"system\", \"reject-domains\"]\ntcp = true\nudp = true\n",
    class_mask: abi::CLASS_ADAPTER,
    validate: validate_config,
    initialize: initialize,
    poll: poll_instance,
    control: control_instance,
    shutdown: shutdown_instance,
    destroy: destroy_instance,
    byte_io: std::ptr::null(),
    datagram_io: std::ptr::null(),
    adapter: &ADAPTER,
    protection: std::ptr::null(),
    carrier: std::ptr::null(),
    policy: std::ptr::null(),
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::net::TcpListener;
    use std::task::Waker;

    use super::*;

    #[derive(Default)]
    struct MemoryIo {
        input: VecDeque<u8>,
        output: Vec<u8>,
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
                *byte = self.input.pop_front().unwrap();
            }
            Poll::Ready(Ok(count))
        }

        fn poll_write(
            &mut self,
            _context: &mut Context<'_>,
            input: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.output.extend_from_slice(input);
            Poll::Ready(Ok(input.len()))
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

    fn no_wake() -> SnolWakeHandle {
        SnolWakeHandle {
            context: std::ptr::null_mut(),
            wake: None,
            retain: None,
            release: None,
        }
    }

    #[test]
    fn resolver_is_bounded_and_returns_generation() {
        let resolver = SystemResolver::new(1).unwrap();
        let addresses = resolver
            .resolve("localhost", 80, Duration::from_secs(2))
            .unwrap();
        assert!(addresses.iter().all(|address| address.port() == 80));
    }

    #[test]
    fn denied_resolved_ip_prevents_connect() {
        let resolver = SystemResolver::new(1).unwrap();
        let result = connect_domain(
            &resolver,
            "localhost",
            80,
            Duration::from_secs(2),
            |_| false,
            &NoopProtector,
        );
        assert!(matches!(result, Err(DirectError::Denied)));
    }

    #[test]
    fn worker_connects_ip_and_wakes_without_blocking_submitter() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let accept = thread::spawn(move || listener.accept().unwrap().0);
        let (sender, receiver) = sync_channel(1);
        let worker = thread::spawn(move || connect_worker(receiver));
        let (response_tx, response_rx) = sync_channel(1);
        sender
            .try_send(ConnectRequest {
                kind: abi::FLOW_TCP,
                destination: Destination::Ip(address),
                dns_mode: DnsMode::RejectDomains,
                resolve_timeout: Duration::from_secs(1),
                connect_timeout: Duration::from_secs(1),
                response: response_tx,
                wake: WorkerWake(no_wake()),
            })
            .unwrap();
        let stream = response_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap();
        let Endpoint::Tcp(stream) = stream else {
            panic!("worker returned a UDP endpoint");
        };
        assert_eq!(stream.peer_addr().unwrap(), address);
        drop(stream);
        drop(sender);
        worker.join().unwrap();
        drop(accept.join().unwrap());
    }

    #[test]
    fn abi_open_keeps_one_keyed_pending_operation() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let accept = thread::spawn(move || listener.accept().unwrap().0);
        let descriptor = unsafe { &*snolc_module_entry() };
        let config = b"dns_mode = \"reject-domains\"\nmax_pending_opens = 2\nresolve_timeout_ms = 1000\nconnect_timeout_ms = 1000\n";
        let mut instance = 0;
        assert_eq!(
            unsafe {
                descriptor.create.unwrap()(
                    SnolBytes {
                        pointer: config.as_ptr(),
                        length: config.len(),
                    },
                    SnolBytes {
                        pointer: std::ptr::null(),
                        length: 0,
                    },
                    std::ptr::null(),
                    &mut instance,
                )
            },
            abi::STATUS_OK
        );
        let octets = match address.ip() {
            IpAddr::V4(address) => address.octets(),
            IpAddr::V6(_) => panic!("test listener must use IPv4"),
        };
        let metadata = abi::SnolFlowMetadataV1 {
            struct_size: size_of::<abi::SnolFlowMetadataV1>() as u32,
            kind: abi::FLOW_TCP,
            address_type: abi::ADDRESS_IPV4,
            reserved: 0,
            address: SnolBytes {
                pointer: octets.as_ptr(),
                length: octets.len(),
            },
            port: address.port(),
            reserved2: [0; 6],
            metadata: SnolBytes {
                pointer: std::ptr::null(),
                length: 0,
            },
        };
        let adapter = unsafe { &*descriptor.adapter };
        let mut flow = 0;
        assert_eq!(
            unsafe { adapter.open.unwrap()(instance, 42, &metadata, no_wake(), &mut flow) },
            abi::STATUS_PENDING
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            let status =
                unsafe { adapter.open.unwrap()(instance, 42, &metadata, no_wake(), &mut flow) };
            if status == abi::STATUS_OK {
                break;
            }
            assert_eq!(status, abi::STATUS_PENDING);
            assert!(std::time::Instant::now() < deadline);
            thread::yield_now();
        }
        assert_eq!(flow, 42);
        assert_eq!(
            unsafe { adapter.close_flow.unwrap()(instance, flow) },
            abi::STATUS_OK
        );
        assert_eq!(
            unsafe { descriptor.shutdown.unwrap()(instance) },
            abi::STATUS_OK
        );
        unsafe { descriptor.destroy.unwrap()(instance) };
        drop(accept.join().unwrap());
    }

    #[test]
    fn direct_flow_pumps_through_the_supplied_stack_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let peer = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut input = [0; 6];
            stream.read_exact(&mut input).unwrap();
            assert_eq!(&input, b"upload");
            stream.write_all(b"download").unwrap();
        });
        let endpoint = TcpStream::connect(address).unwrap();
        let stack = MemoryIo {
            input: b"upload".iter().copied().collect(),
            ..MemoryIo::default()
        };
        let mut flow = DirectFlow::new(stack, endpoint).unwrap();
        let mut context = Context::from_waker(Waker::noop());
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while flow.stack.output.len() < 8 && std::time::Instant::now() < deadline {
            let _ = flow.poll(&mut context);
            thread::yield_now();
        }
        peer.join().unwrap();
        assert_eq!(flow.stack.output, b"download");
    }
}
