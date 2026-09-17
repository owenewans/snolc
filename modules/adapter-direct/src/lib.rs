#![deny(unsafe_op_in_unsafe_fn)]

use std::io;
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde::Deserialize;
use snolc_sdk::abi::{self, SnolAdapterApiV1, SnolBytes, SnolWakeHandle};

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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Options {
    dns_mode: DnsMode,
    max_pending_opens: usize,
    resolve_timeout_ms: u64,
    connect_timeout_ms: u64,
}

fn validate_config(config: &[u8], _base: &[u8]) -> Result<(), String> {
    let text = std::str::from_utf8(config).map_err(|_| "config is not UTF-8".to_owned())?;
    let options: Options = toml::from_str(text).map_err(|error| error.to_string())?;
    if options.max_pending_opens == 0
        || options.resolve_timeout_ms == 0
        || options.connect_timeout_ms == 0
    {
        return Err("direct adapter options are inconsistent".into());
    }
    match options.dns_mode {
        DnsMode::System | DnsMode::RejectDomains => Ok(()),
    }
}

static FLOW_NEXT: AtomicU64 = AtomicU64::new(1);

unsafe extern "C" fn open(
    instance: u64,
    request: SnolBytes,
    _wake: SnolWakeHandle,
    output: *mut u64,
) -> u32 {
    snolc_sdk::catch_status(|| {
        if !INSTANCES.contains(instance) {
            return abi::STATUS_INVALID;
        }
        let request = match unsafe { snolc_sdk::module::input(request) } {
            Ok(request) => request,
            Err(status) => return status,
        };
        if request.is_empty() || request.len() > 4096 {
            return abi::STATUS_INVALID;
        }
        let Some(output) = (unsafe { output.as_mut() }) else {
            return abi::STATUS_INVALID;
        };
        let handle = FLOW_NEXT.fetch_add(1, Ordering::Relaxed);
        if handle == 0 {
            return abi::STATUS_RESOURCE;
        }
        *output = handle;
        abi::STATUS_OK
    })
}

static ADAPTER: SnolAdapterApiV1 = SnolAdapterApiV1 {
    struct_size: size_of::<SnolAdapterApiV1>() as u32,
    reserved: 0,
    open: Some(open),
    accept: Some(snolc_sdk::module::unsupported_adapter_accept),
    attach: Some(snolc_sdk::module::unsupported_adapter_attach),
    complete: Some(snolc_sdk::module::unsupported_adapter_complete),
    close_flow: Some(snolc_sdk::module::unsupported_adapter_close),
};

snolc_sdk::declare_module! {
    name: "adapter-direct",
    description: "name = \"adapter-direct\"\nroles = [\"server\"]\ndns_modes = [\"system\", \"reject-domains\"]\ntcp = true\nudp = true\n",
    class_mask: abi::CLASS_ADAPTER,
    validate: validate_config,
    byte_io: std::ptr::null(),
    datagram_io: std::ptr::null(),
    adapter: &ADAPTER,
    protection: std::ptr::null(),
    carrier: std::ptr::null(),
    policy: std::ptr::null(),
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
