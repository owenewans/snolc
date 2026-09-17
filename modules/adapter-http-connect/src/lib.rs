#![deny(unsafe_op_in_unsafe_fn)]

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::task::{Context, Poll, Waker};

use serde::Deserialize;
use snolc_sdk::abi::{
    self, SnolAdapterApiV1, SnolByteIoV1, SnolBytes, SnolFlowMetadataV1, SnolWakeHandle,
};
use snolc_sdk::{ByteIo, ForeignByteIo, Pump};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Host {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Domain(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectRequest<'a> {
    pub host: Host,
    pub port: u16,
    pub trailing: &'a [u8],
}

pub fn parse_connect(
    input: &[u8],
    max_header_bytes: usize,
) -> Result<ConnectRequest<'_>, ParseError> {
    let end = input
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|offset| offset + 4)
        .ok_or({
            if input.len() >= max_header_bytes {
                ParseError::HeaderTooLarge
            } else {
                ParseError::Incomplete
            }
        })?;
    if end > max_header_bytes {
        return Err(ParseError::HeaderTooLarge);
    }
    let header = std::str::from_utf8(&input[..end]).map_err(|_| ParseError::Protocol)?;
    if header.contains("\r\n ") || header.contains("\r\n\t") {
        return Err(ParseError::Protocol);
    }
    let line = header.split("\r\n").next().ok_or(ParseError::Protocol)?;
    let mut parts = line.split(' ');
    if parts.next() != Some("CONNECT") {
        return Err(ParseError::Method);
    }
    let authority = parts.next().ok_or(ParseError::Authority)?;
    if parts.next() != Some("HTTP/1.1") || parts.next().is_some() {
        return Err(ParseError::Protocol);
    }
    let (host, port) = parse_authority(authority)?;
    Ok(ConnectRequest {
        host,
        port,
        trailing: &input[end..],
    })
}

fn parse_authority(authority: &str) -> Result<(Host, u16), ParseError> {
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let close = rest.find(']').ok_or(ParseError::Authority)?;
        if rest.as_bytes().get(close + 1) != Some(&b':') {
            return Err(ParseError::Authority);
        }
        let address = rest[..close]
            .parse::<Ipv6Addr>()
            .map_err(|_| ParseError::Authority)?;
        (Host::Ipv6(address), &rest[close + 2..])
    } else {
        let (name, port) = authority.rsplit_once(':').ok_or(ParseError::Authority)?;
        let host = if let Ok(address) = name.parse::<Ipv4Addr>() {
            Host::Ipv4(address)
        } else if valid_domain(name) {
            Host::Domain(name.to_owned())
        } else {
            return Err(ParseError::Authority);
        };
        (host, port)
    };
    let port = port.parse::<u16>().map_err(|_| ParseError::Authority)?;
    if port == 0 {
        return Err(ParseError::Authority);
    }
    Ok((host, port))
}

fn valid_domain(domain: &str) -> bool {
    !domain.is_empty()
        && domain.len() <= 253
        && domain.is_ascii()
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    Incomplete,
    HeaderTooLarge,
    Method,
    Authority,
    Protocol,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Options {
    listen: String,
    max_connections: usize,
    max_header_bytes: usize,
}

fn validate_config(config: &[u8], _base: &[u8]) -> Result<(), String> {
    parse_options(config).map(|_| ())
}

fn parse_options(config: &[u8]) -> Result<Options, String> {
    let text = std::str::from_utf8(config).map_err(|_| "config is not UTF-8".to_owned())?;
    let options: Options = toml::from_str(text).map_err(|error| error.to_string())?;
    if options.listen.parse::<SocketAddr>().is_err()
        || options.max_connections == 0
        || options.max_header_bytes < 64
    {
        return Err("HTTP CONNECT options are inconsistent".into());
    }
    Ok(options)
}

struct PendingClient {
    stream: TcpStream,
    input: Vec<u8>,
}

impl PendingClient {
    fn new(stream: TcpStream) -> io::Result<Self> {
        stream.set_nonblocking(true)?;
        Ok(Self {
            stream,
            input: Vec::new(),
        })
    }

    fn poll(&mut self, limit: usize) -> Result<Option<OwnedRequest>, ParseError> {
        let mut buffer = [0; 1024];
        loop {
            match self.stream.read(&mut buffer) {
                Ok(0) => return Err(ParseError::Protocol),
                Ok(count) => {
                    if self.input.len().saturating_add(count) > limit {
                        return Err(ParseError::HeaderTooLarge);
                    }
                    self.input.extend_from_slice(&buffer[..count]);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => return Err(ParseError::Protocol),
            }
        }
        match parse_connect(&self.input, limit) {
            Ok(request) => Ok(Some(OwnedRequest {
                host: request.host,
                port: request.port,
                trailing: request.trailing.to_vec(),
            })),
            Err(ParseError::Incomplete) => Ok(None),
            Err(error) => Err(error),
        }
    }
}

struct OwnedRequest {
    host: Host,
    port: u16,
    trailing: Vec<u8>,
}

struct ClientIo {
    stream: TcpStream,
    prefix: VecDeque<u8>,
}

impl ByteIo for ClientIo {
    fn poll_read(
        &mut self,
        _context: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if !self.prefix.is_empty() {
            let count = output.len().min(self.prefix.len());
            for byte in &mut output[..count] {
                *byte = self.prefix.pop_front().expect("count checked");
            }
            return Poll::Ready(Ok(count));
        }
        map_nonblocking(self.stream.read(output))
    }

    fn poll_write(&mut self, _context: &mut Context<'_>, input: &[u8]) -> Poll<io::Result<usize>> {
        map_nonblocking(self.stream.write(input))
    }

    fn poll_flush(&mut self, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        map_nonblocking(self.stream.flush())
    }

    fn poll_shutdown_write(&mut self, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(self.stream.shutdown(Shutdown::Write))
    }

    fn close(&mut self) -> io::Result<()> {
        self.stream.shutdown(Shutdown::Both)
    }
}

fn map_nonblocking<T>(result: io::Result<T>) -> Poll<io::Result<T>> {
    match result {
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
        result => Poll::Ready(result),
    }
}

struct ClientFlow {
    client: ClientIo,
    address_type: u32,
    address: Vec<u8>,
    port: u16,
    announced: bool,
    stack: Option<ForeignByteIo>,
    upload: Pump,
    download: Pump,
    response: Vec<u8>,
    response_offset: usize,
    accepted: Option<bool>,
}

impl ClientFlow {
    fn new(client: PendingClient, request: OwnedRequest) -> Result<Self, u32> {
        let (address_type, address) = match request.host {
            Host::Ipv4(address) => (abi::ADDRESS_IPV4, address.octets().to_vec()),
            Host::Ipv6(address) => (abi::ADDRESS_IPV6, address.octets().to_vec()),
            Host::Domain(address) => (abi::ADDRESS_DOMAIN, address.into_bytes()),
        };
        Ok(Self {
            client: ClientIo {
                stream: client.stream,
                prefix: request.trailing.into(),
            },
            address_type,
            address,
            port: request.port,
            announced: false,
            stack: None,
            upload: Pump::new(16_384).map_err(|_| abi::STATUS_RESOURCE)?,
            download: Pump::new(16_384).map_err(|_| abi::STATUS_RESOURCE)?,
            response: Vec::new(),
            response_offset: 0,
            accepted: None,
        })
    }

    fn poll(&mut self, context: &mut Context<'_>) -> Poll<io::Result<bool>> {
        while self.response_offset < self.response.len() {
            match self
                .client
                .poll_write(context, &self.response[self.response_offset..])
            {
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Poll::Ready(Ok(count)) => self.response_offset += count,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        if self.accepted == Some(false) {
            return Poll::Ready(Ok(true));
        }
        if self.accepted != Some(true) {
            return Poll::Pending;
        }
        let Some(stack) = &mut self.stack else {
            return Poll::Pending;
        };
        let upload = self
            .upload
            .poll(context, &mut self.client, stack, 16_384)
            .map_err(|error| io::Error::other(error.to_string()));
        let download = self
            .download
            .poll(context, stack, &mut self.client, 16_384)
            .map_err(|error| io::Error::other(error.to_string()));
        match (upload, download) {
            (Poll::Ready(Ok(upload)), Poll::Ready(Ok(download))) => {
                Poll::Ready(Ok(upload.finished && download.finished))
            }
            (Poll::Ready(Err(error)), _) | (_, Poll::Ready(Err(error))) => Poll::Ready(Err(error)),
            _ => Poll::Pending,
        }
    }
}

struct State {
    listener: TcpListener,
    options: Options,
    pending: Vec<PendingClient>,
    flows: HashMap<u64, ClientFlow>,
    next_flow: u64,
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
    let listener = TcpListener::bind(&options.listen).map_err(|_| abi::STATUS_IO)?;
    listener.set_nonblocking(true).map_err(|_| abi::STATUS_IO)?;
    STATES.with(|states| {
        states.borrow_mut().insert(
            instance,
            State {
                listener,
                options,
                pending: Vec::new(),
                flows: HashMap::new(),
                next_flow: 1,
            },
        );
    });
    Ok(())
}

unsafe extern "C" fn open(
    instance: u64,
    _operation: u64,
    _metadata: *const abi::SnolFlowMetadataV1,
    _wake: SnolWakeHandle,
    _output: *mut u64,
) -> u32 {
    snolc_sdk::catch_status(|| {
        if !INSTANCES.contains(instance) {
            return abi::STATUS_INVALID;
        }
        abi::STATUS_UNSUPPORTED
    })
}

unsafe extern "C" fn accept(
    instance: u64,
    metadata: *mut SnolFlowMetadataV1,
    _wake: SnolWakeHandle,
    output: *mut u64,
) -> u32 {
    snolc_sdk::catch_status(|| {
        let (Some(metadata), Some(output)) =
            (unsafe { metadata.as_mut() }, unsafe { output.as_mut() })
        else {
            return abi::STATUS_INVALID;
        };
        STATES.with(|states| {
            let mut states = states.borrow_mut();
            let Some(state) = states.get_mut(&instance) else {
                return abi::STATUS_INVALID;
            };
            poll_state(state);
            let Some((handle, flow)) = state.flows.iter_mut().find(|(_, flow)| !flow.announced)
            else {
                return abi::STATUS_PENDING;
            };
            flow.announced = true;
            *metadata = SnolFlowMetadataV1 {
                struct_size: size_of::<SnolFlowMetadataV1>() as u32,
                kind: abi::FLOW_TCP,
                address_type: flow.address_type,
                reserved: 0,
                address: SnolBytes {
                    pointer: flow.address.as_ptr(),
                    length: flow.address.len(),
                },
                port: flow.port,
                reserved2: [0; 6],
                metadata: SnolBytes {
                    pointer: std::ptr::null(),
                    length: 0,
                },
            };
            *output = *handle;
            abi::STATUS_OK
        })
    })
}

unsafe extern "C" fn attach(
    instance: u64,
    flow: u64,
    stack_socket: u64,
    stack_socket_io: *const SnolByteIoV1,
) -> u32 {
    snolc_sdk::catch_status(|| {
        let stack = match unsafe { ForeignByteIo::from_raw(stack_socket, stack_socket_io) } {
            Ok(stack) => stack,
            Err(_) => return abi::STATUS_INVALID,
        };
        STATES.with(|states| {
            let mut states = states.borrow_mut();
            let Some(flow) = states
                .get_mut(&instance)
                .and_then(|state| state.flows.get_mut(&flow))
            else {
                return abi::STATUS_INVALID;
            };
            if flow.stack.is_some() {
                return abi::STATUS_INVALID;
            }
            flow.stack = Some(stack);
            abi::STATUS_OK
        })
    })
}

unsafe extern "C" fn complete(instance: u64, flow: u64, status: u32, reason: SnolBytes) -> u32 {
    snolc_sdk::catch_status(|| {
        if reason.length > 256 {
            return abi::STATUS_INVALID;
        }
        STATES.with(|states| {
            let mut states = states.borrow_mut();
            let Some(flow) = states
                .get_mut(&instance)
                .and_then(|state| state.flows.get_mut(&flow))
            else {
                return abi::STATUS_INVALID;
            };
            let response = match status {
                abi::STATUS_OK => "HTTP/1.1 200 Connection Established\r\n\r\n",
                abi::STATUS_DENIED => "HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n",
                abi::STATUS_UNSUPPORTED => {
                    "HTTP/1.1 501 Not Implemented\r\nConnection: close\r\n\r\n"
                }
                abi::STATUS_IO => "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n",
                abi::STATUS_RESOURCE => {
                    "HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n"
                }
                _ => "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n",
            };
            flow.response = response.as_bytes().to_vec();
            flow.response_offset = 0;
            flow.accepted = Some(status == abi::STATUS_OK);
            abi::STATUS_OK
        })
    })
}

unsafe extern "C" fn close_flow(instance: u64, flow: u64) -> u32 {
    snolc_sdk::catch_status(|| {
        if STATES.with(|states| {
            states
                .borrow_mut()
                .get_mut(&instance)
                .and_then(|state| state.flows.remove(&flow))
                .is_some()
        }) {
            abi::STATUS_OK
        } else {
            abi::STATUS_INVALID
        }
    })
}

fn poll_state(state: &mut State) {
    while state.pending.len() + state.flows.len() < state.options.max_connections {
        match state.listener.accept() {
            Ok((stream, _)) => match PendingClient::new(stream) {
                Ok(client) => state.pending.push(client),
                Err(_) => continue,
            },
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(_) => break,
        }
    }
    let mut pending = Vec::with_capacity(state.pending.len());
    for mut client in state.pending.drain(..) {
        match client.poll(state.options.max_header_bytes) {
            Ok(Some(request)) => {
                let handle = state.next_flow;
                let Some(next) = handle.checked_add(1) else {
                    continue;
                };
                state.next_flow = next;
                if let Ok(flow) = ClientFlow::new(client, request) {
                    state.flows.insert(handle, flow);
                }
            }
            Ok(None) => pending.push(client),
            Err(_) => {
                let _ = client
                    .stream
                    .write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
            }
        }
    }
    state.pending = pending;
    let mut context = Context::from_waker(Waker::noop());
    let mut finished = Vec::new();
    for (handle, flow) in &mut state.flows {
        match flow.poll(&mut context) {
            Poll::Ready(Ok(true)) | Poll::Ready(Err(_)) => finished.push(*handle),
            Poll::Ready(Ok(false)) | Poll::Pending => {}
        }
    }
    for handle in finished {
        state.flows.remove(&handle);
    }
}

fn poll_instance(instance: u64, _wake: SnolWakeHandle) -> u32 {
    STATES.with(|states| {
        let mut states = states.borrow_mut();
        let Some(state) = states.get_mut(&instance) else {
            return abi::STATUS_INVALID;
        };
        poll_state(state);
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
    accept: Some(accept),
    attach: Some(attach),
    complete: Some(complete),
    close_flow: Some(close_flow),
    attach_datagram: None,
    attach_packet_port: None,
};

snolc_sdk::declare_stateful_module! {
    name: "adapter-http-connect",
    description: "name = \"adapter-http-connect\"\nroles = [\"client\"]\nprotocol = \"HTTP/1.1 CONNECT\"\nforward_proxy = false\n",
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
    use super::*;

    #[test]
    fn parses_ipv6_and_preserves_trailing_bytes() {
        let request = parse_connect(
            b"CONNECT [2001:db8::1]:443 HTTP/1.1\r\nHost: ignored\r\n\r\nhello",
            1024,
        )
        .unwrap();
        assert_eq!(request.host, Host::Ipv6("2001:db8::1".parse().unwrap()));
        assert_eq!(request.port, 443);
        assert_eq!(request.trailing, b"hello");
    }

    #[test]
    fn rejects_forward_proxy_and_oversized_headers() {
        assert_eq!(
            parse_connect(b"GET http://example.com HTTP/1.1\r\n\r\n", 1024),
            Err(ParseError::Method)
        );
        assert_eq!(
            parse_connect(&[b'a'; 64], 64),
            Err(ParseError::HeaderTooLarge)
        );
    }
}
