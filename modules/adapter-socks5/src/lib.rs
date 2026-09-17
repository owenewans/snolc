#![deny(unsafe_op_in_unsafe_fn)]

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::task::{Context, Poll, Waker};

use serde::Deserialize;
use snolc_sdk::abi::{
    self, SnolAdapterApiV1, SnolByteIoV1, SnolBytes, SnolDatagramIoV1, SnolFlowMetadataV1,
    SnolWakeHandle,
};
use snolc_sdk::{ByteIo, DatagramIo, DatagramRecv, ForeignByteIo, ForeignDatagramIo, Pump};

const MAX_UDP_PAYLOAD: usize = 65_507;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Command {
    Connect,
    UdpAssociate,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum Address {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Domain(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Request {
    pub command: Command,
    pub address: Address,
    pub port: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpPacket<'a> {
    pub address: Address,
    pub port: u16,
    pub payload: &'a [u8],
}

pub fn parse_request(input: &[u8]) -> Result<Request, ParseError> {
    if input.len() < 4 || input[0] != 5 || input[2] != 0 {
        return Err(ParseError::Protocol);
    }
    let command = match input[1] {
        1 => Command::Connect,
        2 => return Err(ParseError::BindUnsupported),
        3 => Command::UdpAssociate,
        _ => return Err(ParseError::Command),
    };
    let (address, port, consumed) = parse_address(&input[3..], command == Command::UdpAssociate)?;
    if consumed + 3 != input.len() {
        return Err(ParseError::TrailingBytes);
    }
    Ok(Request {
        command,
        address,
        port,
    })
}

pub fn parse_udp(input: &[u8]) -> Result<UdpPacket<'_>, ParseError> {
    if input.len() < 4 || input[..2] != [0, 0] {
        return Err(ParseError::Protocol);
    }
    if input[2] != 0 {
        return Err(ParseError::FragmentUnsupported);
    }
    let (address, port, consumed) = parse_address(&input[3..], false)?;
    Ok(UdpPacket {
        address,
        port,
        payload: &input[3 + consumed..],
    })
}

fn parse_address(input: &[u8], allow_zero_port: bool) -> Result<(Address, u16, usize), ParseError> {
    let kind = *input.first().ok_or(ParseError::Incomplete)?;
    let (address, offset) = match kind {
        1 => {
            let bytes: [u8; 4] = input
                .get(1..5)
                .ok_or(ParseError::Incomplete)?
                .try_into()
                .map_err(|_| ParseError::Incomplete)?;
            (Address::Ipv4(Ipv4Addr::from(bytes)), 5)
        }
        4 => {
            let bytes: [u8; 16] = input
                .get(1..17)
                .ok_or(ParseError::Incomplete)?
                .try_into()
                .map_err(|_| ParseError::Incomplete)?;
            (Address::Ipv6(Ipv6Addr::from(bytes)), 17)
        }
        3 => {
            let length = *input.get(1).ok_or(ParseError::Incomplete)? as usize;
            if length == 0 {
                return Err(ParseError::Address);
            }
            let bytes = input.get(2..2 + length).ok_or(ParseError::Incomplete)?;
            let domain = std::str::from_utf8(bytes).map_err(|_| ParseError::Address)?;
            if !valid_domain(domain) {
                return Err(ParseError::Address);
            }
            (Address::Domain(domain.to_owned()), 2 + length)
        }
        _ => return Err(ParseError::Address),
    };
    let port_bytes: [u8; 2] = input
        .get(offset..offset + 2)
        .ok_or(ParseError::Incomplete)?
        .try_into()
        .map_err(|_| ParseError::Incomplete)?;
    let port = u16::from_be_bytes(port_bytes);
    if port == 0 && !allow_zero_port {
        return Err(ParseError::Port);
    }
    Ok((address, port, offset + 2))
}

fn valid_domain(domain: &str) -> bool {
    domain.len() <= 253
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
    Protocol,
    Command,
    BindUnsupported,
    FragmentUnsupported,
    Address,
    Port,
    TrailingBytes,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Options {
    listen: String,
    max_connections: usize,
    max_udp_associations: usize,
    max_request_bytes: usize,
    reject_fragments: bool,
}

fn validate_config(config: &[u8], _base: &[u8]) -> Result<(), String> {
    parse_options(config).map(|_| ())
}

fn parse_options(config: &[u8]) -> Result<Options, String> {
    let text = std::str::from_utf8(config).map_err(|_| "config is not UTF-8".to_owned())?;
    let options: Options = toml::from_str(text).map_err(|error| error.to_string())?;
    if options.listen.parse::<SocketAddr>().is_err()
        || options.max_connections == 0
        || options.max_udp_associations == 0
        || options.max_request_bytes < 262
        || !options.reject_fragments
    {
        return Err("SOCKS5 options are inconsistent".into());
    }
    Ok(options)
}

enum ClientPhase {
    Greeting,
    Request,
    Ready(Request),
    Failed,
}

struct ClientConnection {
    stream: TcpStream,
    input: Vec<u8>,
    output: Vec<u8>,
    output_offset: usize,
    phase: ClientPhase,
}

impl ClientConnection {
    fn new(stream: TcpStream) -> io::Result<Self> {
        stream.set_nonblocking(true)?;
        Ok(Self {
            stream,
            input: Vec::new(),
            output: Vec::new(),
            output_offset: 0,
            phase: ClientPhase::Greeting,
        })
    }

    fn poll(&mut self, limit: usize) -> io::Result<()> {
        let mut buffer = [0; 1024];
        loop {
            match self.stream.read(&mut buffer) {
                Ok(0) => {
                    self.phase = ClientPhase::Failed;
                    break;
                }
                Ok(count) => {
                    if self.input.len().saturating_add(count) > limit {
                        self.phase = ClientPhase::Failed;
                        break;
                    }
                    self.input.extend_from_slice(&buffer[..count]);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
        }
        self.parse();
        self.write_pending()
    }

    fn parse(&mut self) {
        if matches!(self.phase, ClientPhase::Greeting) {
            if self.input.len() < 2 {
                return;
            }
            let methods = self.input[1] as usize;
            let total = 2 + methods;
            if self.input.len() < total {
                return;
            }
            if self.input[0] != 5 || !self.input[2..total].contains(&0) {
                self.queue(&[5, 0xff]);
                self.phase = ClientPhase::Failed;
                return;
            }
            self.input.drain(..total);
            self.queue(&[5, 0]);
            self.phase = ClientPhase::Request;
        }
        if matches!(self.phase, ClientPhase::Request) {
            let Some(length) = request_length(&self.input) else {
                return;
            };
            if self.input.len() < length {
                return;
            }
            match parse_request(&self.input[..length]) {
                Ok(request) => {
                    self.input.drain(..length);
                    self.phase = ClientPhase::Ready(request);
                }
                Err(_) => {
                    self.queue(&socks_response(1));
                    self.phase = ClientPhase::Failed;
                }
            }
        }
    }

    fn queue(&mut self, bytes: &[u8]) {
        if self.output_offset == self.output.len() {
            self.output.clear();
            self.output_offset = 0;
        }
        self.output.extend_from_slice(bytes);
    }

    fn write_pending(&mut self) -> io::Result<()> {
        while self.output_offset < self.output.len() {
            match self.stream.write(&self.output[self.output_offset..]) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(count) => self.output_offset += count,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) => return Err(error),
            }
        }
        self.output.clear();
        self.output_offset = 0;
        Ok(())
    }

    fn ready(&self) -> bool {
        matches!(self.phase, ClientPhase::Ready(_)) && self.output.is_empty()
    }
}

fn request_length(input: &[u8]) -> Option<usize> {
    let address_type = *input.get(3)?;
    match address_type {
        1 => Some(10),
        4 => Some(22),
        3 => Some(7 + *input.get(4)? as usize),
        _ => Some(4),
    }
}

struct SocksIo {
    stream: TcpStream,
    prefix: VecDeque<u8>,
}

impl ByteIo for SocksIo {
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
    client: SocksIo,
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

struct UdpAssociation {
    control: ClientConnection,
    socket: UdpSocket,
    client: Option<SocketAddr>,
    destinations: HashMap<(Address, u16), u64>,
    receive_buffer: Vec<u8>,
}

struct UdpClientFlow {
    socket: UdpSocket,
    client: SocketAddr,
    address: Address,
    address_type: u32,
    address_bytes: Vec<u8>,
    port: u16,
    announced: bool,
    stack: Option<ForeignDatagramIo>,
    pending_upload: Option<Vec<u8>>,
    pending_reply: Option<Vec<u8>>,
    receive_buffer: Vec<u8>,
    accepted: Option<bool>,
}

impl ClientFlow {
    fn new(connection: ClientConnection, request: Request) -> Result<Self, u32> {
        let (address_type, address) = match request.address {
            Address::Ipv4(address) => (abi::ADDRESS_IPV4, address.octets().to_vec()),
            Address::Ipv6(address) => (abi::ADDRESS_IPV6, address.octets().to_vec()),
            Address::Domain(address) => (abi::ADDRESS_DOMAIN, address.into_bytes()),
        };
        Ok(Self {
            client: SocksIo {
                stream: connection.stream,
                prefix: connection.input.into(),
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

impl UdpClientFlow {
    fn new(
        socket: UdpSocket,
        client: SocketAddr,
        address: Address,
        port: u16,
        payload: Vec<u8>,
    ) -> io::Result<Self> {
        socket.set_nonblocking(true)?;
        let (address_type, address_bytes) = match &address {
            Address::Ipv4(address) => (abi::ADDRESS_IPV4, address.octets().to_vec()),
            Address::Ipv6(address) => (abi::ADDRESS_IPV6, address.octets().to_vec()),
            Address::Domain(address) => (abi::ADDRESS_DOMAIN, address.as_bytes().to_vec()),
        };
        Ok(Self {
            socket,
            client,
            address,
            address_type,
            address_bytes,
            port,
            announced: false,
            stack: None,
            pending_upload: Some(payload),
            pending_reply: None,
            receive_buffer: vec![0; MAX_UDP_PAYLOAD],
            accepted: None,
        })
    }

    fn poll(&mut self, context: &mut Context<'_>) -> Poll<io::Result<bool>> {
        if self.accepted == Some(false) {
            return Poll::Ready(Ok(true));
        }
        if self.accepted != Some(true) {
            return Poll::Pending;
        }
        let Some(stack) = &mut self.stack else {
            return Poll::Pending;
        };
        if let Some(payload) = &self.pending_upload {
            match stack.poll_send_datagram(context, payload) {
                Poll::Ready(Ok(())) => self.pending_upload = None,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        if let Some(reply) = &self.pending_reply {
            match self.socket.send_to(reply, self.client) {
                Ok(length) if length == reply.len() => self.pending_reply = None,
                Ok(_) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
                Err(error) => return Poll::Ready(Err(error)),
            }
        }
        match stack.poll_recv_datagram(context, &mut self.receive_buffer) {
            Poll::Ready(Ok(DatagramRecv::Datagram(length))) => {
                let mut reply = encode_udp_header(&self.address, self.port)?;
                reply.extend_from_slice(&self.receive_buffer[..length]);
                match self.socket.send_to(&reply, self.client) {
                    Ok(written) if written == reply.len() => Poll::Ready(Ok(false)),
                    Ok(_) => Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        self.pending_reply = Some(reply);
                        Poll::Pending
                    }
                    Err(error) => Poll::Ready(Err(error)),
                }
            }
            Poll::Ready(Ok(DatagramRecv::BufferTooSmall(_))) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "stack returned oversized UDP payload",
            ))),
            Poll::Ready(Ok(DatagramRecv::Closed)) => Poll::Ready(Ok(true)),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

fn encode_udp_header(address: &Address, port: u16) -> io::Result<Vec<u8>> {
    let mut output = vec![0, 0, 0];
    match address {
        Address::Ipv4(address) => {
            output.push(1);
            output.extend_from_slice(&address.octets());
        }
        Address::Ipv6(address) => {
            output.push(4);
            output.extend_from_slice(&address.octets());
        }
        Address::Domain(address) => {
            let length = u8::try_from(address.len())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "domain is too long"))?;
            output.extend_from_slice(&[3, length]);
            output.extend_from_slice(address.as_bytes());
        }
    }
    output.extend_from_slice(&port.to_be_bytes());
    Ok(output)
}

struct State {
    listener: TcpListener,
    options: Options,
    clients: Vec<ClientConnection>,
    flows: HashMap<u64, ClientFlow>,
    associations: Vec<UdpAssociation>,
    udp_flows: HashMap<u64, UdpClientFlow>,
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
                clients: Vec::new(),
                flows: HashMap::new(),
                associations: Vec::new(),
                udp_flows: HashMap::new(),
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
        if !INSTANCES.contains(instance) {
            return abi::STATUS_INVALID;
        }
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
            if let Some((handle, flow)) = state.flows.iter_mut().find(|(_, flow)| !flow.announced) {
                flow.announced = true;
                *metadata =
                    flow_metadata(abi::FLOW_TCP, flow.address_type, &flow.address, flow.port);
                *output = *handle;
                return abi::STATUS_OK;
            }
            if let Some((handle, flow)) =
                state.udp_flows.iter_mut().find(|(_, flow)| !flow.announced)
            {
                flow.announced = true;
                *metadata = flow_metadata(
                    abi::FLOW_UDP,
                    flow.address_type,
                    &flow.address_bytes,
                    flow.port,
                );
                *output = *handle;
                return abi::STATUS_OK;
            }
            abi::STATUS_PENDING
        })
    })
}

fn flow_metadata(kind: u32, address_type: u32, address: &[u8], port: u16) -> SnolFlowMetadataV1 {
    SnolFlowMetadataV1 {
        struct_size: size_of::<SnolFlowMetadataV1>() as u32,
        kind,
        address_type,
        reserved: 0,
        address: SnolBytes {
            pointer: address.as_ptr(),
            length: address.len(),
        },
        port,
        reserved2: [0; 6],
        metadata: SnolBytes {
            pointer: std::ptr::null(),
            length: 0,
        },
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
            let Some(flow) = states
                .get_mut(&instance)
                .and_then(|state| state.flows.get_mut(&flow))
            else {
                return abi::STATUS_INVALID;
            };
            if flow.stack.is_some() {
                return abi::STATUS_INVALID;
            }
            flow.stack = match unsafe { ForeignByteIo::from_raw(stack_socket, stack_socket_io) } {
                Ok(stack) => Some(stack),
                Err(_) => return abi::STATUS_INVALID,
            };
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
            let Some(flow) = states
                .get_mut(&instance)
                .and_then(|state| state.udp_flows.get_mut(&flow))
            else {
                return abi::STATUS_INVALID;
            };
            if flow.stack.is_some() {
                return abi::STATUS_INVALID;
            }
            flow.stack = match unsafe { ForeignDatagramIo::from_raw(stack_socket, stack_socket_io) }
            {
                Ok(stack) => Some(stack),
                Err(_) => return abi::STATUS_INVALID,
            };
            abi::STATUS_OK
        })
    })
}

unsafe extern "C" fn complete(instance: u64, flow: u64, status: u32, reason: SnolBytes) -> u32 {
    snolc_sdk::catch_status(|| {
        if !INSTANCES.contains(instance) || flow == 0 || reason.length > 256 {
            return abi::STATUS_INVALID;
        }
        STATES.with(|states| {
            let mut states = states.borrow_mut();
            let Some(state) = states.get_mut(&instance) else {
                return abi::STATUS_INVALID;
            };
            let reply = match status {
                abi::STATUS_OK => 0,
                abi::STATUS_DENIED => 2,
                abi::STATUS_UNSUPPORTED => 7,
                abi::STATUS_IO => 5,
                _ => 1,
            };
            if let Some(flow) = state.flows.get_mut(&flow) {
                flow.response = socks_response(reply).to_vec();
                flow.response_offset = 0;
                flow.accepted = Some(status == abi::STATUS_OK);
            } else if let Some(flow) = state.udp_flows.get_mut(&flow) {
                flow.accepted = Some(status == abi::STATUS_OK);
            } else {
                return abi::STATUS_INVALID;
            }
            abi::STATUS_OK
        })
    })
}

unsafe extern "C" fn close_flow(instance: u64, flow: u64) -> u32 {
    snolc_sdk::catch_status(|| {
        if !INSTANCES.contains(instance) || flow == 0 {
            return abi::STATUS_INVALID;
        }
        if STATES.with(|states| {
            states.borrow_mut().get_mut(&instance).is_some_and(|state| {
                state.flows.remove(&flow).is_some() | state.udp_flows.remove(&flow).is_some()
            })
        }) {
            abi::STATUS_OK
        } else {
            abi::STATUS_INVALID
        }
    })
}

fn socks_response(reply: u8) -> [u8; 10] {
    [5, reply, 0, 1, 0, 0, 0, 0, 0, 0]
}

fn socks_bound_response(address: SocketAddr) -> Vec<u8> {
    let mut output = vec![5, 0, 0];
    match address {
        SocketAddr::V4(address) => {
            output.push(1);
            output.extend_from_slice(&address.ip().octets());
            output.extend_from_slice(&address.port().to_be_bytes());
        }
        SocketAddr::V6(address) => {
            output.push(4);
            output.extend_from_slice(&address.ip().octets());
            output.extend_from_slice(&address.port().to_be_bytes());
        }
    }
    output
}

fn poll_state(state: &mut State) {
    while state.clients.len() + state.flows.len() + state.associations.len()
        < state.options.max_connections
    {
        match state.listener.accept() {
            Ok((stream, _)) => match ClientConnection::new(stream) {
                Ok(client) => state.clients.push(client),
                Err(_) => continue,
            },
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(_) => break,
        }
    }
    let mut promote = Vec::new();
    for (index, client) in state.clients.iter_mut().enumerate() {
        if client.poll(state.options.max_request_bytes).is_err() {
            client.phase = ClientPhase::Failed;
        }
        if client.ready() {
            promote.push(index);
        }
    }
    for index in promote.into_iter().rev() {
        let connection = state.clients.swap_remove(index);
        let ClientPhase::Ready(request) = &connection.phase else {
            continue;
        };
        let request = request.clone();
        match request.command {
            Command::Connect => {
                let handle = state.next_flow;
                let Some(next) = handle.checked_add(1) else {
                    continue;
                };
                state.next_flow = next;
                if let Ok(flow) = ClientFlow::new(connection, request) {
                    state.flows.insert(handle, flow);
                }
            }
            Command::UdpAssociate
                if state.associations.len() < state.options.max_udp_associations =>
            {
                let listen: SocketAddr = match state.options.listen.parse() {
                    Ok(listen) => listen,
                    Err(_) => continue,
                };
                let bind = SocketAddr::new(listen.ip(), 0);
                let socket = match UdpSocket::bind(bind) {
                    Ok(socket) => socket,
                    Err(_) => continue,
                };
                if socket.set_nonblocking(true).is_err() {
                    continue;
                }
                let mut connection = connection;
                let response = match socket.local_addr() {
                    Ok(address) => socks_bound_response(address),
                    Err(_) => continue,
                };
                connection.queue(&response);
                state.associations.push(UdpAssociation {
                    control: connection,
                    socket,
                    client: None,
                    destinations: HashMap::new(),
                    receive_buffer: vec![0; u16::MAX as usize],
                });
            }
            Command::UdpAssociate => {}
        }
    }
    state
        .clients
        .retain(|client| !matches!(client.phase, ClientPhase::Failed) || !client.output.is_empty());

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

    poll_udp_associations(state, &mut context);
}

fn poll_udp_associations(state: &mut State, context: &mut Context<'_>) {
    let mut packets = Vec::new();
    let mut closed = Vec::new();
    for (index, association) in state.associations.iter_mut().enumerate() {
        if association.control.write_pending().is_err() {
            closed.push(index);
            continue;
        }
        let mut probe = [0; 1];
        match association.control.stream.peek(&mut probe) {
            Ok(0) => {
                closed.push(index);
                continue;
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(_) => {
                closed.push(index);
                continue;
            }
        }
        match association
            .socket
            .recv_from(&mut association.receive_buffer)
        {
            Ok((length, source)) => {
                if association.client.is_some_and(|client| client != source) {
                    continue;
                }
                association.client = Some(source);
                if let Ok(packet) = parse_udp(&association.receive_buffer[..length]) {
                    packets.push((
                        index,
                        source,
                        packet.address,
                        packet.port,
                        packet.payload.to_vec(),
                    ));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(_) => closed.push(index),
        }
    }
    for (index, source, address, port, payload) in packets {
        let key = (address.clone(), port);
        let existing = state.associations[index].destinations.get(&key).copied();
        if let Some(handle) = existing
            && let Some(flow) = state.udp_flows.get_mut(&handle)
        {
            if flow.pending_upload.is_none() {
                flow.pending_upload = Some(payload);
            }
            continue;
        }
        state.associations[index].destinations.remove(&key);
        if state.flows.len() + state.udp_flows.len() >= state.options.max_connections {
            continue;
        }
        let handle = state.next_flow;
        let Some(next) = handle.checked_add(1) else {
            continue;
        };
        let socket = match state.associations[index].socket.try_clone() {
            Ok(socket) => socket,
            Err(_) => continue,
        };
        let flow = match UdpClientFlow::new(socket, source, address, port, payload) {
            Ok(flow) => flow,
            Err(_) => continue,
        };
        state.next_flow = next;
        state.associations[index].destinations.insert(key, handle);
        state.udp_flows.insert(handle, flow);
    }
    let mut finished = Vec::new();
    for (handle, flow) in &mut state.udp_flows {
        match flow.poll(context) {
            Poll::Ready(Ok(true)) | Poll::Ready(Err(_)) => finished.push(*handle),
            Poll::Ready(Ok(false)) | Poll::Pending => {}
        }
    }
    for handle in finished {
        state.udp_flows.remove(&handle);
    }
    closed.sort_unstable();
    closed.dedup();
    for index in closed.into_iter().rev() {
        state.associations.swap_remove(index);
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
    attach_datagram: Some(attach_datagram),
    attach_packet_port: None,
};

snolc_sdk::declare_stateful_module! {
    name: "adapter-socks5",
    description: "name = \"adapter-socks5\"\nroles = [\"client\"]\nplatforms = [\"linux\", \"android\", \"bsd\", \"macos\", \"windows\"]\nconnect = true\nudp_associate = true\nbind = false\nfragments = false\n",
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
    use std::thread;
    use std::time::{Duration, Instant};

    use super::*;

    fn no_wake() -> SnolWakeHandle {
        SnolWakeHandle {
            context: std::ptr::null_mut(),
            wake: None,
            retain: None,
            release: None,
        }
    }

    #[test]
    fn parses_connect_and_rejects_bind() {
        let request = parse_request(&[
            5, 1, 0, 3, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', 1,
            187,
        ])
        .unwrap();
        assert_eq!(request.command, Command::Connect);
        assert_eq!(request.port, 443);
        let mut bind = vec![5, 2, 0, 1, 127, 0, 0, 1, 0, 80];
        assert_eq!(parse_request(&bind), Err(ParseError::BindUnsupported));
        bind[1] = 1;
        assert!(parse_request(&bind).is_ok());
    }

    #[test]
    fn udp_rejects_fragments_without_consuming_payload() {
        let packet = [0, 0, 0, 1, 127, 0, 0, 1, 0, 53, 1, 2, 3];
        assert_eq!(parse_udp(&packet).unwrap().payload, &[1, 2, 3]);
        let mut fragmented = packet;
        fragmented[2] = 1;
        assert_eq!(parse_udp(&fragmented), Err(ParseError::FragmentUnsupported));
    }

    #[test]
    fn native_listener_announces_connect_after_greeting() {
        let reservation = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = reservation.local_addr().unwrap();
        drop(reservation);
        let options = format!(
            "listen = \"{address}\"\nmax_connections = 2\nmax_udp_associations = 1\nmax_request_bytes = 1024\nreject_fragments = true\n"
        );
        let descriptor = unsafe { &*snolc_module_entry() };
        let mut instance = 0;
        assert_eq!(
            unsafe {
                descriptor.create.unwrap()(
                    SnolBytes {
                        pointer: options.as_ptr(),
                        length: options.len(),
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
        let mut client = TcpStream::connect(address).unwrap();
        client.set_nonblocking(true).unwrap();
        client.write_all(&[5, 1, 0]).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut greeting = [0; 2];
        loop {
            unsafe { descriptor.poll.unwrap()(instance, no_wake()) };
            match client.read_exact(&mut greeting) {
                Ok(()) => break,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("greeting failed: {error}"),
            }
            assert!(Instant::now() < deadline);
            thread::yield_now();
        }
        assert_eq!(greeting, [5, 0]);
        client
            .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0, 80])
            .unwrap();
        let adapter = unsafe { &*descriptor.adapter };
        let mut metadata = SnolFlowMetadataV1 {
            struct_size: size_of::<SnolFlowMetadataV1>() as u32,
            kind: 0,
            address_type: 0,
            reserved: 0,
            address: SnolBytes {
                pointer: std::ptr::null(),
                length: 0,
            },
            port: 0,
            reserved2: [0; 6],
            metadata: SnolBytes {
                pointer: std::ptr::null(),
                length: 0,
            },
        };
        let mut flow = 0;
        loop {
            unsafe { descriptor.poll.unwrap()(instance, no_wake()) };
            let status =
                unsafe { adapter.accept.unwrap()(instance, &mut metadata, no_wake(), &mut flow) };
            if status == abi::STATUS_OK {
                break;
            }
            assert_eq!(status, abi::STATUS_PENDING);
            assert!(Instant::now() < deadline);
            thread::yield_now();
        }
        assert_ne!(flow, 0);
        assert_eq!(metadata.kind, abi::FLOW_TCP);
        assert_eq!(metadata.address_type, abi::ADDRESS_IPV4);
        assert_eq!(metadata.port, 80);
        let address = unsafe {
            std::slice::from_raw_parts(metadata.address.pointer, metadata.address.length)
        };
        assert_eq!(address, [127, 0, 0, 1]);
        assert_eq!(
            unsafe {
                adapter.complete.unwrap()(
                    instance,
                    flow,
                    abi::STATUS_DENIED,
                    SnolBytes {
                        pointer: std::ptr::null(),
                        length: 0,
                    },
                )
            },
            abi::STATUS_OK
        );
        let mut response = [0; 10];
        loop {
            unsafe { descriptor.poll.unwrap()(instance, no_wake()) };
            match client.read_exact(&mut response) {
                Ok(()) => break,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("response failed: {error}"),
            }
            assert!(Instant::now() < deadline);
            thread::yield_now();
        }
        assert_eq!(response[1], 2);
        assert_eq!(
            unsafe { descriptor.shutdown.unwrap()(instance) },
            abi::STATUS_OK
        );
        unsafe { descriptor.destroy.unwrap()(instance) };
    }
}
