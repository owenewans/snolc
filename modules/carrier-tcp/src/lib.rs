#![deny(unsafe_op_in_unsafe_fn)]

use std::cell::RefCell;
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
#[cfg(any(target_os = "android", target_os = "linux"))]
use std::os::fd::{AsRawFd, FromRawFd};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, Waker};

use async_io::Async;
use futures::io::{AsyncRead, AsyncWrite};
use serde::Deserialize;
use snolc_sdk::HostApi;
use snolc_sdk::abi::{
    self, SnolByteIoV1, SnolBytes, SnolBytesMut, SnolCarrierApiV1, SnolIoResult,
    SnolModuleDescriptor, SnolWakeHandle,
};

type ConnectFuture = Pin<Box<dyn Future<Output = io::Result<Async<TcpStream>>>>>;

#[derive(Deserialize)]
#[serde(tag = "mode", rename_all = "lowercase", deny_unknown_fields)]
enum Options {
    Connect {
        endpoint_ip: SocketAddr,
        max_connections: usize,
        nodelay: bool,
    },
    Listen {
        endpoint_ip: SocketAddr,
        max_connections: usize,
        nodelay: bool,
    },
}

impl Options {
    fn validate(&self) -> Result<(), String> {
        let (endpoint, max_connections) = match self {
            Self::Connect {
                endpoint_ip,
                max_connections,
                ..
            }
            | Self::Listen {
                endpoint_ip,
                max_connections,
                ..
            } => (endpoint_ip, max_connections),
        };
        if endpoint.port() == 0 || *max_connections == 0 {
            return Err("TCP carrier options are inconsistent".into());
        }
        Ok(())
    }
}

struct InstanceState {
    host: HostApi,
    mode: Mode,
    max_connections: usize,
    active_connections: usize,
    nodelay: bool,
    pending_connect: Option<ConnectFuture>,
    connect_result: Option<io::Result<Async<TcpStream>>>,
    connect_wake: WakeSlot,
    accept_wake: WakeSlot,
}

enum Mode {
    Connect(SocketAddr),
    Listen(Async<TcpListener>),
}

struct StreamState {
    owner: u64,
    io: Async<TcpStream>,
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

fn parse_options(config: &[u8]) -> Result<Options, String> {
    let text = std::str::from_utf8(config).map_err(|_| "config is not UTF-8".to_owned())?;
    let options: Options = toml::from_str(text).map_err(|error| error.to_string())?;
    options.validate()?;
    Ok(options)
}

unsafe extern "C" fn describe(output: SnolBytesMut, written: *mut usize) -> u32 {
    snolc_sdk::catch_status(|| unsafe {
        snolc_sdk::module::write_output(
            b"name = \"carrier-tcp\"\nroles = [\"client\", \"server\"]\nordered = true\n",
            output,
            written,
        )
    })
}

unsafe extern "C" fn validate_config(
    config: SnolBytes,
    _base: SnolBytes,
    error: SnolBytesMut,
    written: *mut usize,
) -> u32 {
    snolc_sdk::catch_status(|| {
        let config = match unsafe { snolc_sdk::module::input(config) } {
            Ok(config) => config,
            Err(status) => return status,
        };
        match parse_options(config) {
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
    _base: SnolBytes,
    host: *const abi::SnolHostApiV1,
    output: *mut u64,
) -> u32 {
    snolc_sdk::catch_status(|| {
        let config = match unsafe { snolc_sdk::module::input(config) } {
            Ok(config) => config,
            Err(status) => return status,
        };
        let options = match parse_options(config) {
            Ok(options) => options,
            Err(_) => return abi::STATUS_INVALID,
        };
        let Some(output) = (unsafe { output.as_mut() }) else {
            return abi::STATUS_INVALID;
        };
        let host = match unsafe { HostApi::from_raw(host) } {
            Ok(host) => host,
            Err(status) => return status,
        };
        let (mode, max_connections, nodelay) = match options {
            Options::Connect {
                endpoint_ip,
                max_connections,
                nodelay,
            } => (Mode::Connect(endpoint_ip), max_connections, nodelay),
            Options::Listen {
                endpoint_ip,
                max_connections,
                nodelay,
            } => {
                let listener = match TcpListener::bind(endpoint_ip).and_then(Async::new) {
                    Ok(listener) => listener,
                    Err(_) => return abi::STATUS_IO,
                };
                (Mode::Listen(listener), max_connections, nodelay)
            }
        };
        let handle = INSTANCE_NEXT.fetch_add(1, Ordering::Relaxed);
        if handle == 0 {
            return abi::STATUS_RESOURCE;
        }
        INSTANCES.with(|instances| {
            instances.borrow_mut().insert(
                handle,
                InstanceState {
                    host,
                    mode,
                    max_connections,
                    active_connections: 0,
                    nodelay,
                    pending_connect: None,
                    connect_result: None,
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
            if let Some(connect) = state.pending_connect.as_mut() {
                let mut context = Context::from_waker(Waker::noop());
                if let Poll::Ready(result) = connect.as_mut().poll(&mut context) {
                    state.pending_connect = None;
                    state.connect_result = Some(result);
                    state.connect_wake.wake();
                }
            }
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
        if INSTANCES.with(|instances| instances.borrow().contains_key(&instance)) {
            abi::STATUS_OK
        } else {
            abi::STATUS_INVALID
        }
    })
}

unsafe extern "C" fn destroy(instance: u64) {
    let _ = std::panic::catch_unwind(|| {
        STREAMS.with(|streams| {
            streams
                .borrow_mut()
                .retain(|_, stream| stream.owner != instance)
        });
        INSTANCES.with(|instances| instances.borrow_mut().remove(&instance));
    });
}

unsafe extern "C" fn connect(
    instance: u64,
    endpoint: SnolBytes,
    wake: SnolWakeHandle,
    output: *mut u64,
) -> u32 {
    snolc_sdk::catch_status(|| {
        let requested = match unsafe { snolc_sdk::module::input(endpoint) } {
            Ok([]) => None,
            Ok(bytes) => match std::str::from_utf8(bytes)
                .ok()
                .and_then(|value| value.parse::<SocketAddr>().ok())
            {
                Some(endpoint) => Some(endpoint),
                None => return abi::STATUS_INVALID,
            },
            Err(status) => return status,
        };
        INSTANCES.with(|instances| {
            let mut instances = instances.borrow_mut();
            let Some(state) = instances.get_mut(&instance) else {
                return abi::STATUS_INVALID;
            };
            if state.active_connections >= state.max_connections {
                return abi::STATUS_RESOURCE;
            }
            let configured = match &state.mode {
                Mode::Connect(endpoint) => *endpoint,
                Mode::Listen(_) => return abi::STATUS_UNSUPPORTED,
            };
            let endpoint = requested.unwrap_or(configured);
            if let Some(result) = state.connect_result.take() {
                return match result {
                    Ok(stream) => finish_stream(instance, stream, state, output),
                    Err(_) => abi::STATUS_IO,
                };
            }
            if state.pending_connect.is_none() {
                state.pending_connect = Some(Box::pin(protected_connect(endpoint, state.host)));
            }
            state.connect_wake.replace(wake);
            abi::STATUS_PENDING
        })
    })
}

#[cfg(any(target_os = "android", target_os = "linux"))]
async fn protected_connect(endpoint: SocketAddr, host: HostApi) -> io::Result<Async<TcpStream>> {
    let domain = match endpoint {
        SocketAddr::V4(_) => libc::AF_INET,
        SocketAddr::V6(_) => libc::AF_INET6,
    };
    let raw = unsafe {
        libc::socket(
            domain,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            libc::IPPROTO_TCP,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let stream = unsafe { TcpStream::from_raw_fd(raw) };
    host.protect_socket(i64::from(stream.as_raw_fd()))
        .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "socket protect failed"))?;
    let result = match endpoint {
        SocketAddr::V4(endpoint) => {
            let [a, b, c, d] = endpoint.ip().octets();
            let address = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: endpoint.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes([a, b, c, d]),
                },
                sin_zero: [0; 8],
            };
            unsafe {
                libc::connect(
                    stream.as_raw_fd(),
                    (&raw const address).cast::<libc::sockaddr>(),
                    size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            }
        }
        SocketAddr::V6(endpoint) => {
            let address = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: endpoint.port().to_be(),
                sin6_flowinfo: endpoint.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: endpoint.ip().octets(),
                },
                sin6_scope_id: endpoint.scope_id(),
            };
            unsafe {
                libc::connect(
                    stream.as_raw_fd(),
                    (&raw const address).cast::<libc::sockaddr>(),
                    size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                )
            }
        }
    };
    if result < 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(error);
        }
    }
    let stream = Async::new(stream)?;
    stream.writable().await?;
    if let Some(error) = stream.get_ref().take_error()? {
        return Err(error);
    }
    Ok(stream)
}

#[cfg(not(any(target_os = "android", target_os = "linux")))]
async fn protected_connect(endpoint: SocketAddr, host: HostApi) -> io::Result<Async<TcpStream>> {
    let stream = Async::<TcpStream>::connect(endpoint).await?;
    #[cfg(unix)]
    let socket = {
        use std::os::fd::AsRawFd;
        i64::from(stream.get_ref().as_raw_fd())
    };
    #[cfg(windows)]
    let socket = {
        use std::os::windows::io::AsRawSocket;
        i64::try_from(stream.get_ref().as_raw_socket())
            .map_err(|_| io::Error::other("socket handle does not fit i64"))?
    };
    host.protect_socket(socket)
        .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "socket protect failed"))?;
    Ok(stream)
}

unsafe extern "C" fn accept(instance: u64, wake: SnolWakeHandle, output: *mut u64) -> u32 {
    snolc_sdk::catch_status(|| {
        INSTANCES.with(|instances| {
            let mut instances = instances.borrow_mut();
            let Some(state) = instances.get_mut(&instance) else {
                return abi::STATUS_INVALID;
            };
            if state.active_connections >= state.max_connections {
                return abi::STATUS_RESOURCE;
            }
            let Mode::Listen(listener) = &state.mode else {
                return abi::STATUS_UNSUPPORTED;
            };
            match listener.get_ref().accept() {
                Ok((stream, _)) => match Async::new(stream) {
                    Ok(stream) => finish_stream(instance, stream, state, output),
                    Err(_) => abi::STATUS_IO,
                },
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    state.accept_wake.replace(wake);
                    abi::STATUS_PENDING
                }
                Err(_) => abi::STATUS_IO,
            }
        })
    })
}

fn finish_stream(
    owner: u64,
    stream: Async<TcpStream>,
    instance: &mut InstanceState,
    output: *mut u64,
) -> u32 {
    let Some(output) = (unsafe { output.as_mut() }) else {
        return abi::STATUS_INVALID;
    };
    if stream.get_ref().set_nodelay(instance.nodelay).is_err() {
        return abi::STATUS_IO;
    }
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
                Poll::Ready(Ok(0)) => SnolIoResult::error(abi::STATUS_IO),
                Poll::Ready(Ok(count)) => SnolIoResult::progress(count),
                Poll::Ready(Err(_)) => SnolIoResult::error(abi::STATUS_IO),
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
    action: impl FnOnce(&mut Async<TcpStream>, &mut Context<'_>) -> Poll<io::Result<()>>,
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
    name: c"carrier-tcp".as_ptr(),
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
    use std::ffi::c_void;
    use std::sync::atomic::{AtomicBool, AtomicUsize};

    use super::*;

    struct ProtectState {
        allow: AtomicBool,
        calls: AtomicUsize,
    }

    unsafe extern "C" fn protect(context: *mut c_void, _socket: i64) -> u32 {
        let state = unsafe { &*(context as *const ProtectState) };
        state.calls.fetch_add(1, Ordering::Relaxed);
        if state.allow.load(Ordering::Relaxed) {
            abi::STATUS_OK
        } else {
            abi::STATUS_DENIED
        }
    }

    fn host_api(state: &ProtectState) -> abi::SnolHostApiV1 {
        abi::SnolHostApiV1 {
            struct_size: size_of::<abi::SnolHostApiV1>() as u32,
            reserved: 0,
            context: (state as *const ProtectState).cast_mut().cast(),
            now_monotonic_nanos: None,
            set_timer: None,
            emit_event: None,
            context_get: None,
            context_set: None,
            protect_socket: Some(protect),
        }
    }

    #[test]
    fn strict_modes_require_explicit_limits() {
        assert!(parse_options(
            b"mode = \"connect\"\nendpoint_ip = \"127.0.0.1:443\"\nmax_connections = 2\nnodelay = true\n"
        )
        .is_ok());
        assert!(parse_options(b"mode = \"connect\"\nendpoint_ip = \"example.com:443\"\n").is_err());
    }

    #[test]
    fn byte_io_round_trip_uses_tcp() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let client = TcpStream::connect(address).unwrap();
        let (server, _) = listener.accept().unwrap();
        client.set_nonblocking(true).unwrap();
        server.set_nonblocking(true).unwrap();
        let client = Async::new(client).unwrap();
        let server = Async::new(server).unwrap();
        async_io::block_on(async {
            use futures::io::{AsyncReadExt, AsyncWriteExt};

            let mut client = client;
            let mut server = server;
            client.write_all(b"snolc").await.unwrap();
            let mut output = [0; 5];
            server.read_exact(&mut output).await.unwrap();
            assert_eq!(&output, b"snolc");
        });
    }

    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[test]
    fn socket_protection_runs_before_connect_and_denial_closes_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let state = ProtectState {
            allow: AtomicBool::new(false),
            calls: AtomicUsize::new(0),
        };
        let raw = host_api(&state);
        let host = unsafe { HostApi::from_raw(&raw) }.unwrap();
        let error = async_io::block_on(protected_connect(listener.local_addr().unwrap(), host))
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(state.calls.load(Ordering::Relaxed), 1);
        assert!(
            matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
        );

        state.allow.store(true, Ordering::Relaxed);
        let stream =
            async_io::block_on(protected_connect(listener.local_addr().unwrap(), host)).unwrap();
        let (_accepted, _) = listener.accept().unwrap();
        assert_eq!(state.calls.load(Ordering::Relaxed), 2);
        drop(stream);
    }
}
