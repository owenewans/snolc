#![deny(unsafe_op_in_unsafe_fn)]

use std::cell::RefCell;
use std::collections::HashMap;
use std::fs::File;
#[cfg(target_os = "linux")]
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::task::{Context, Poll, Waker};

use serde::Deserialize;
use snolc_sdk::abi::{self, SnolAdapterApiV1, SnolDatagramIoV1, SnolHostApiV1, SnolWakeHandle};
use snolc_sdk::{DatagramIo, DatagramRecv, ForeignDatagramIo};

pub struct TunFd {
    file: File,
}

impl TunFd {
    #[cfg(target_os = "linux")]
    pub fn open(name: &str) -> io::Result<Self> {
        if name.is_empty() || name.len() >= libc::IFNAMSIZ {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid TUN name",
            ));
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")?;
        let mut request = IfReq {
            name: [0; libc::IFNAMSIZ],
            flags: (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short,
            padding: [0; 24],
        };
        for (target, source) in request.name.iter_mut().zip(name.bytes()) {
            *target = source as libc::c_char;
        }
        // fd and request match the Linux TUNSETIFF ABI.
        let result = unsafe { libc::ioctl(file.as_raw_fd(), libc::TUNSETIFF, &mut request) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        set_nonblocking(&file)?;
        Ok(Self { file })
    }

    pub fn from_owned_fd(fd: RawFd) -> io::Result<Self> {
        if fd < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid TUN fd",
            ));
        }
        // caller transfers ownership of a valid descriptor.
        let file = unsafe { File::from_raw_fd(fd) };
        set_nonblocking(&file)?;
        Ok(Self { file })
    }

    pub fn duplicate_fd(fd: RawFd) -> io::Result<Self> {
        if fd < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid TUN fd",
            ));
        }
        let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
        if duplicate < 0 {
            return Err(io::Error::last_os_error());
        }
        Self::from_owned_fd(duplicate)
    }

    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            file: self.file.try_clone()?,
        })
    }

    pub fn read_packet(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.file.read(output)
    }

    pub fn write_packet(&mut self, packet: &[u8]) -> io::Result<()> {
        self.file.write_all(packet)
    }
}

fn set_nonblocking(file: &File) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct IfReq {
    name: [libc::c_char; libc::IFNAMSIZ],
    flags: libc::c_short,
    padding: [u8; 24],
}

#[derive(Deserialize)]
#[serde(tag = "mode", rename_all = "kebab-case", deny_unknown_fields)]
enum Options {
    Linux {
        interface: String,
        mtu: usize,
        packet_queue_bytes: usize,
    },
    AndroidFd {
        fd: RawFd,
        mtu: usize,
        packet_queue_bytes: usize,
    },
}

impl Options {
    fn limits(&self) -> (usize, usize) {
        match self {
            Self::Linux {
                mtu,
                packet_queue_bytes,
                ..
            }
            | Self::AndroidFd {
                mtu,
                packet_queue_bytes,
                ..
            } => (*mtu, *packet_queue_bytes),
        }
    }
}

fn parse_options(config: &[u8]) -> Result<Options, String> {
    let text = std::str::from_utf8(config).map_err(|_| "config is not UTF-8".to_owned())?;
    let options: Options = toml::from_str(text).map_err(|error| error.to_string())?;
    let (mtu, packet_queue_bytes) = options.limits();
    if mtu < 1280 || mtu > u16::MAX as usize || packet_queue_bytes < mtu {
        return Err("TUN limits are inconsistent".into());
    }
    match &options {
        Options::Linux { interface, .. } if !interface.is_empty() => Ok(options),
        Options::AndroidFd { fd, .. } if *fd >= 0 => Ok(options),
        _ => Err("TUN mode fields are inconsistent".into()),
    }
}

fn validate_config(config: &[u8], _base: &[u8]) -> Result<(), String> {
    parse_options(config).map(|_| ())
}

struct State {
    tun: TunFd,
    packet_port: Option<ForeignDatagramIo>,
    ingress: Vec<u8>,
    ingress_len: Option<usize>,
    egress: Vec<u8>,
    egress_len: Option<usize>,
}

thread_local! {
    static STATES: RefCell<HashMap<u64, State>> = RefCell::new(HashMap::new());
}

fn initialize(
    instance: u64,
    config: &[u8],
    _base: &[u8],
    _host: *const SnolHostApiV1,
) -> Result<(), u32> {
    let options = parse_options(config).map_err(|_| abi::STATUS_INVALID)?;
    let (mtu, _) = options.limits();
    let tun = match options {
        Options::Linux { interface, .. } => {
            #[cfg(target_os = "linux")]
            {
                TunFd::open(&interface).map_err(|_| abi::STATUS_IO)?
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = interface;
                return Err(abi::STATUS_UNSUPPORTED);
            }
        }
        Options::AndroidFd { fd, .. } => TunFd::duplicate_fd(fd).map_err(|_| abi::STATUS_IO)?,
    };
    STATES.with(|states| {
        states.borrow_mut().insert(
            instance,
            State {
                tun,
                packet_port: None,
                ingress: vec![0; mtu],
                ingress_len: None,
                egress: vec![0; mtu],
                egress_len: None,
            },
        );
    });
    Ok(())
}

fn poll_instance(instance: u64, _wake: SnolWakeHandle) -> u32 {
    STATES.with(|states| {
        let mut states = states.borrow_mut();
        let Some(state) = states.get_mut(&instance) else {
            return abi::STATUS_INVALID;
        };
        let Some(packet_port) = state.packet_port.as_mut() else {
            return abi::STATUS_PENDING;
        };
        let mut context = Context::from_waker(Waker::noop());
        if let Some(length) = state.ingress_len {
            match packet_port.poll_send_datagram(&mut context, &state.ingress[..length]) {
                Poll::Ready(Ok(())) => state.ingress_len = None,
                Poll::Ready(Err(_)) => return abi::STATUS_IO,
                Poll::Pending => {}
            }
        }
        if state.ingress_len.is_none() {
            match state.tun.read_packet(&mut state.ingress) {
                Ok(0) => return abi::STATUS_IO,
                Ok(length) => state.ingress_len = Some(length),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => return abi::STATUS_IO,
            }
            if let Some(length) = state.ingress_len {
                match packet_port.poll_send_datagram(&mut context, &state.ingress[..length]) {
                    Poll::Ready(Ok(())) => state.ingress_len = None,
                    Poll::Ready(Err(_)) => return abi::STATUS_IO,
                    Poll::Pending => {}
                }
            }
        }
        if state.egress_len.is_none() {
            match packet_port.poll_recv_datagram(&mut context, &mut state.egress) {
                Poll::Ready(Ok(DatagramRecv::Datagram(length))) => {
                    state.egress_len = Some(length);
                }
                Poll::Ready(Ok(DatagramRecv::BufferTooSmall(_))) | Poll::Ready(Err(_)) => {
                    return abi::STATUS_IO;
                }
                Poll::Ready(Ok(DatagramRecv::Closed)) => return abi::STATUS_IO,
                Poll::Pending => {}
            }
        }
        if let Some(length) = state.egress_len {
            match state.tun.file.write(&state.egress[..length]) {
                Ok(written) if written == length => state.egress_len = None,
                Ok(_) => return abi::STATUS_IO,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => return abi::STATUS_IO,
            }
        }
        abi::STATUS_PENDING
    })
}

fn control_instance(_instance: u64, _request: &[u8]) -> Result<Vec<u8>, u32> {
    Err(abi::STATUS_UNSUPPORTED)
}

fn shutdown_instance(instance: u64) -> u32 {
    if STATES.with(|states| states.borrow().contains_key(&instance)) {
        abi::STATUS_OK
    } else {
        abi::STATUS_INVALID
    }
}

fn destroy_instance(instance: u64) {
    STATES.with(|states| states.borrow_mut().remove(&instance));
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

unsafe extern "C" fn attach_packet_port(
    instance: u64,
    packet_port: u64,
    packet_port_io: *const SnolDatagramIoV1,
) -> u32 {
    snolc_sdk::catch_status(|| {
        let packet_port = match unsafe { ForeignDatagramIo::from_raw(packet_port, packet_port_io) }
        {
            Ok(packet_port) => packet_port,
            Err(_) => return abi::STATUS_INVALID,
        };
        STATES.with(|states| {
            let mut states = states.borrow_mut();
            let Some(state) = states.get_mut(&instance) else {
                return abi::STATUS_INVALID;
            };
            if state.packet_port.is_some() {
                return abi::STATUS_INVALID;
            }
            state.packet_port = Some(packet_port);
            abi::STATUS_OK
        })
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
    attach_datagram: None,
    attach_packet_port: Some(attach_packet_port),
    resolve: None,
};

snolc_sdk::declare_stateful_module! {
    name: "adapter-tun",
    description: "name = \"adapter-tun\"\nroles = [\"client\"]\nplatforms = [\"linux\", \"android\"]\nlinux_tun = true\nandroid_fd = true\n",
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
    use std::os::fd::{AsRawFd, IntoRawFd};
    use std::os::unix::net::UnixDatagram;
    use std::time::Duration;

    use super::*;

    #[test]
    fn owned_fd_clone_has_independent_lifetime() {
        let file = File::open("/dev/null").unwrap();
        let tun = TunFd::from_owned_fd(file.into_raw_fd()).unwrap();
        let clone = tun.try_clone().unwrap();
        drop(tun);
        assert!(clone.file.metadata().is_ok());
    }

    #[test]
    fn duplicated_fd_does_not_take_platform_ownership() {
        let platform = File::open("/dev/null").unwrap();
        let tun = TunFd::duplicate_fd(platform.as_raw_fd()).unwrap();
        drop(platform);
        assert!(tun.file.metadata().is_ok());
    }

    thread_local! {
        static RECEIVED: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
        static OUTGOING: RefCell<VecDeque<Vec<u8>>> = const { RefCell::new(VecDeque::new()) };
    }

    unsafe extern "C" fn fake_recv(
        _handle: u64,
        output: abi::SnolBytesMut,
        _wake: SnolWakeHandle,
    ) -> abi::SnolIoResult {
        OUTGOING.with(|outgoing| {
            let mut outgoing = outgoing.borrow_mut();
            let Some(packet) = outgoing.front() else {
                return abi::SnolIoResult::pending();
            };
            if output.length < packet.len() {
                return abi::SnolIoResult::buffer_too_small(packet.len());
            }
            unsafe { std::ptr::copy_nonoverlapping(packet.as_ptr(), output.pointer, packet.len()) };
            let length = packet.len();
            outgoing.pop_front();
            abi::SnolIoResult::progress(length)
        })
    }

    unsafe extern "C" fn fake_send(
        _handle: u64,
        input: abi::SnolBytes,
        _wake: SnolWakeHandle,
    ) -> abi::SnolIoResult {
        let packet = if input.length == 0 {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(input.pointer, input.length) }.to_vec()
        };
        RECEIVED.with(|received| received.borrow_mut().push(packet));
        abi::SnolIoResult::progress(input.length)
    }

    unsafe extern "C" fn fake_close(_handle: u64) -> u32 {
        abi::STATUS_OK
    }

    static FAKE_PACKET_IO: SnolDatagramIoV1 = SnolDatagramIoV1 {
        struct_size: size_of::<SnolDatagramIoV1>() as u32,
        reserved: 0,
        recv_datagram: Some(fake_recv),
        send_datagram: Some(fake_send),
        close: Some(fake_close),
    };

    #[test]
    fn fd_runtime_moves_packets_in_both_directions() {
        let (module, platform) = UnixDatagram::pair().unwrap();
        platform
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let tun = TunFd::from_owned_fd(module.into_raw_fd()).unwrap();
        let packet_port = unsafe { ForeignDatagramIo::from_raw(1, &FAKE_PACKET_IO) }.unwrap();
        let instance = 99_001;
        STATES.with(|states| {
            states.borrow_mut().insert(
                instance,
                State {
                    tun,
                    packet_port: Some(packet_port),
                    ingress: vec![0; 1280],
                    ingress_len: None,
                    egress: vec![0; 1280],
                    egress_len: None,
                },
            );
        });
        let mut packet = vec![0; 20];
        packet[0] = 0x45;
        packet[16..20].copy_from_slice(&[203, 0, 113, 1]);
        platform.send(&packet).unwrap();
        let wake = SnolWakeHandle {
            context: std::ptr::null_mut(),
            wake: None,
            retain: None,
            release: None,
        };
        assert_eq!(poll_instance(instance, wake), abi::STATUS_PENDING);
        RECEIVED.with(|received| assert_eq!(received.borrow().as_slice(), [packet.clone()]));

        OUTGOING.with(|outgoing| outgoing.borrow_mut().push_back(packet.clone()));
        assert_eq!(poll_instance(instance, wake), abi::STATUS_PENDING);
        let mut output = [0; 1280];
        let length = platform.recv(&mut output).unwrap();
        assert_eq!(&output[..length], packet);
        destroy_instance(instance);
        RECEIVED.with(|received| received.borrow_mut().clear());
        OUTGOING.with(|outgoing| outgoing.borrow_mut().clear());
    }
}
