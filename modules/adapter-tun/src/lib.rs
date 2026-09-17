#![deny(unsafe_op_in_unsafe_fn)]

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::Deserialize;
use snolc_sdk::abi::{self, SnolAdapterApiV1, SnolBytes, SnolWakeHandle};

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
        Ok(Self { file })
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

#[cfg(target_os = "linux")]
#[repr(C)]
struct IfReq {
    name: [libc::c_char; libc::IFNAMSIZ],
    flags: libc::c_short,
    padding: [u8; 24],
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Mode {
    Linux,
    AndroidFd,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Options {
    mode: Mode,
    interface: Option<String>,
    mtu: usize,
    packet_queue_bytes: usize,
}

fn validate_config(config: &[u8], _base: &[u8]) -> Result<(), String> {
    let text = std::str::from_utf8(config).map_err(|_| "config is not UTF-8".to_owned())?;
    let options: Options = toml::from_str(text).map_err(|error| error.to_string())?;
    if options.mtu < 1280 || options.packet_queue_bytes < options.mtu {
        return Err("TUN limits are inconsistent".into());
    }
    match options.mode {
        Mode::Linux
            if options
                .interface
                .as_deref()
                .is_some_and(|name| !name.is_empty()) =>
        {
            Ok(())
        }
        Mode::AndroidFd if options.interface.is_none() => Ok(()),
        _ => Err("TUN mode fields are inconsistent".into()),
    }
}

static FLOW_NEXT: AtomicU64 = AtomicU64::new(1);

unsafe extern "C" fn open(
    instance: u64,
    _request: SnolBytes,
    _wake: SnolWakeHandle,
    output: *mut u64,
) -> u32 {
    snolc_sdk::catch_status(|| {
        if !INSTANCES.contains(instance) {
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
};

snolc_sdk::declare_module! {
    name: "adapter-tun",
    description: "name = \"adapter-tun\"\nroles = [\"client\"]\nplatforms = [\"linux\", \"android\"]\nlinux_tun = true\nandroid_fd = true\n",
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
    use std::os::fd::IntoRawFd;

    use super::*;

    #[test]
    fn owned_fd_clone_has_independent_lifetime() {
        let file = File::open("/dev/null").unwrap();
        let tun = TunFd::from_owned_fd(file.into_raw_fd()).unwrap();
        let clone = tun.try_clone().unwrap();
        drop(tun);
        assert!(clone.file.metadata().is_ok());
    }
}
