use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use snolc_abi::{SnolBytes, SnolBytesMut};

/// # Safety
///
/// `written`, when non-null, must be writable for one `usize`.
pub unsafe extern "C" fn unsupported_adapter_accept(
    _instance: u64,
    _request: SnolBytesMut,
    written: *mut usize,
    _wake: snolc_abi::SnolWakeHandle,
    _flow: *mut u64,
) -> u32 {
    if let Some(written) = unsafe { written.as_mut() } {
        *written = 0;
    }
    snolc_abi::STATUS_UNSUPPORTED
}

/// # Safety
///
/// ABI arguments must follow the adapter contract.
pub unsafe extern "C" fn unsupported_adapter_attach(
    _instance: u64,
    _flow: u64,
    _stack_socket: u64,
    _stack_socket_io: *const snolc_abi::SnolByteIoV1,
) -> u32 {
    snolc_abi::STATUS_UNSUPPORTED
}

/// # Safety
///
/// ABI arguments must follow the adapter contract.
pub unsafe extern "C" fn unsupported_adapter_complete(
    _instance: u64,
    _flow: u64,
    _status: u32,
    _reason: SnolBytes,
) -> u32 {
    snolc_abi::STATUS_UNSUPPORTED
}

/// # Safety
///
/// ABI arguments must follow the adapter contract.
pub unsafe extern "C" fn unsupported_adapter_close(_instance: u64, _flow: u64) -> u32 {
    snolc_abi::STATUS_UNSUPPORTED
}

pub struct Instances {
    next: AtomicU64,
    active: OnceLock<Mutex<HashSet<u64>>>,
}

impl Instances {
    pub const fn new() -> Self {
        Self {
            next: AtomicU64::new(1),
            active: OnceLock::new(),
        }
    }

    pub fn create(&self) -> Result<u64, u32> {
        let handle = self.next.fetch_add(1, Ordering::Relaxed);
        if handle == 0 {
            return Err(snolc_abi::STATUS_RESOURCE);
        }
        self.active()
            .lock()
            .map_err(|_| snolc_abi::STATUS_INTERNAL)?
            .insert(handle);
        Ok(handle)
    }

    pub fn contains(&self, handle: u64) -> bool {
        handle != 0
            && self
                .active()
                .lock()
                .map(|active| active.contains(&handle))
                .unwrap_or(false)
    }

    pub fn remove(&self, handle: u64) {
        if let Ok(mut active) = self.active().lock() {
            active.remove(&handle);
        }
    }

    fn active(&self) -> &Mutex<HashSet<u64>> {
        self.active.get_or_init(|| Mutex::new(HashSet::new()))
    }
}

impl Default for Instances {
    fn default() -> Self {
        Self::new()
    }
}

/// # Safety
///
/// `bytes` must reference readable memory for the returned borrow.
pub unsafe fn input<'a>(bytes: SnolBytes) -> Result<&'a [u8], u32> {
    if bytes.pointer.is_null() && bytes.length != 0 {
        return Err(snolc_abi::STATUS_INVALID);
    }
    if bytes.length == 0 {
        return Ok(&[]);
    }
    // caller guarantees the borrowed input for the duration of the call.
    Ok(unsafe { std::slice::from_raw_parts(bytes.pointer, bytes.length) })
}

/// # Safety
///
/// `output` and `written` must reference writable memory for this call.
pub unsafe fn write_output(data: &[u8], output: SnolBytesMut, written: *mut usize) -> u32 {
    let Some(written) = (unsafe { written.as_mut() }) else {
        return snolc_abi::STATUS_INVALID;
    };
    *written = data.len();
    if output.length < data.len() {
        return snolc_abi::STATUS_RESOURCE;
    }
    if output.pointer.is_null() && !data.is_empty() {
        return snolc_abi::STATUS_INVALID;
    }
    if !data.is_empty() {
        // caller guarantees writable output for output.length bytes.
        unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), output.pointer, data.len()) };
    }
    snolc_abi::STATUS_OK
}

#[macro_export]
macro_rules! declare_module {
    (
        name: $name:literal,
        description: $description:literal,
        class_mask: $class_mask:expr,
        validate: $validate:path,
        byte_io: $byte_io:expr,
        datagram_io: $datagram_io:expr,
        adapter: $adapter:expr,
        protection: $protection:expr,
        carrier: $carrier:expr,
        policy: $policy:expr $(,)?
    ) => {
        static INSTANCES: $crate::module::Instances = $crate::module::Instances::new();

        unsafe extern "C" fn ffi_describe(
            output: $crate::abi::SnolBytesMut,
            written: *mut usize,
        ) -> u32 {
            $crate::catch_status(|| unsafe {
                $crate::module::write_output($description.as_bytes(), output, written)
            })
        }

        unsafe extern "C" fn ffi_validate_config(
            config: $crate::abi::SnolBytes,
            base: $crate::abi::SnolBytes,
            error: $crate::abi::SnolBytesMut,
            written: *mut usize,
        ) -> u32 {
            $crate::catch_status(|| unsafe {
                let config = match $crate::module::input(config) {
                    Ok(value) => value,
                    Err(status) => return status,
                };
                let base = match $crate::module::input(base) {
                    Ok(value) => value,
                    Err(status) => return status,
                };
                match $validate(config, base) {
                    Ok(()) => $crate::module::write_output(&[], error, written),
                    Err(message) => {
                        let _ = $crate::module::write_output(message.as_bytes(), error, written);
                        $crate::abi::STATUS_INVALID
                    }
                }
            })
        }

        unsafe extern "C" fn ffi_create(
            _config: $crate::abi::SnolBytes,
            _base: $crate::abi::SnolBytes,
            _host: *const $crate::abi::SnolHostApiV1,
            output: *mut u64,
        ) -> u32 {
            $crate::catch_status(|| {
                let Some(output) = (unsafe { output.as_mut() }) else {
                    return $crate::abi::STATUS_INVALID;
                };
                match INSTANCES.create() {
                    Ok(handle) => {
                        *output = handle;
                        $crate::abi::STATUS_OK
                    }
                    Err(status) => status,
                }
            })
        }

        unsafe extern "C" fn ffi_poll(instance: u64, _wake: $crate::abi::SnolWakeHandle) -> u32 {
            $crate::catch_status(|| {
                if INSTANCES.contains(instance) {
                    $crate::abi::STATUS_PENDING
                } else {
                    $crate::abi::STATUS_INVALID
                }
            })
        }

        unsafe extern "C" fn ffi_control(
            instance: u64,
            _request: $crate::abi::SnolBytes,
            _response: $crate::abi::SnolBytesMut,
            written: *mut usize,
        ) -> u32 {
            $crate::catch_status(|| {
                if !written.is_null() {
                    unsafe { *written = 0 };
                }
                if INSTANCES.contains(instance) {
                    $crate::abi::STATUS_UNSUPPORTED
                } else {
                    $crate::abi::STATUS_INVALID
                }
            })
        }

        unsafe extern "C" fn ffi_shutdown(instance: u64) -> u32 {
            $crate::catch_status(|| {
                if INSTANCES.contains(instance) {
                    $crate::abi::STATUS_OK
                } else {
                    $crate::abi::STATUS_INVALID
                }
            })
        }

        unsafe extern "C" fn ffi_destroy(instance: u64) {
            let _ = std::panic::catch_unwind(|| INSTANCES.remove(instance));
        }

        static DESCRIPTOR: $crate::abi::SnolModuleDescriptor = $crate::abi::SnolModuleDescriptor {
            struct_size: core::mem::size_of::<$crate::abi::SnolModuleDescriptor>() as u32,
            wire_version: $crate::abi::WIRE_VERSION,
            class_mask: $class_mask,
            reserved: 0,
            name: concat!($name, "\0").as_ptr().cast(),
            describe: Some(ffi_describe),
            validate_config: Some(ffi_validate_config),
            create: Some(ffi_create),
            poll: Some(ffi_poll),
            control: Some(ffi_control),
            shutdown: Some(ffi_shutdown),
            destroy: Some(ffi_destroy),
            byte_io: $byte_io,
            datagram_io: $datagram_io,
            adapter: $adapter,
            protection: $protection,
            carrier: $carrier,
            policy: $policy,
        };

        #[unsafe(no_mangle)]
        pub extern "C" fn snolc_module_entry() -> *const $crate::abi::SnolModuleDescriptor {
            &DESCRIPTOR
        }
    };
}

#[macro_export]
macro_rules! declare_stateful_module {
    (
        name: $name:literal,
        description: $description:literal,
        class_mask: $class_mask:expr,
        validate: $validate:path,
        initialize: $initialize:path,
        poll: $poll:path,
        control: $control:path,
        shutdown: $shutdown:path,
        destroy: $destroy:path,
        byte_io: $byte_io:expr,
        datagram_io: $datagram_io:expr,
        adapter: $adapter:expr,
        protection: $protection:expr,
        carrier: $carrier:expr,
        policy: $policy:expr $(,)?
    ) => {
        static INSTANCES: $crate::module::Instances = $crate::module::Instances::new();

        unsafe extern "C" fn ffi_describe(
            output: $crate::abi::SnolBytesMut,
            written: *mut usize,
        ) -> u32 {
            $crate::catch_status(|| unsafe {
                $crate::module::write_output($description.as_bytes(), output, written)
            })
        }

        unsafe extern "C" fn ffi_validate_config(
            config: $crate::abi::SnolBytes,
            base: $crate::abi::SnolBytes,
            error: $crate::abi::SnolBytesMut,
            written: *mut usize,
        ) -> u32 {
            $crate::catch_status(|| unsafe {
                let config = match $crate::module::input(config) {
                    Ok(value) => value,
                    Err(status) => return status,
                };
                let base = match $crate::module::input(base) {
                    Ok(value) => value,
                    Err(status) => return status,
                };
                match $validate(config, base) {
                    Ok(()) => $crate::module::write_output(&[], error, written),
                    Err(message) => {
                        let _ = $crate::module::write_output(message.as_bytes(), error, written);
                        $crate::abi::STATUS_INVALID
                    }
                }
            })
        }

        unsafe extern "C" fn ffi_create(
            config: $crate::abi::SnolBytes,
            base: $crate::abi::SnolBytes,
            host: *const $crate::abi::SnolHostApiV1,
            output: *mut u64,
        ) -> u32 {
            $crate::catch_status(|| {
                let Some(output) = (unsafe { output.as_mut() }) else {
                    return $crate::abi::STATUS_INVALID;
                };
                let config = match unsafe { $crate::module::input(config) } {
                    Ok(value) => value,
                    Err(status) => return status,
                };
                let base = match unsafe { $crate::module::input(base) } {
                    Ok(value) => value,
                    Err(status) => return status,
                };
                let handle = match INSTANCES.create() {
                    Ok(handle) => handle,
                    Err(status) => return status,
                };
                match $initialize(handle, config, base, host) {
                    Ok(()) => {
                        *output = handle;
                        $crate::abi::STATUS_OK
                    }
                    Err(status) => {
                        INSTANCES.remove(handle);
                        status
                    }
                }
            })
        }

        unsafe extern "C" fn ffi_poll(instance: u64, wake: $crate::abi::SnolWakeHandle) -> u32 {
            $crate::catch_status(|| {
                if INSTANCES.contains(instance) {
                    $poll(instance, wake)
                } else {
                    $crate::abi::STATUS_INVALID
                }
            })
        }

        unsafe extern "C" fn ffi_control(
            instance: u64,
            request: $crate::abi::SnolBytes,
            response: $crate::abi::SnolBytesMut,
            written: *mut usize,
        ) -> u32 {
            $crate::catch_status(|| unsafe {
                if !INSTANCES.contains(instance) {
                    return $crate::abi::STATUS_INVALID;
                }
                let request = match $crate::module::input(request) {
                    Ok(value) => value,
                    Err(status) => return status,
                };
                match $control(instance, request) {
                    Ok(output) => $crate::module::write_output(&output, response, written),
                    Err(status) => {
                        if let Some(written) = written.as_mut() {
                            *written = 0;
                        }
                        status
                    }
                }
            })
        }

        unsafe extern "C" fn ffi_shutdown(instance: u64) -> u32 {
            $crate::catch_status(|| {
                if INSTANCES.contains(instance) {
                    $shutdown(instance)
                } else {
                    $crate::abi::STATUS_INVALID
                }
            })
        }

        unsafe extern "C" fn ffi_destroy(instance: u64) {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                $destroy(instance);
                INSTANCES.remove(instance);
            }));
        }

        static DESCRIPTOR: $crate::abi::SnolModuleDescriptor = $crate::abi::SnolModuleDescriptor {
            struct_size: core::mem::size_of::<$crate::abi::SnolModuleDescriptor>() as u32,
            wire_version: $crate::abi::WIRE_VERSION,
            class_mask: $class_mask,
            reserved: 0,
            name: concat!($name, "\0").as_ptr().cast(),
            describe: Some(ffi_describe),
            validate_config: Some(ffi_validate_config),
            create: Some(ffi_create),
            poll: Some(ffi_poll),
            control: Some(ffi_control),
            shutdown: Some(ffi_shutdown),
            destroy: Some(ffi_destroy),
            byte_io: $byte_io,
            datagram_io: $datagram_io,
            adapter: $adapter,
            protection: $protection,
            carrier: $carrier,
            policy: $policy,
        };

        #[unsafe(no_mangle)]
        pub extern "C" fn snolc_module_entry() -> *const $crate::abi::SnolModuleDescriptor {
            &DESCRIPTOR
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instance_handles_are_not_reused() {
        let instances = Instances::new();
        let first = instances.create().unwrap();
        instances.remove(first);
        let second = instances.create().unwrap();
        assert_ne!(first, second);
        assert!(!instances.contains(first));
        assert!(instances.contains(second));
    }
}
