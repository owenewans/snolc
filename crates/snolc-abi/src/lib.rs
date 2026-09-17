#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

use core::ffi::{c_char, c_void};

pub const WIRE_VERSION: u32 = 1;

pub const STATUS_OK: u32 = 0;
pub const STATUS_UNSUPPORTED: u32 = 1;
pub const STATUS_INVALID: u32 = 2;
pub const STATUS_RESOURCE: u32 = 3;
pub const STATUS_IO: u32 = 4;
pub const STATUS_INTERNAL: u32 = 5;
pub const STATUS_PENDING: u32 = 6;
pub const STATUS_DENIED: u32 = 7;

pub const CLASS_ADAPTER: u32 = 1 << 0;
pub const CLASS_PROTECTION: u32 = 1 << 1;
pub const CLASS_CARRIER: u32 = 1 << 2;
pub const CLASS_POLICY: u32 = 1 << 3;

pub const IO_PROGRESS: u32 = 0;
pub const IO_PENDING: u32 = 1;
pub const IO_EOF: u32 = 2;
pub const IO_ERROR: u32 = 3;
pub const IO_BUFFER_TOO_SMALL: u32 = 4;

pub const FLOW_TCP: u32 = 1;
pub const FLOW_UDP: u32 = 2;
pub const ADDRESS_IPV4: u32 = 1;
pub const ADDRESS_IPV6: u32 = 2;
pub const ADDRESS_DOMAIN: u32 = 3;

pub type SnolHandle = u64;
pub type SnolStatus = u32;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SnolBytes {
    pub pointer: *const u8,
    pub length: usize,
}

unsafe impl Sync for SnolBytes {}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SnolBytesMut {
    pub pointer: *mut u8,
    pub length: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SnolFlowMetadataV1 {
    pub struct_size: u32,
    pub kind: u32,
    pub address_type: u32,
    pub reserved: u32,
    pub address: SnolBytes,
    pub port: u16,
    pub reserved2: [u8; 6],
    pub metadata: SnolBytes,
}

unsafe impl Sync for SnolFlowMetadataV1 {}

unsafe impl Sync for SnolBytesMut {}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnolIoResult {
    pub tag: u32,
    pub code: u32,
    pub count: usize,
}

impl SnolIoResult {
    pub const fn progress(count: usize) -> Self {
        Self {
            tag: IO_PROGRESS,
            code: STATUS_OK,
            count,
        }
    }

    pub const fn pending() -> Self {
        Self {
            tag: IO_PENDING,
            code: STATUS_OK,
            count: 0,
        }
    }

    pub const fn eof() -> Self {
        Self {
            tag: IO_EOF,
            code: STATUS_OK,
            count: 0,
        }
    }

    pub const fn error(code: u32) -> Self {
        Self {
            tag: IO_ERROR,
            code,
            count: 0,
        }
    }

    pub const fn buffer_too_small(required: usize) -> Self {
        Self {
            tag: IO_BUFFER_TOO_SMALL,
            code: STATUS_OK,
            count: required,
        }
    }
}

pub type WakeFn = unsafe extern "C" fn(*mut c_void);
pub type RetainFn = unsafe extern "C" fn(*mut c_void) -> SnolStatus;
pub type ReleaseFn = unsafe extern "C" fn(*mut c_void);

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SnolWakeHandle {
    pub context: *mut c_void,
    pub wake: Option<WakeFn>,
    pub retain: Option<RetainFn>,
    pub release: Option<ReleaseFn>,
}

pub type ReadFn = unsafe extern "C" fn(SnolHandle, SnolBytesMut, SnolWakeHandle) -> SnolIoResult;
pub type WriteFn = unsafe extern "C" fn(SnolHandle, SnolBytes, SnolWakeHandle) -> SnolIoResult;
pub type IoActionFn = unsafe extern "C" fn(SnolHandle, SnolWakeHandle) -> SnolIoResult;
pub type CloseFn = unsafe extern "C" fn(SnolHandle) -> SnolStatus;

#[repr(C)]
pub struct SnolByteIoV1 {
    pub struct_size: u32,
    pub reserved: u32,
    pub read: Option<ReadFn>,
    pub write: Option<WriteFn>,
    pub flush: Option<IoActionFn>,
    pub shutdown_write: Option<IoActionFn>,
    pub close: Option<CloseFn>,
}

unsafe impl Sync for SnolByteIoV1 {}

#[repr(C)]
pub struct SnolDatagramIoV1 {
    pub struct_size: u32,
    pub reserved: u32,
    pub recv_datagram: Option<ReadFn>,
    pub send_datagram: Option<WriteFn>,
    pub close: Option<CloseFn>,
}

unsafe impl Sync for SnolDatagramIoV1 {}

pub type AdapterOpenFn = unsafe extern "C" fn(
    SnolHandle,
    SnolHandle,
    *const SnolFlowMetadataV1,
    SnolWakeHandle,
    *mut SnolHandle,
) -> SnolStatus;
pub type AdapterAcceptFn = unsafe extern "C" fn(
    SnolHandle,
    *mut SnolFlowMetadataV1,
    SnolWakeHandle,
    *mut SnolHandle,
) -> SnolStatus;
pub type AdapterAttachFn =
    unsafe extern "C" fn(SnolHandle, SnolHandle, SnolHandle, *const SnolByteIoV1) -> SnolStatus;
pub type AdapterAttachDatagramFn =
    unsafe extern "C" fn(SnolHandle, SnolHandle, SnolHandle, *const SnolDatagramIoV1) -> SnolStatus;
pub type AdapterCompleteFn =
    unsafe extern "C" fn(SnolHandle, SnolHandle, u32, SnolBytes) -> SnolStatus;
pub type AdapterCloseFlowFn = unsafe extern "C" fn(SnolHandle, SnolHandle) -> SnolStatus;

#[repr(C)]
pub struct SnolAdapterApiV1 {
    pub struct_size: u32,
    pub reserved: u32,
    pub open: Option<AdapterOpenFn>,
    pub accept: Option<AdapterAcceptFn>,
    pub attach: Option<AdapterAttachFn>,
    pub complete: Option<AdapterCompleteFn>,
    pub close_flow: Option<AdapterCloseFlowFn>,
    pub attach_datagram: Option<AdapterAttachDatagramFn>,
}

unsafe impl Sync for SnolAdapterApiV1 {}

pub type WrapFn = unsafe extern "C" fn(
    SnolHandle,
    SnolHandle,
    *const SnolByteIoV1,
    SnolBytes,
    SnolWakeHandle,
    *mut SnolHandle,
) -> SnolStatus;

#[repr(C)]
pub struct SnolProtectionApiV1 {
    pub struct_size: u32,
    pub reserved: u32,
    pub wrap: Option<WrapFn>,
}

unsafe impl Sync for SnolProtectionApiV1 {}

pub type ConnectFn =
    unsafe extern "C" fn(SnolHandle, SnolBytes, SnolWakeHandle, *mut SnolHandle) -> SnolStatus;
pub type AcceptFn = unsafe extern "C" fn(SnolHandle, SnolWakeHandle, *mut SnolHandle) -> SnolStatus;

#[repr(C)]
pub struct SnolCarrierApiV1 {
    pub struct_size: u32,
    pub reserved: u32,
    pub connect: Option<ConnectFn>,
    pub accept: Option<AcceptFn>,
}

unsafe impl Sync for SnolCarrierApiV1 {}

pub type AttachSessionFn = unsafe extern "C" fn(
    SnolHandle,
    SnolHandle,
    *const SnolByteIoV1,
    SnolBytes,
    SnolWakeHandle,
    *mut SnolHandle,
) -> SnolStatus;
pub type AdmitFlowFn = unsafe extern "C" fn(
    SnolHandle,
    SnolHandle,
    *const SnolFlowMetadataV1,
    SnolWakeHandle,
) -> SnolStatus;
pub type AttachFlowFn = unsafe extern "C" fn(
    SnolHandle,
    SnolHandle,
    SnolHandle,
    *const SnolByteIoV1,
    SnolHandle,
    *const SnolByteIoV1,
) -> SnolStatus;
pub type AttachDatagramFlowFn = unsafe extern "C" fn(
    SnolHandle,
    SnolHandle,
    SnolHandle,
    *const SnolDatagramIoV1,
    SnolHandle,
    *const SnolDatagramIoV1,
) -> SnolStatus;

#[repr(C)]
pub struct SnolPolicyApiV1 {
    pub struct_size: u32,
    pub reserved: u32,
    pub attach_session: Option<AttachSessionFn>,
    pub admit_flow: Option<AdmitFlowFn>,
    pub attach_flow: Option<AttachFlowFn>,
    pub attach_datagram_flow: Option<AttachDatagramFlowFn>,
}

unsafe impl Sync for SnolPolicyApiV1 {}

pub type NowNanosFn = unsafe extern "C" fn(*mut c_void) -> u64;
pub type SetTimerFn = unsafe extern "C" fn(*mut c_void, SnolHandle, u64) -> SnolStatus;
pub type EmitEventFn = unsafe extern "C" fn(*mut c_void, SnolBytes) -> SnolStatus;
pub type ContextGetFn = unsafe extern "C" fn(
    *mut c_void,
    SnolHandle,
    SnolBytes,
    SnolBytesMut,
    *mut usize,
) -> SnolStatus;
pub type ContextSetFn =
    unsafe extern "C" fn(*mut c_void, SnolHandle, SnolBytes, SnolBytes) -> SnolStatus;

#[repr(C)]
pub struct SnolHostApiV1 {
    pub struct_size: u32,
    pub reserved: u32,
    pub context: *mut c_void,
    pub now_monotonic_nanos: Option<NowNanosFn>,
    pub set_timer: Option<SetTimerFn>,
    pub emit_event: Option<EmitEventFn>,
    pub context_get: Option<ContextGetFn>,
    pub context_set: Option<ContextSetFn>,
}

unsafe impl Sync for SnolHostApiV1 {}

pub type DescribeFn = unsafe extern "C" fn(SnolBytesMut, *mut usize) -> SnolStatus;
pub type ValidateConfigFn =
    unsafe extern "C" fn(SnolBytes, SnolBytes, SnolBytesMut, *mut usize) -> SnolStatus;
pub type CreateFn =
    unsafe extern "C" fn(SnolBytes, SnolBytes, *const SnolHostApiV1, *mut SnolHandle) -> SnolStatus;
pub type PollFn = unsafe extern "C" fn(SnolHandle, SnolWakeHandle) -> SnolStatus;
pub type ControlFn =
    unsafe extern "C" fn(SnolHandle, SnolBytes, SnolBytesMut, *mut usize) -> SnolStatus;
pub type ShutdownFn = unsafe extern "C" fn(SnolHandle) -> SnolStatus;
pub type DestroyFn = unsafe extern "C" fn(SnolHandle);

#[repr(C)]
pub struct SnolModuleDescriptor {
    pub struct_size: u32,
    pub wire_version: u32,
    pub class_mask: u32,
    pub reserved: u32,
    pub name: *const c_char,
    pub describe: Option<DescribeFn>,
    pub validate_config: Option<ValidateConfigFn>,
    pub create: Option<CreateFn>,
    pub poll: Option<PollFn>,
    pub control: Option<ControlFn>,
    pub shutdown: Option<ShutdownFn>,
    pub destroy: Option<DestroyFn>,
    pub byte_io: *const SnolByteIoV1,
    pub datagram_io: *const SnolDatagramIoV1,
    pub adapter: *const SnolAdapterApiV1,
    pub protection: *const SnolProtectionApiV1,
    pub carrier: *const SnolCarrierApiV1,
    pub policy: *const SnolPolicyApiV1,
}

unsafe impl Sync for SnolModuleDescriptor {}

pub type ModuleEntry = unsafe extern "C" fn() -> *const SnolModuleDescriptor;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_prefix_has_fixed_layout() {
        assert_eq!(core::mem::offset_of!(SnolModuleDescriptor, name), 16);
    }

    #[test]
    fn required_datagram_length_is_preserved() {
        assert_eq!(SnolIoResult::buffer_too_small(65_507).count, 65_507);
    }

    #[test]
    fn flow_metadata_has_fixed_prefix_layout() {
        assert_eq!(core::mem::offset_of!(SnolFlowMetadataV1, address), 16);
        assert_eq!(core::mem::offset_of!(SnolFlowMetadataV1, port), 32);
    }
}
