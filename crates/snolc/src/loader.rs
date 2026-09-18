use std::ffi::CStr;
use std::io;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::ptr::NonNull;
use std::rc::Rc;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use futures::io::{AsyncRead, AsyncWrite};
use libloading::{Library, Symbol};
use snolc_abi::{
    ModuleEntry, SnolByteIoV1, SnolBytes, SnolBytesMut, SnolDatagramIoV1, SnolFlowMetadataV1,
    SnolHostApiV1, SnolIoResult, SnolModuleDescriptor, SnolWakeHandle,
};
use thiserror::Error;

use crate::wire::{Destination, OpenRequest, StreamKind};

const KNOWN_CLASSES: u32 = snolc_abi::CLASS_ADAPTER
    | snolc_abi::CLASS_PROTECTION
    | snolc_abi::CLASS_CARRIER
    | snolc_abi::CLASS_POLICY;
const MAX_DESCRIPTION: usize = 65_536;
const MAX_CONFIG_ERROR: usize = 4096;

pub struct LoadedModule {
    descriptor: NonNull<SnolModuleDescriptor>,
    library: Arc<Library>,
    source_config: PathBuf,
    path: PathBuf,
    instance_name: String,
    name: String,
    class_mask: u32,
    config: Vec<u8>,
    base_directory: Vec<u8>,
    instance: Option<u64>,
}

// the descriptor is immutable and the owned library keeps its storage alive.
unsafe impl Send for LoadedModule {}

impl LoadedModule {
    pub(crate) fn supports_packet_port(&self) -> bool {
        unsafe { self.descriptor().adapter.as_ref() }
            .is_some_and(|adapter| adapter.attach_packet_port.is_some())
    }

    pub fn load(
        instance_name: String,
        path: &Path,
        config: Vec<u8>,
        base_directory: &Path,
        source_config: &Path,
    ) -> Result<Self, LoadError> {
        // loading trusted native code can execute library initializers.
        let library = Arc::new(unsafe { Library::new(path) }.map_err(LoadError::Open)?);
        // the entry symbol and descriptor remain valid while library is owned.
        let (descriptor, name, class_mask) = unsafe {
            let entry: Symbol<'_, ModuleEntry> = library
                .get(b"snolc_module_entry\0")
                .map_err(LoadError::Entry)?;
            let descriptor = NonNull::new(entry().cast_mut()).ok_or(LoadError::NullDescriptor)?;
            let (name, class_mask) = validate_descriptor(descriptor)?;
            (descriptor, name, class_mask)
        };
        let base_directory = base_directory.as_os_str().as_encoded_bytes().to_vec();
        let module = Self {
            descriptor,
            library,
            source_config: source_config.to_path_buf(),
            path: path.to_path_buf(),
            instance_name,
            name,
            class_mask,
            config,
            base_directory,
            instance: None,
        };
        module.validate_config()?;
        Ok(module)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn instance_name(&self) -> &str {
        &self.instance_name
    }

    pub fn class_mask(&self) -> u32 {
        self.class_mask
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn source_config(&self) -> &Path {
        &self.source_config
    }

    pub fn describe(&self) -> Result<Vec<u8>, LoadError> {
        let function = self
            .descriptor()
            .describe
            .ok_or(LoadError::MissingFunction)?;
        let mut output = vec![0; MAX_DESCRIPTION];
        let mut written = 0;
        // buffers live for the complete FFI call.
        let status = unsafe { function(bytes_mut(&mut output), &mut written) };
        check_output(status, output, written, MAX_DESCRIPTION)
    }

    pub fn create(&mut self, host: &SnolHostApiV1) -> Result<(), LoadError> {
        if self.instance.is_some() {
            return Err(LoadError::AlreadyCreated);
        }
        let function = self.descriptor().create.ok_or(LoadError::MissingFunction)?;
        let mut instance = 0;
        // config and host pointers remain valid for the call; modules copy retained data.
        let status = unsafe {
            function(
                bytes(&self.config),
                bytes(&self.base_directory),
                host,
                &mut instance,
            )
        };
        if status != snolc_abi::STATUS_OK {
            return Err(LoadError::ModuleStatus(status));
        }
        if instance == 0 {
            return Err(LoadError::InvalidHandle);
        }
        self.instance = Some(instance);
        Ok(())
    }

    pub fn poll(&mut self, wake: snolc_abi::SnolWakeHandle) -> Result<(), LoadError> {
        let instance = self.instance.ok_or(LoadError::NotCreated)?;
        let function = self.descriptor().poll.ok_or(LoadError::MissingFunction)?;
        // lifecycle calls run only on the engine owner thread.
        let status = unsafe { function(instance, wake) };
        match status {
            snolc_abi::STATUS_OK | snolc_abi::STATUS_PENDING => Ok(()),
            status => Err(LoadError::ModuleStatus(status)),
        }
    }

    pub fn poll_control(
        &mut self,
        request: &[u8],
        max_response: usize,
    ) -> Poll<Result<Vec<u8>, LoadError>> {
        let instance = self.instance.ok_or(LoadError::NotCreated)?;
        let function = self
            .descriptor()
            .control
            .ok_or(LoadError::MissingFunction)?;
        let mut output = vec![0; max_response];
        let mut written = 0;
        // borrowed request and response buffers live for the complete FFI call.
        let status = unsafe {
            function(
                instance,
                bytes(request),
                bytes_mut(&mut output),
                &mut written,
            )
        };
        if status == snolc_abi::STATUS_UNSUPPORTED {
            return Poll::Ready(Err(LoadError::Unsupported));
        }
        if status == snolc_abi::STATUS_PENDING {
            return Poll::Pending;
        }
        Poll::Ready(check_output(status, output, written, max_response))
    }

    pub fn poll_shutdown(&mut self) -> Poll<Result<(), LoadError>> {
        let Some(instance) = self.instance else {
            return Poll::Ready(Ok(()));
        };
        let function = self
            .descriptor()
            .shutdown
            .ok_or(LoadError::MissingFunction)?;
        // lifecycle calls run only on the engine owner thread.
        let status = unsafe { function(instance) };
        match status {
            snolc_abi::STATUS_OK => Poll::Ready(Ok(())),
            snolc_abi::STATUS_PENDING => Poll::Pending,
            status => Poll::Ready(Err(LoadError::ModuleStatus(status))),
        }
    }

    pub fn carrier_connect(
        &self,
        endpoint: &[u8],
        context: &mut Context<'_>,
    ) -> Poll<Result<ModuleByteIo, LoadError>> {
        let instance = match self.instance {
            Some(instance) => instance,
            None => return Poll::Ready(Err(LoadError::NotCreated)),
        };
        let carrier = match unsafe { self.descriptor().carrier.as_ref() } {
            Some(carrier) => carrier,
            None => return Poll::Ready(Err(LoadError::ClassTable(snolc_abi::CLASS_CARRIER))),
        };
        let connect = match carrier.connect {
            Some(connect) => connect,
            None => return Poll::Ready(Err(LoadError::MissingFunction)),
        };
        let mut stream = 0;
        let wake = WakeCall::new(context.waker());
        let status = unsafe { connect(instance, bytes(endpoint), wake.handle(), &mut stream) };
        self.finish_byte_io(status, stream, vec![Arc::clone(&self.library)])
    }

    pub fn carrier_accept(
        &self,
        context: &mut Context<'_>,
    ) -> Poll<Result<ModuleByteIo, LoadError>> {
        let instance = match self.instance {
            Some(instance) => instance,
            None => return Poll::Ready(Err(LoadError::NotCreated)),
        };
        let carrier = match unsafe { self.descriptor().carrier.as_ref() } {
            Some(carrier) => carrier,
            None => return Poll::Ready(Err(LoadError::ClassTable(snolc_abi::CLASS_CARRIER))),
        };
        let accept = match carrier.accept {
            Some(accept) => accept,
            None => return Poll::Ready(Err(LoadError::MissingFunction)),
        };
        let mut stream = 0;
        let wake = WakeCall::new(context.waker());
        let status = unsafe { accept(instance, wake.handle(), &mut stream) };
        self.finish_byte_io(status, stream, vec![Arc::clone(&self.library)])
    }

    pub fn adapter_open(
        &self,
        operation: u64,
        metadata: &SnolFlowMetadataV1,
        context: &mut Context<'_>,
    ) -> Poll<Result<u64, LoadError>> {
        let instance = match self.instance {
            Some(instance) => instance,
            None => return Poll::Ready(Err(LoadError::NotCreated)),
        };
        let adapter = match unsafe { self.descriptor().adapter.as_ref() } {
            Some(adapter) => adapter,
            None => return Poll::Ready(Err(LoadError::ClassTable(snolc_abi::CLASS_ADAPTER))),
        };
        let open = match adapter.open {
            Some(open) => open,
            None => return Poll::Ready(Err(LoadError::MissingFunction)),
        };
        let mut flow = 0;
        let wake = WakeCall::new(context.waker());
        let status = unsafe { open(instance, operation, metadata, wake.handle(), &mut flow) };
        match status {
            snolc_abi::STATUS_PENDING => Poll::Pending,
            snolc_abi::STATUS_OK if flow == 0 => Poll::Ready(Err(LoadError::InvalidHandle)),
            snolc_abi::STATUS_OK => Poll::Ready(Ok(flow)),
            status => Poll::Ready(Err(LoadError::ModuleStatus(status))),
        }
    }

    pub fn adapter_resolve(
        &self,
        operation: u64,
        metadata: &SnolFlowMetadataV1,
        context: &mut Context<'_>,
    ) -> Poll<Result<Option<Vec<std::net::IpAddr>>, LoadError>> {
        let instance = match self.instance {
            Some(instance) => instance,
            None => return Poll::Ready(Err(LoadError::NotCreated)),
        };
        let adapter = match unsafe { self.descriptor().adapter.as_ref() } {
            Some(adapter) => adapter,
            None => return Poll::Ready(Err(LoadError::ClassTable(snolc_abi::CLASS_ADAPTER))),
        };
        let Some(resolve) = adapter.resolve else {
            return Poll::Ready(Ok(None));
        };
        let mut output = [0; snolc_sdk::MAX_RESOLVED_ADDRESS_BYTES];
        let mut written = 0;
        let wake = WakeCall::new(context.waker());
        let status = unsafe {
            resolve(
                instance,
                operation,
                metadata,
                wake.handle(),
                bytes_mut(&mut output),
                &mut written,
            )
        };
        match status {
            snolc_abi::STATUS_PENDING => Poll::Pending,
            snolc_abi::STATUS_UNSUPPORTED => Poll::Ready(Ok(None)),
            snolc_abi::STATUS_OK if written <= output.len() => {
                match snolc_sdk::decode_resolved_addresses(&output[..written]) {
                    Ok(addresses) => Poll::Ready(Ok(Some(addresses))),
                    Err(_) => Poll::Ready(Err(LoadError::FlowMetadata)),
                }
            }
            snolc_abi::STATUS_OK => Poll::Ready(Err(LoadError::FlowMetadata)),
            status => Poll::Ready(Err(LoadError::ModuleStatus(status))),
        }
    }

    pub(crate) fn adapter_accept(
        &self,
        context: &mut Context<'_>,
    ) -> Poll<Result<(u64, OpenRequest), LoadError>> {
        let instance = match self.instance {
            Some(instance) => instance,
            None => return Poll::Ready(Err(LoadError::NotCreated)),
        };
        let adapter = match unsafe { self.descriptor().adapter.as_ref() } {
            Some(adapter) => adapter,
            None => return Poll::Ready(Err(LoadError::ClassTable(snolc_abi::CLASS_ADAPTER))),
        };
        let accept = match adapter.accept {
            Some(accept) => accept,
            None => return Poll::Ready(Err(LoadError::MissingFunction)),
        };
        let mut flow = 0;
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
        let wake = WakeCall::new(context.waker());
        let status = unsafe { accept(instance, &mut metadata, wake.handle(), &mut flow) };
        match status {
            snolc_abi::STATUS_PENDING => Poll::Pending,
            snolc_abi::STATUS_OK if flow == 0 => Poll::Ready(Err(LoadError::InvalidHandle)),
            snolc_abi::STATUS_OK => {
                let metadata = match unsafe { snolc_sdk::module::flow_metadata(&metadata) } {
                    Ok(metadata) => metadata,
                    Err(_) => return Poll::Ready(Err(LoadError::FlowMetadata)),
                };
                let destination = match metadata.address_type {
                    snolc_abi::ADDRESS_IPV4 => Destination::Ipv4(
                        <[u8; 4]>::try_from(metadata.address)
                            .map(std::net::Ipv4Addr::from)
                            .map_err(|_| LoadError::FlowMetadata)?,
                    ),
                    snolc_abi::ADDRESS_IPV6 => Destination::Ipv6(
                        <[u8; 16]>::try_from(metadata.address)
                            .map(std::net::Ipv6Addr::from)
                            .map_err(|_| LoadError::FlowMetadata)?,
                    ),
                    snolc_abi::ADDRESS_DOMAIN => Destination::Domain(
                        std::str::from_utf8(metadata.address)
                            .map_err(|_| LoadError::FlowMetadata)?
                            .to_owned(),
                    ),
                    _ => return Poll::Ready(Err(LoadError::FlowMetadata)),
                };
                let kind = match metadata.kind {
                    snolc_abi::FLOW_TCP => StreamKind::Tcp,
                    snolc_abi::FLOW_UDP => StreamKind::Udp,
                    _ => return Poll::Ready(Err(LoadError::FlowMetadata)),
                };
                Poll::Ready(Ok((
                    flow,
                    OpenRequest {
                        kind,
                        destination,
                        port: metadata.port,
                        metadata: metadata.metadata.to_vec(),
                    },
                )))
            }
            status => Poll::Ready(Err(LoadError::ModuleStatus(status))),
        }
    }

    /// # Safety
    ///
    /// The stack handle and I/O table must remain valid until the adapter closes them.
    pub unsafe fn adapter_attach_flow(
        &self,
        flow: u64,
        stack_handle: u64,
        stack_io: *const SnolByteIoV1,
    ) -> Result<(), LoadError> {
        let instance = self.instance.ok_or(LoadError::NotCreated)?;
        let adapter = unsafe { self.descriptor().adapter.as_ref() }
            .ok_or(LoadError::ClassTable(snolc_abi::CLASS_ADAPTER))?;
        let attach = adapter.attach.ok_or(LoadError::MissingFunction)?;
        let status = unsafe { attach(instance, flow, stack_handle, stack_io) };
        if status == snolc_abi::STATUS_OK {
            Ok(())
        } else {
            Err(LoadError::ModuleStatus(status))
        }
    }

    /// # Safety
    ///
    /// The stack handle and I/O table must remain valid until the adapter closes them.
    pub unsafe fn adapter_attach_datagram(
        &self,
        flow: u64,
        stack_handle: u64,
        stack_io: *const SnolDatagramIoV1,
    ) -> Result<(), LoadError> {
        let instance = self.instance.ok_or(LoadError::NotCreated)?;
        let adapter = unsafe { self.descriptor().adapter.as_ref() }
            .ok_or(LoadError::ClassTable(snolc_abi::CLASS_ADAPTER))?;
        let attach = adapter.attach_datagram.ok_or(LoadError::MissingFunction)?;
        let status = unsafe { attach(instance, flow, stack_handle, stack_io) };
        if status == snolc_abi::STATUS_OK {
            Ok(())
        } else {
            Err(LoadError::ModuleStatus(status))
        }
    }

    /// # Safety
    ///
    /// The packet port handle and I/O table must remain valid until the adapter closes them.
    pub unsafe fn adapter_attach_packet_port(
        &self,
        packet_port: u64,
        packet_port_io: *const SnolDatagramIoV1,
    ) -> Result<(), LoadError> {
        let instance = self.instance.ok_or(LoadError::NotCreated)?;
        let adapter = unsafe { self.descriptor().adapter.as_ref() }
            .ok_or(LoadError::ClassTable(snolc_abi::CLASS_ADAPTER))?;
        let attach = adapter.attach_packet_port.ok_or(LoadError::Unsupported)?;
        let status = unsafe { attach(instance, packet_port, packet_port_io) };
        if status == snolc_abi::STATUS_OK {
            Ok(())
        } else {
            Err(LoadError::ModuleStatus(status))
        }
    }

    pub fn adapter_complete_flow(
        &self,
        flow: u64,
        status: u32,
        reason: &[u8],
    ) -> Result<(), LoadError> {
        let instance = self.instance.ok_or(LoadError::NotCreated)?;
        let adapter = unsafe { self.descriptor().adapter.as_ref() }
            .ok_or(LoadError::ClassTable(snolc_abi::CLASS_ADAPTER))?;
        let complete = adapter.complete.ok_or(LoadError::MissingFunction)?;
        let status = unsafe { complete(instance, flow, status, bytes(reason)) };
        if status == snolc_abi::STATUS_OK {
            Ok(())
        } else {
            Err(LoadError::ModuleStatus(status))
        }
    }

    pub fn adapter_close_flow(&self, flow: u64) -> Result<(), LoadError> {
        let instance = self.instance.ok_or(LoadError::NotCreated)?;
        let adapter = unsafe { self.descriptor().adapter.as_ref() }
            .ok_or(LoadError::ClassTable(snolc_abi::CLASS_ADAPTER))?;
        let close = adapter.close_flow.ok_or(LoadError::MissingFunction)?;
        let status = unsafe { close(instance, flow) };
        if status == snolc_abi::STATUS_OK {
            Ok(())
        } else {
            Err(LoadError::ModuleStatus(status))
        }
    }

    pub fn protection_wrap(
        &self,
        lower: &mut Option<ModuleByteIo>,
        context_bytes: &[u8],
        context: &mut Context<'_>,
    ) -> Poll<Result<ModuleByteIo, LoadError>> {
        let instance = match self.instance {
            Some(instance) => instance,
            None => return Poll::Ready(Err(LoadError::NotCreated)),
        };
        let protection = match unsafe { self.descriptor().protection.as_ref() } {
            Some(protection) => protection,
            None => {
                return Poll::Ready(Err(LoadError::ClassTable(snolc_abi::CLASS_PROTECTION)));
            }
        };
        let wrap = match protection.wrap {
            Some(wrap) => wrap,
            None => return Poll::Ready(Err(LoadError::MissingFunction)),
        };
        let (lower_handle, lower_io) = match lower.as_ref() {
            Some(lower) => lower.raw_parts(),
            None => return Poll::Ready(Err(LoadError::InvalidHandle)),
        };
        let mut wrapped = 0;
        let wake = WakeCall::new(context.waker());
        let status = unsafe {
            wrap(
                instance,
                lower_handle,
                lower_io.as_ptr(),
                bytes(context_bytes),
                wake.handle(),
                &mut wrapped,
            )
        };
        let mut libraries = lower
            .as_ref()
            .map(|lower| lower.libraries.clone())
            .unwrap_or_default();
        libraries.push(Arc::clone(&self.library));
        match self.finish_byte_io(status, wrapped, libraries) {
            Poll::Ready(Ok(output)) => {
                if let Some(lower) = lower.take() {
                    lower.transfer();
                }
                Poll::Ready(Ok(output))
            }
            result => result,
        }
    }

    pub fn protection_passthrough(&self) -> bool {
        unsafe { self.descriptor().protection.as_ref() }
            .is_some_and(|protection| protection.flags & snolc_abi::PROTECTION_PASSTHROUGH != 0)
    }

    pub(crate) fn policy_attach_session(
        &self,
        policy_stream: u64,
        policy_stream_io: *const SnolByteIoV1,
        context_bytes: &[u8],
        context: &mut Context<'_>,
    ) -> Poll<Result<u64, LoadError>> {
        let instance = match self.instance {
            Some(instance) => instance,
            None => return Poll::Ready(Err(LoadError::NotCreated)),
        };
        let policy = match unsafe { self.descriptor().policy.as_ref() } {
            Some(policy) => policy,
            None => return Poll::Ready(Err(LoadError::ClassTable(snolc_abi::CLASS_POLICY))),
        };
        let attach = match policy.attach_session {
            Some(attach) => attach,
            None => return Poll::Ready(Err(LoadError::MissingFunction)),
        };
        let mut session = 0;
        let wake = WakeCall::new(context.waker());
        let status = unsafe {
            attach(
                instance,
                policy_stream,
                policy_stream_io,
                bytes(context_bytes),
                wake.handle(),
                &mut session,
            )
        };
        match status {
            snolc_abi::STATUS_PENDING => Poll::Pending,
            snolc_abi::STATUS_OK if session == 0 => Poll::Ready(Err(LoadError::InvalidHandle)),
            snolc_abi::STATUS_OK => Poll::Ready(Ok(session)),
            status => Poll::Ready(Err(LoadError::ModuleStatus(status))),
        }
    }

    pub fn policy_admit_flow(
        &self,
        policy_session: u64,
        metadata: &SnolFlowMetadataV1,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), LoadError>> {
        let instance = match self.instance {
            Some(instance) => instance,
            None => return Poll::Ready(Err(LoadError::NotCreated)),
        };
        let policy = match unsafe { self.descriptor().policy.as_ref() } {
            Some(policy) => policy,
            None => return Poll::Ready(Err(LoadError::ClassTable(snolc_abi::CLASS_POLICY))),
        };
        let admit = match policy.admit_flow {
            Some(admit) => admit,
            None => return Poll::Ready(Err(LoadError::MissingFunction)),
        };
        let wake = WakeCall::new(context.waker());
        let status = unsafe { admit(instance, policy_session, metadata, wake.handle()) };
        match status {
            snolc_abi::STATUS_PENDING => Poll::Pending,
            snolc_abi::STATUS_OK => Poll::Ready(Ok(())),
            status => Poll::Ready(Err(LoadError::ModuleStatus(status))),
        }
    }

    pub fn policy_passthrough_tcp(&self) -> bool {
        unsafe { self.descriptor().policy.as_ref() }
            .is_some_and(|policy| policy.flags & snolc_abi::POLICY_PASSTHROUGH_TCP != 0)
    }

    pub fn policy_admit_resolved(
        &self,
        policy_session: u64,
        metadata: &SnolFlowMetadataV1,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), LoadError>> {
        let instance = match self.instance {
            Some(instance) => instance,
            None => return Poll::Ready(Err(LoadError::NotCreated)),
        };
        let policy = match unsafe { self.descriptor().policy.as_ref() } {
            Some(policy) => policy,
            None => return Poll::Ready(Err(LoadError::ClassTable(snolc_abi::CLASS_POLICY))),
        };
        let admit = match policy.admit_resolved {
            Some(admit) => admit,
            None => return Poll::Ready(Err(LoadError::MissingFunction)),
        };
        let wake = WakeCall::new(context.waker());
        let status = unsafe { admit(instance, policy_session, metadata, wake.handle()) };
        match status {
            snolc_abi::STATUS_PENDING => Poll::Pending,
            snolc_abi::STATUS_OK => Poll::Ready(Ok(())),
            status => Poll::Ready(Err(LoadError::ModuleStatus(status))),
        }
    }

    /// # Safety
    ///
    /// Both handles and I/O tables must remain valid until the policy closes them.
    pub unsafe fn policy_attach_flow(
        &self,
        policy_session: u64,
        stack_handle: u64,
        stack_io: *const SnolByteIoV1,
        mux_handle: u64,
        mux_io: *const SnolByteIoV1,
    ) -> Result<(), LoadError> {
        let instance = self.instance.ok_or(LoadError::NotCreated)?;
        let policy = unsafe { self.descriptor().policy.as_ref() }
            .ok_or(LoadError::ClassTable(snolc_abi::CLASS_POLICY))?;
        let attach = policy.attach_flow.ok_or(LoadError::MissingFunction)?;
        let status = unsafe {
            attach(
                instance,
                policy_session,
                stack_handle,
                stack_io,
                mux_handle,
                mux_io,
            )
        };
        if status == snolc_abi::STATUS_OK {
            Ok(())
        } else {
            Err(LoadError::ModuleStatus(status))
        }
    }

    /// # Safety
    ///
    /// Both handles and I/O tables must remain valid until the policy closes them.
    pub unsafe fn policy_attach_datagram_flow(
        &self,
        policy_session: u64,
        stack_handle: u64,
        stack_io: *const SnolDatagramIoV1,
        mux_handle: u64,
        mux_io: *const SnolDatagramIoV1,
    ) -> Result<(), LoadError> {
        let instance = self.instance.ok_or(LoadError::NotCreated)?;
        let policy = unsafe { self.descriptor().policy.as_ref() }
            .ok_or(LoadError::ClassTable(snolc_abi::CLASS_POLICY))?;
        let attach = policy
            .attach_datagram_flow
            .ok_or(LoadError::MissingFunction)?;
        let status = unsafe {
            attach(
                instance,
                policy_session,
                stack_handle,
                stack_io,
                mux_handle,
                mux_io,
            )
        };
        if status == snolc_abi::STATUS_OK {
            Ok(())
        } else {
            Err(LoadError::ModuleStatus(status))
        }
    }

    fn finish_byte_io(
        &self,
        status: u32,
        handle: u64,
        libraries: Vec<Arc<Library>>,
    ) -> Poll<Result<ModuleByteIo, LoadError>> {
        match status {
            snolc_abi::STATUS_PENDING => Poll::Pending,
            snolc_abi::STATUS_OK if handle == 0 => Poll::Ready(Err(LoadError::InvalidHandle)),
            snolc_abi::STATUS_OK => {
                let io = match NonNull::new(self.descriptor().byte_io.cast_mut()) {
                    Some(io) => io,
                    None => return Poll::Ready(Err(LoadError::ByteIo)),
                };
                Poll::Ready(Ok(ModuleByteIo::new(handle, io, libraries)))
            }
            status => Poll::Ready(Err(LoadError::ModuleStatus(status))),
        }
    }

    fn validate_config(&self) -> Result<(), LoadError> {
        let function = self
            .descriptor()
            .validate_config
            .ok_or(LoadError::MissingFunction)?;
        let mut error = vec![0; MAX_CONFIG_ERROR];
        let mut written = 0;
        // borrowed buffers live for the complete FFI call.
        let status = unsafe {
            function(
                bytes(&self.config),
                bytes(&self.base_directory),
                bytes_mut(&mut error),
                &mut written,
            )
        };
        if status == snolc_abi::STATUS_OK {
            return Ok(());
        }
        if written > error.len() {
            return Err(LoadError::OutputLength);
        }
        error.truncate(written);
        Err(LoadError::Config {
            status,
            message: String::from_utf8_lossy(&error).into_owned(),
        })
    }

    fn descriptor(&self) -> &SnolModuleDescriptor {
        // the library owns immutable descriptor storage and self keeps it loaded.
        unsafe { self.descriptor.as_ref() }
    }
}

impl Drop for LoadedModule {
    fn drop(&mut self) {
        if let Some(instance) = self.instance.take()
            && let Some(destroy) = self.descriptor().destroy
        {
            // destroy runs before the library field is dropped.
            unsafe { destroy(instance) };
        }
        let _ = &self.library;
    }
}

unsafe fn validate_descriptor(
    descriptor: NonNull<SnolModuleDescriptor>,
) -> Result<(String, u32), LoadError> {
    // the caller obtained this pointer from the module entry contract.
    let descriptor = unsafe { descriptor.as_ref() };
    if descriptor.struct_size < size_of::<SnolModuleDescriptor>() as u32 {
        return Err(LoadError::DescriptorSize(descriptor.struct_size));
    }
    if descriptor.wire_version != snolc_abi::WIRE_VERSION {
        return Err(LoadError::WireVersion(descriptor.wire_version));
    }
    if descriptor.reserved != 0 {
        return Err(LoadError::Reserved);
    }
    if descriptor.class_mask == 0 || descriptor.class_mask & !KNOWN_CLASSES != 0 {
        return Err(LoadError::ClassMask(descriptor.class_mask));
    }
    if descriptor.name.is_null() {
        return Err(LoadError::Name);
    }
    // descriptor names are permanent nul-terminated strings by contract.
    let name = unsafe { CStr::from_ptr(descriptor.name) }
        .to_str()
        .map_err(|_| LoadError::Name)?;
    if name.is_empty() || name.len() > 128 {
        return Err(LoadError::Name);
    }
    if descriptor.describe.is_none()
        || descriptor.validate_config.is_none()
        || descriptor.create.is_none()
        || descriptor.poll.is_none()
        || descriptor.control.is_none()
        || descriptor.shutdown.is_none()
        || descriptor.destroy.is_none()
    {
        return Err(LoadError::MissingFunction);
    }
    validate_class_tables(descriptor)?;
    Ok((name.to_owned(), descriptor.class_mask))
}

fn validate_class_tables(descriptor: &SnolModuleDescriptor) -> Result<(), LoadError> {
    let tables = [
        (snolc_abi::CLASS_ADAPTER, descriptor.adapter.cast::<()>()),
        (
            snolc_abi::CLASS_PROTECTION,
            descriptor.protection.cast::<()>(),
        ),
        (snolc_abi::CLASS_CARRIER, descriptor.carrier.cast::<()>()),
        (snolc_abi::CLASS_POLICY, descriptor.policy.cast::<()>()),
    ];
    for (class, table) in tables {
        if descriptor.class_mask & class != 0 && table.is_null() {
            return Err(LoadError::ClassTable(class));
        }
    }
    if descriptor.class_mask & (snolc_abi::CLASS_PROTECTION | snolc_abi::CLASS_CARRIER) != 0 {
        validate_byte_io(descriptor.byte_io)?;
    }
    if descriptor.class_mask & snolc_abi::CLASS_ADAPTER != 0 {
        let adapter = unsafe { descriptor.adapter.as_ref() }
            .ok_or(LoadError::ClassTable(snolc_abi::CLASS_ADAPTER))?;
        if adapter.struct_size < size_of::<snolc_abi::SnolAdapterApiV1>() as u32
            || adapter.reserved != 0
            || adapter.open.is_none()
            || adapter.accept.is_none()
            || adapter.attach.is_none()
            || adapter.complete.is_none()
            || adapter.close_flow.is_none()
        {
            return Err(LoadError::ClassTable(snolc_abi::CLASS_ADAPTER));
        }
    }
    if descriptor.class_mask & snolc_abi::CLASS_PROTECTION != 0 {
        let protection = unsafe { descriptor.protection.as_ref() }
            .ok_or(LoadError::ClassTable(snolc_abi::CLASS_PROTECTION))?;
        if protection.struct_size < size_of::<snolc_abi::SnolProtectionApiV1>() as u32
            || protection.flags & !snolc_abi::PROTECTION_PASSTHROUGH != 0
            || protection.wrap.is_none()
        {
            return Err(LoadError::ClassTable(snolc_abi::CLASS_PROTECTION));
        }
    }
    if descriptor.class_mask & snolc_abi::CLASS_CARRIER != 0 {
        let carrier = unsafe { descriptor.carrier.as_ref() }
            .ok_or(LoadError::ClassTable(snolc_abi::CLASS_CARRIER))?;
        if carrier.struct_size < size_of::<snolc_abi::SnolCarrierApiV1>() as u32
            || carrier.reserved != 0
            || carrier.connect.is_none()
            || carrier.accept.is_none()
        {
            return Err(LoadError::ClassTable(snolc_abi::CLASS_CARRIER));
        }
    }
    if descriptor.class_mask & snolc_abi::CLASS_POLICY != 0 {
        let policy = unsafe { descriptor.policy.as_ref() }
            .ok_or(LoadError::ClassTable(snolc_abi::CLASS_POLICY))?;
        if policy.struct_size < size_of::<snolc_abi::SnolPolicyApiV1>() as u32
            || policy.flags & !snolc_abi::POLICY_PASSTHROUGH_TCP != 0
            || policy.attach_session.is_none()
            || policy.admit_flow.is_none()
            || policy.admit_resolved.is_none()
            || policy.attach_flow.is_none()
        {
            return Err(LoadError::ClassTable(snolc_abi::CLASS_POLICY));
        }
    }
    Ok(())
}

fn validate_byte_io(io: *const SnolByteIoV1) -> Result<(), LoadError> {
    let io = unsafe { io.as_ref() }.ok_or(LoadError::ByteIo)?;
    if io.struct_size < size_of::<SnolByteIoV1>() as u32
        || io.reserved != 0
        || io.read.is_none()
        || io.write.is_none()
        || io.flush.is_none()
        || io.shutdown_write.is_none()
        || io.close.is_none()
    {
        return Err(LoadError::ByteIo);
    }
    Ok(())
}

pub struct ModuleByteIo {
    handle: u64,
    io: NonNull<SnolByteIoV1>,
    libraries: Vec<Arc<Library>>,
    closed: bool,
    not_send: PhantomData<Rc<()>>,
}

impl ModuleByteIo {
    fn new(handle: u64, io: NonNull<SnolByteIoV1>, libraries: Vec<Arc<Library>>) -> Self {
        Self {
            handle,
            io,
            libraries,
            closed: false,
            not_send: PhantomData,
        }
    }

    fn raw_parts(&self) -> (u64, NonNull<SnolByteIoV1>) {
        (self.handle, self.io)
    }

    fn transfer(mut self) {
        self.closed = true;
    }

    fn table(&self) -> &SnolByteIoV1 {
        unsafe { self.io.as_ref() }
    }

    fn action(
        &mut self,
        context: &mut Context<'_>,
        function: Option<snolc_abi::IoActionFn>,
    ) -> Poll<io::Result<()>> {
        let function = match function {
            Some(function) => function,
            None => return Poll::Ready(Err(io::Error::other("module I/O function is missing"))),
        };
        let wake = WakeCall::new(context.waker());
        let result = unsafe { function(self.handle, wake.handle()) };
        map_action(result)
    }

    fn close(&mut self) -> io::Result<()> {
        if self.closed {
            return Ok(());
        }
        let close = self
            .table()
            .close
            .ok_or_else(|| io::Error::other("module close function is missing"))?;
        let status = unsafe { close(self.handle) };
        self.closed = true;
        if status == snolc_abi::STATUS_OK {
            Ok(())
        } else {
            Err(status_error(status))
        }
    }
}

impl AsyncRead for ModuleByteIo {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let read = match self.table().read {
            Some(read) => read,
            None => return Poll::Ready(Err(io::Error::other("module read function is missing"))),
        };
        let wake = WakeCall::new(context.waker());
        let result = unsafe { read(self.handle, bytes_mut(output), wake.handle()) };
        map_io(result, output.len(), true)
    }
}

impl AsyncWrite for ModuleByteIo {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let write = match self.table().write {
            Some(write) => write,
            None => return Poll::Ready(Err(io::Error::other("module write function is missing"))),
        };
        let wake = WakeCall::new(context.waker());
        let result = unsafe { write(self.handle, bytes(input), wake.handle()) };
        map_io(result, input.len(), false)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let function = self.table().flush;
        self.action(context, function)
    }

    fn poll_close(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let function = self.table().shutdown_write;
        self.action(context, function)
    }
}

impl Drop for ModuleByteIo {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

fn map_io(result: SnolIoResult, limit: usize, read: bool) -> Poll<io::Result<usize>> {
    match result.tag {
        snolc_abi::IO_PROGRESS if result.code == snolc_abi::STATUS_OK && result.count <= limit => {
            Poll::Ready(Ok(result.count))
        }
        snolc_abi::IO_PENDING if result.code == snolc_abi::STATUS_OK && result.count == 0 => {
            Poll::Pending
        }
        snolc_abi::IO_EOF if read && result.code == snolc_abi::STATUS_OK && result.count == 0 => {
            Poll::Ready(Ok(0))
        }
        snolc_abi::IO_ERROR if result.count == 0 => Poll::Ready(Err(status_error(result.code))),
        _ => Poll::Ready(Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "module returned an invalid I/O result",
        ))),
    }
}

fn map_action(result: SnolIoResult) -> Poll<io::Result<()>> {
    match result.tag {
        snolc_abi::IO_PROGRESS if result.code == snolc_abi::STATUS_OK && result.count == 0 => {
            Poll::Ready(Ok(()))
        }
        snolc_abi::IO_PENDING if result.code == snolc_abi::STATUS_OK && result.count == 0 => {
            Poll::Pending
        }
        snolc_abi::IO_ERROR if result.count == 0 => Poll::Ready(Err(status_error(result.code))),
        _ => Poll::Ready(Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "module returned an invalid I/O action result",
        ))),
    }
}

fn status_error(status: u32) -> io::Error {
    io::Error::other(format!("module I/O failed with status {status}"))
}

struct WakeCall {
    pointer: *const Waker,
}

impl WakeCall {
    fn new(waker: &Waker) -> Self {
        Self {
            pointer: Arc::into_raw(Arc::new(waker.clone())),
        }
    }

    fn handle(&self) -> SnolWakeHandle {
        SnolWakeHandle {
            context: self.pointer.cast_mut().cast(),
            wake: Some(ffi_wake),
            retain: Some(ffi_wake_retain),
            release: Some(ffi_wake_release),
        }
    }
}

impl Drop for WakeCall {
    fn drop(&mut self) {
        unsafe { Arc::decrement_strong_count(self.pointer) };
    }
}

unsafe extern "C" fn ffi_wake(context: *mut std::ffi::c_void) {
    let Some(waker) = (unsafe { (context as *const Waker).as_ref() }) else {
        return;
    };
    waker.wake_by_ref();
}

unsafe extern "C" fn ffi_wake_retain(context: *mut std::ffi::c_void) -> u32 {
    if context.is_null() {
        return snolc_abi::STATUS_INVALID;
    }
    unsafe { Arc::increment_strong_count(context as *const Waker) };
    snolc_abi::STATUS_OK
}

unsafe extern "C" fn ffi_wake_release(context: *mut std::ffi::c_void) {
    if !context.is_null() {
        unsafe { Arc::decrement_strong_count(context as *const Waker) };
    }
}

fn bytes(input: &[u8]) -> SnolBytes {
    SnolBytes {
        pointer: input.as_ptr(),
        length: input.len(),
    }
}

fn bytes_mut(output: &mut [u8]) -> SnolBytesMut {
    SnolBytesMut {
        pointer: output.as_mut_ptr(),
        length: output.len(),
    }
}

fn check_output(
    status: u32,
    mut output: Vec<u8>,
    written: usize,
    limit: usize,
) -> Result<Vec<u8>, LoadError> {
    if status != snolc_abi::STATUS_OK {
        return Err(LoadError::ModuleStatus(status));
    }
    if written > output.len() || written > limit {
        return Err(LoadError::OutputLength);
    }
    output.truncate(written);
    Ok(output)
}

#[derive(Debug, Error)]
pub enum LoadError {
    #[error("cannot load module library: {0}")]
    Open(libloading::Error),
    #[error("module entry is unavailable: {0}")]
    Entry(libloading::Error),
    #[error("module entry returned a null descriptor")]
    NullDescriptor,
    #[error("descriptor size {0} is too small")]
    DescriptorSize(u32),
    #[error("module wire version {0} is incompatible")]
    WireVersion(u32),
    #[error("descriptor reserved field is nonzero")]
    Reserved,
    #[error("module class mask {0:#x} is invalid")]
    ClassMask(u32),
    #[error("module class {0:#x} has no API table")]
    ClassTable(u32),
    #[error("module byte I/O table is invalid")]
    ByteIo,
    #[error("module name is invalid")]
    Name,
    #[error("module omits a required function")]
    MissingFunction,
    #[error("module config failed with status {status}: {message}")]
    Config { status: u32, message: String },
    #[error("module returned status {0}")]
    ModuleStatus(u32),
    #[error("module returned an invalid output length")]
    OutputLength,
    #[error("module returned invalid flow metadata")]
    FlowMetadata,
    #[error("module instance was already created")]
    AlreadyCreated,
    #[error("module instance is not created")]
    NotCreated,
    #[error("module returned an invalid handle")]
    InvalidHandle,
    #[error("module does not support this control request")]
    Unsupported,
}

#[cfg(test)]
mod tests {
    use std::ffi::c_void;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::task::Wake;

    use futures::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    unsafe extern "C" fn describe(_: SnolBytesMut, written: *mut usize) -> u32 {
        // test pointer comes from local storage.
        unsafe { *written = 0 };
        snolc_abi::STATUS_OK
    }
    unsafe extern "C" fn validate(
        _: SnolBytes,
        _: SnolBytes,
        _: SnolBytesMut,
        written: *mut usize,
    ) -> u32 {
        // test pointer comes from local storage.
        unsafe { *written = 0 };
        snolc_abi::STATUS_OK
    }
    unsafe extern "C" fn create(
        _: SnolBytes,
        _: SnolBytes,
        _: *const SnolHostApiV1,
        _: *mut u64,
    ) -> u32 {
        snolc_abi::STATUS_OK
    }
    unsafe extern "C" fn poll(_: u64, _: snolc_abi::SnolWakeHandle) -> u32 {
        snolc_abi::STATUS_OK
    }
    unsafe extern "C" fn control(_: u64, _: SnolBytes, _: SnolBytesMut, _: *mut usize) -> u32 {
        snolc_abi::STATUS_UNSUPPORTED
    }
    unsafe extern "C" fn shutdown(_: u64) -> u32 {
        snolc_abi::STATUS_OK
    }
    unsafe extern "C" fn destroy(_: u64) {}
    unsafe extern "C" fn open(
        _: u64,
        _: u64,
        _: *const SnolFlowMetadataV1,
        _: snolc_abi::SnolWakeHandle,
        _: *mut u64,
    ) -> u32 {
        snolc_abi::STATUS_OK
    }

    static ADAPTER: snolc_abi::SnolAdapterApiV1 = snolc_abi::SnolAdapterApiV1 {
        struct_size: size_of::<snolc_abi::SnolAdapterApiV1>() as u32,
        reserved: 0,
        open: Some(open),
        accept: Some(snolc_sdk::module::unsupported_adapter_accept),
        attach: Some(snolc_sdk::module::unsupported_adapter_attach),
        complete: Some(snolc_sdk::module::unsupported_adapter_complete),
        close_flow: Some(snolc_sdk::module::unsupported_adapter_close),
        attach_datagram: None,
        attach_packet_port: None,
        resolve: None,
    };

    static CLOSED: AtomicBool = AtomicBool::new(false);

    unsafe extern "C" fn io_read(_: u64, output: SnolBytesMut, _: SnolWakeHandle) -> SnolIoResult {
        if output.length < 2 || output.pointer.is_null() {
            return SnolIoResult::buffer_too_small(2);
        }
        unsafe { std::ptr::copy_nonoverlapping(b"io".as_ptr(), output.pointer, 2) };
        SnolIoResult::progress(2)
    }

    unsafe extern "C" fn io_write(_: u64, input: SnolBytes, _: SnolWakeHandle) -> SnolIoResult {
        SnolIoResult::progress(input.length)
    }

    unsafe extern "C" fn io_action(_: u64, _: SnolWakeHandle) -> SnolIoResult {
        SnolIoResult::progress(0)
    }

    unsafe extern "C" fn io_close(_: u64) -> u32 {
        CLOSED.store(true, Ordering::Release);
        snolc_abi::STATUS_OK
    }

    static BYTE_IO: SnolByteIoV1 = SnolByteIoV1 {
        struct_size: size_of::<SnolByteIoV1>() as u32,
        reserved: 0,
        read: Some(io_read),
        write: Some(io_write),
        flush: Some(io_action),
        shutdown_write: Some(io_action),
        close: Some(io_close),
    };

    fn descriptor() -> SnolModuleDescriptor {
        SnolModuleDescriptor {
            struct_size: size_of::<SnolModuleDescriptor>() as u32,
            wire_version: snolc_abi::WIRE_VERSION,
            class_mask: snolc_abi::CLASS_ADAPTER,
            reserved: 0,
            name: c"test".as_ptr(),
            describe: Some(describe),
            validate_config: Some(validate),
            create: Some(create),
            poll: Some(poll),
            control: Some(control),
            shutdown: Some(shutdown),
            destroy: Some(destroy),
            byte_io: std::ptr::null(),
            datagram_io: std::ptr::null(),
            adapter: &ADAPTER,
            protection: std::ptr::null(),
            carrier: std::ptr::null(),
            policy: std::ptr::null(),
        }
    }

    #[test]
    fn validates_descriptor_before_lifecycle() {
        let mut descriptor = descriptor();
        let pointer = NonNull::from(&mut descriptor);
        let (name, class) = unsafe { validate_descriptor(pointer) }.unwrap();
        assert_eq!(name, "test");
        assert_eq!(class, snolc_abi::CLASS_ADAPTER);
    }

    #[test]
    fn rejects_wire_and_missing_class_table() {
        let mut descriptor = descriptor();
        descriptor.wire_version = 2;
        assert!(matches!(
            unsafe { validate_descriptor(NonNull::from(&mut descriptor)) },
            Err(LoadError::WireVersion(2))
        ));
        descriptor.wire_version = 1;
        descriptor.adapter = std::ptr::null::<c_void>().cast();
        assert!(matches!(
            unsafe { validate_descriptor(NonNull::from(&mut descriptor)) },
            Err(LoadError::ClassTable(snolc_abi::CLASS_ADAPTER))
        ));
    }

    #[test]
    fn module_byte_io_maps_callbacks_and_closes_once() {
        CLOSED.store(false, Ordering::Release);
        let mut io = ModuleByteIo::new(1, NonNull::from(&BYTE_IO), Vec::new());
        async_io::block_on(async {
            let mut output = [0; 2];
            io.read_exact(&mut output).await.unwrap();
            assert_eq!(&output, b"io");
            io.write_all(b"write").await.unwrap();
            io.flush().await.unwrap();
            AsyncWriteExt::close(&mut io).await.unwrap();
        });
        drop(io);
        assert!(CLOSED.load(Ordering::Acquire));
    }

    struct CountWake(AtomicUsize);

    impl Wake for CountWake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn ffi_wake_supports_retained_module_handles() {
        let state = Arc::new(CountWake(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&state));
        let call = WakeCall::new(&waker);
        let handle = call.handle();
        assert_eq!(
            unsafe { handle.retain.unwrap()(handle.context) },
            snolc_abi::STATUS_OK
        );
        unsafe { handle.wake.unwrap()(handle.context) };
        unsafe { handle.release.unwrap()(handle.context) };
        assert_eq!(state.0.load(Ordering::Relaxed), 1);
    }
}
