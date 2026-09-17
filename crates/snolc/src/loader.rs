use std::ffi::CStr;
use std::path::{Path, PathBuf};
use std::ptr::NonNull;

use libloading::{Library, Symbol};
use snolc_abi::{ModuleEntry, SnolBytes, SnolBytesMut, SnolHostApiV1, SnolModuleDescriptor};
use thiserror::Error;

const KNOWN_CLASSES: u32 = snolc_abi::CLASS_ADAPTER
    | snolc_abi::CLASS_PROTECTION
    | snolc_abi::CLASS_CARRIER
    | snolc_abi::CLASS_POLICY;
const MAX_DESCRIPTION: usize = 65_536;
const MAX_CONFIG_ERROR: usize = 4096;

pub struct LoadedModule {
    descriptor: NonNull<SnolModuleDescriptor>,
    library: Library,
    path: PathBuf,
    name: String,
    class_mask: u32,
    config: Vec<u8>,
    base_directory: Vec<u8>,
    instance: Option<u64>,
}

// the descriptor is immutable and the owned library keeps its storage alive.
unsafe impl Send for LoadedModule {}

impl LoadedModule {
    pub fn load(path: &Path, config: Vec<u8>, base_directory: &Path) -> Result<Self, LoadError> {
        // loading trusted native code can execute library initializers.
        let library = unsafe { Library::new(path) }.map_err(LoadError::Open)?;
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
            path: path.to_path_buf(),
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

    pub fn class_mask(&self) -> u32 {
        self.class_mask
    }

    pub fn path(&self) -> &Path {
        &self.path
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
        let status = unsafe { function(bytes(&self.config), host, &mut instance) };
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

    pub fn control(&mut self, request: &[u8], max_response: usize) -> Result<Vec<u8>, LoadError> {
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
            return Err(LoadError::Unsupported);
        }
        check_output(status, output, written, max_response)
    }

    pub fn shutdown(&mut self) -> Result<(), LoadError> {
        let Some(instance) = self.instance else {
            return Ok(());
        };
        let function = self
            .descriptor()
            .shutdown
            .ok_or(LoadError::MissingFunction)?;
        // lifecycle calls run only on the engine owner thread.
        let status = unsafe { function(instance) };
        if status == snolc_abi::STATUS_OK {
            Ok(())
        } else {
            Err(LoadError::ModuleStatus(status))
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
    Ok(())
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
    unsafe extern "C" fn create(_: SnolBytes, _: *const SnolHostApiV1, _: *mut u64) -> u32 {
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
        _: SnolBytes,
        _: snolc_abi::SnolWakeHandle,
        _: *mut u64,
    ) -> u32 {
        snolc_abi::STATUS_OK
    }

    static ADAPTER: snolc_abi::SnolAdapterApiV1 = snolc_abi::SnolAdapterApiV1 {
        struct_size: size_of::<snolc_abi::SnolAdapterApiV1>() as u32,
        reserved: 0,
        open: Some(open),
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
}
