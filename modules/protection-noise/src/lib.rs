#![deny(unsafe_op_in_unsafe_fn)]

use std::cell::RefCell;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::Deserialize;
use snolc_sdk::abi::{
    self, SnolByteIoV1, SnolBytes, SnolBytesMut, SnolIoResult, SnolModuleDescriptor,
    SnolProtectionApiV1, SnolWakeHandle,
};
use snow::{Builder, HandshakeState, TransportState, params::NoiseParams};

const PATTERN: &str = "Noise_NK_25519_ChaChaPoly_BLAKE2s";
const PROLOGUE: &[u8] = b"snolc/protection-noise/1";
const MAX_HANDSHAKE: usize = 4096;
const MAX_PLAINTEXT: usize = 16_384;
const MAX_CIPHERTEXT: usize = 16_400;
const RECORD_LIMIT: u64 = 1_u64 << 32;

#[derive(Deserialize)]
#[serde(tag = "mode", rename_all = "lowercase", deny_unknown_fields)]
enum Options {
    Client { server_public_key_file: PathBuf },
    Server { private_key_file: PathBuf },
}

enum RoleKey {
    Client([u8; 32]),
    Server([u8; 32]),
}

impl Drop for RoleKey {
    fn drop(&mut self) {
        match self {
            Self::Client(key) | Self::Server(key) => key.fill(0),
        }
    }
}

struct InstanceState {
    role: RoleKey,
}

struct PendingHandshake {
    owner: u64,
    lower: u64,
    io: *const SnolByteIoV1,
    handshake: Option<HandshakeState>,
    outbound: Vec<u8>,
    outbound_offset: usize,
    inbound: FrameReader,
    server_reply: bool,
}

struct Wrapped {
    owner: u64,
    lower: u64,
    io: *const SnolByteIoV1,
    transport: TransportState,
    outbound: Vec<u8>,
    outbound_offset: usize,
    inbound: FrameReader,
    plaintext: Vec<u8>,
    plaintext_offset: usize,
    sent_records: u64,
    received_records: u64,
}

#[derive(Default)]
struct FrameReader {
    data: Vec<u8>,
    expected: Option<usize>,
}

impl FrameReader {
    fn push(&mut self, input: &[u8], limit: usize) -> Result<(), NoiseError> {
        if self.data.len().saturating_add(input.len()) > limit + 2 {
            return Err(NoiseError::Length);
        }
        self.data.extend_from_slice(input);
        if self.expected.is_none() && self.data.len() >= 2 {
            let length = u16::from_be_bytes([self.data[0], self.data[1]]) as usize;
            if length == 0 || length > limit {
                return Err(NoiseError::Length);
            }
            self.expected = Some(length + 2);
        }
        Ok(())
    }

    fn take(&mut self) -> Option<Vec<u8>> {
        let expected = self.expected?;
        if self.data.len() < expected {
            return None;
        }
        if self.data.len() != expected {
            return None;
        }
        let frame = self.data.split_off(2);
        self.expected = None;
        Some(frame)
    }

    fn remaining_capacity(&self, limit: usize) -> usize {
        self.expected
            .map(|expected| expected.saturating_sub(self.data.len()))
            .unwrap_or_else(|| 2_usize.saturating_sub(self.data.len()).min(limit + 2))
    }
}

pub struct NoiseHandshake {
    state: Option<HandshakeState>,
    responder: bool,
}

impl NoiseHandshake {
    pub fn client(server_public_key: &[u8; 32]) -> Result<Self, NoiseError> {
        let params: NoiseParams = PATTERN.parse().map_err(NoiseError::Snow)?;
        let state = Builder::new(params)
            .prologue(PROLOGUE)
            .map_err(NoiseError::Snow)?
            .remote_public_key(server_public_key)
            .map_err(NoiseError::Snow)?
            .build_initiator()
            .map_err(NoiseError::Snow)?;
        Ok(Self {
            state: Some(state),
            responder: false,
        })
    }

    pub fn server(private_key: &[u8; 32]) -> Result<Self, NoiseError> {
        let params: NoiseParams = PATTERN.parse().map_err(NoiseError::Snow)?;
        let state = Builder::new(params)
            .prologue(PROLOGUE)
            .map_err(NoiseError::Snow)?
            .local_private_key(private_key)
            .map_err(NoiseError::Snow)?
            .build_responder()
            .map_err(NoiseError::Snow)?;
        Ok(Self {
            state: Some(state),
            responder: true,
        })
    }

    pub fn initial(&mut self) -> Result<Vec<u8>, NoiseError> {
        if self.responder {
            return Err(NoiseError::State);
        }
        self.write_handshake()
    }

    pub fn receive(&mut self, message: &[u8]) -> Result<Option<Vec<u8>>, NoiseError> {
        if message.len() > MAX_HANDSHAKE {
            return Err(NoiseError::Length);
        }
        let state = self.state.as_mut().ok_or(NoiseError::State)?;
        let mut payload = [0; MAX_HANDSHAKE];
        let payload_length = state
            .read_message(message, &mut payload)
            .map_err(NoiseError::Snow)?;
        if payload_length != 0 {
            return Err(NoiseError::HandshakePayload);
        }
        if self.responder {
            Ok(Some(self.write_handshake()?))
        } else {
            Ok(None)
        }
    }

    pub fn finish(mut self) -> Result<NoiseTransport, NoiseError> {
        let state = self.state.take().ok_or(NoiseError::State)?;
        if !state.is_handshake_finished() {
            return Err(NoiseError::State);
        }
        Ok(NoiseTransport {
            state: state.into_transport_mode().map_err(NoiseError::Snow)?,
            sent_records: 0,
            received_records: 0,
        })
    }

    fn write_handshake(&mut self) -> Result<Vec<u8>, NoiseError> {
        let state = self.state.as_mut().ok_or(NoiseError::State)?;
        let mut message = vec![0; MAX_HANDSHAKE];
        let length = state
            .write_message(&[], &mut message)
            .map_err(NoiseError::Snow)?;
        message.truncate(length);
        frame(&message, MAX_HANDSHAKE)
    }
}

pub struct NoiseTransport {
    state: TransportState,
    sent_records: u64,
    received_records: u64,
}

impl NoiseTransport {
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if plaintext.is_empty() || plaintext.len() > MAX_PLAINTEXT {
            return Err(NoiseError::Length);
        }
        if self.sent_records >= RECORD_LIMIT {
            return Err(NoiseError::RecordLimit);
        }
        let mut ciphertext = vec![0; MAX_CIPHERTEXT];
        let length = self
            .state
            .write_message(plaintext, &mut ciphertext)
            .map_err(NoiseError::Snow)?;
        ciphertext.truncate(length);
        self.sent_records += 1;
        frame(&ciphertext, MAX_CIPHERTEXT)
    }

    pub fn open(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if ciphertext.is_empty() || ciphertext.len() > MAX_CIPHERTEXT {
            return Err(NoiseError::Length);
        }
        if self.received_records >= RECORD_LIMIT {
            return Err(NoiseError::RecordLimit);
        }
        let mut plaintext = vec![0; MAX_PLAINTEXT];
        let length = self
            .state
            .read_message(ciphertext, &mut plaintext)
            .map_err(NoiseError::Snow)?;
        if length == 0 {
            return Err(NoiseError::Length);
        }
        plaintext.truncate(length);
        self.received_records += 1;
        Ok(plaintext)
    }
}

fn frame(message: &[u8], limit: usize) -> Result<Vec<u8>, NoiseError> {
    if message.is_empty() || message.len() > limit || message.len() > usize::from(u16::MAX) {
        return Err(NoiseError::Length);
    }
    let mut output = Vec::with_capacity(message.len() + 2);
    output.extend_from_slice(&(message.len() as u16).to_be_bytes());
    output.extend_from_slice(message);
    Ok(output)
}

thread_local! {
    static INSTANCES: RefCell<HashMap<u64, InstanceState>> = RefCell::new(HashMap::new());
    static PENDING: RefCell<HashMap<u64, PendingHandshake>> = RefCell::new(HashMap::new());
    static WRAPPED: RefCell<HashMap<u64, Wrapped>> = RefCell::new(HashMap::new());
}

static INSTANCE_NEXT: AtomicU64 = AtomicU64::new(1);
static WRAPPED_NEXT: AtomicU64 = AtomicU64::new(1);

fn load_options(config: &[u8], base: &[u8]) -> Result<RoleKey, String> {
    let config = std::str::from_utf8(config).map_err(|_| "config is not UTF-8".to_owned())?;
    let base = std::str::from_utf8(base).map_err(|_| "base directory is not UTF-8".to_owned())?;
    let options: Options = toml::from_str(config).map_err(|error| error.to_string())?;
    match options {
        Options::Client {
            server_public_key_file,
        } => Ok(RoleKey::Client(read_key(base, &server_public_key_file)?)),
        Options::Server { private_key_file } => {
            Ok(RoleKey::Server(read_key(base, &private_key_file)?))
        }
    }
}

fn read_key(base: &str, path: &Path) -> Result<[u8; 32], String> {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        Path::new(base).join(path)
    };
    let mut bytes = fs::read(path).map_err(|error| error.to_string())?;
    let result = if bytes.len() == 32 {
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| "key length".to_owned())
    } else {
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| "key must be raw or hexadecimal".to_owned())?
            .trim();
        decode_hex(text)
    };
    bytes.fill(0);
    result
}

fn decode_hex(input: &str) -> Result<[u8; 32], String> {
    if input.len() != 64 {
        return Err("key must contain 32 bytes".into());
    }
    let mut key = [0; 32];
    for (index, byte) in key.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&input[offset..offset + 2], 16)
            .map_err(|_| "key is not hexadecimal".to_owned())?;
    }
    Ok(key)
}

unsafe extern "C" fn describe(output: SnolBytesMut, written: *mut usize) -> u32 {
    snolc_sdk::catch_status(|| unsafe {
        snolc_sdk::module::write_output(
            b"name = \"protection-noise\"\nroles = [\"client\", \"server\"]\npattern = \"Noise_NK_25519_ChaChaPoly_BLAKE2s\"\nconfidentiality = true\nintegrity = true\nserver_authenticated = true\nclient_authenticated = false\n",
            output,
            written,
        )
    })
}

unsafe extern "C" fn validate_config(
    config: SnolBytes,
    base: SnolBytes,
    error: SnolBytesMut,
    written: *mut usize,
) -> u32 {
    snolc_sdk::catch_status(|| {
        let (config, base) = match unsafe {
            (
                snolc_sdk::module::input(config),
                snolc_sdk::module::input(base),
            )
        } {
            (Ok(config), Ok(base)) => (config, base),
            (Err(status), _) | (_, Err(status)) => return status,
        };
        match load_options(config, base) {
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
    base: SnolBytes,
    _host: *const abi::SnolHostApiV1,
    output: *mut u64,
) -> u32 {
    snolc_sdk::catch_status(|| {
        let (config, base) = match unsafe {
            (
                snolc_sdk::module::input(config),
                snolc_sdk::module::input(base),
            )
        } {
            (Ok(config), Ok(base)) => (config, base),
            (Err(status), _) | (_, Err(status)) => return status,
        };
        let role = match load_options(config, base) {
            Ok(role) => role,
            Err(_) => return abi::STATUS_INVALID,
        };
        let Some(output) = (unsafe { output.as_mut() }) else {
            return abi::STATUS_INVALID;
        };
        let handle = INSTANCE_NEXT.fetch_add(1, Ordering::Relaxed);
        if handle == 0 {
            return abi::STATUS_RESOURCE;
        }
        INSTANCES.with(|instances| {
            instances
                .borrow_mut()
                .insert(handle, InstanceState { role });
        });
        *output = handle;
        abi::STATUS_OK
    })
}

unsafe extern "C" fn poll(instance: u64, _wake: SnolWakeHandle) -> u32 {
    snolc_sdk::catch_status(|| {
        if INSTANCES.with(|instances| instances.borrow().contains_key(&instance)) {
            abi::STATUS_PENDING
        } else {
            abi::STATUS_INVALID
        }
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
        PENDING.with(|pending| {
            pending
                .borrow_mut()
                .retain(|_, state| state.owner != instance)
        });
        WRAPPED.with(|wrapped| {
            wrapped
                .borrow_mut()
                .retain(|_, state| state.owner != instance)
        });
        INSTANCES.with(|instances| instances.borrow_mut().remove(&instance));
    });
}

unsafe extern "C" fn wrap(
    instance: u64,
    lower: u64,
    io: *const SnolByteIoV1,
    _context: SnolBytes,
    wake: SnolWakeHandle,
    output: *mut u64,
) -> u32 {
    snolc_sdk::catch_status(|| {
        if lower == 0 || !valid_io(io) || output.is_null() {
            return abi::STATUS_INVALID;
        }
        let pending = PENDING.with(|pending| pending.borrow_mut().remove(&lower));
        let mut pending = match pending {
            Some(pending) if pending.owner == instance && pending.io == io => pending,
            Some(_) => return abi::STATUS_INVALID,
            None => {
                let handshake = INSTANCES.with(|instances| {
                    let instances = instances.borrow();
                    let state = instances.get(&instance).ok_or(NoiseError::State)?;
                    match &state.role {
                        RoleKey::Client(key) => NoiseHandshake::client(key),
                        RoleKey::Server(key) => NoiseHandshake::server(key),
                    }
                });
                let mut handshake = match handshake {
                    Ok(handshake) => handshake,
                    Err(_) => return abi::STATUS_INVALID,
                };
                let (outbound, server_reply) = match handshake.responder {
                    true => (Vec::new(), true),
                    false => match handshake.initial() {
                        Ok(frame) => (frame, false),
                        Err(_) => return abi::STATUS_INTERNAL,
                    },
                };
                PendingHandshake {
                    owner: instance,
                    lower,
                    io,
                    handshake: handshake.state.take(),
                    outbound,
                    outbound_offset: 0,
                    inbound: FrameReader::default(),
                    server_reply,
                }
            }
        };
        match pending.drive(wake) {
            Ok(Some(transport)) => {
                let handle = WRAPPED_NEXT.fetch_add(1, Ordering::Relaxed);
                if handle == 0 {
                    return abi::STATUS_RESOURCE;
                }
                WRAPPED.with(|wrapped| {
                    wrapped.borrow_mut().insert(
                        handle,
                        Wrapped {
                            owner: instance,
                            lower,
                            io,
                            transport,
                            outbound: Vec::new(),
                            outbound_offset: 0,
                            inbound: FrameReader::default(),
                            plaintext: Vec::new(),
                            plaintext_offset: 0,
                            sent_records: 0,
                            received_records: 0,
                        },
                    );
                });
                unsafe { *output = handle };
                abi::STATUS_OK
            }
            Ok(None) => {
                PENDING.with(|states| states.borrow_mut().insert(lower, pending));
                abi::STATUS_PENDING
            }
            Err(_) => {
                close_lower(io, lower);
                abi::STATUS_IO
            }
        }
    })
}

impl PendingHandshake {
    fn drive(&mut self, wake: SnolWakeHandle) -> Result<Option<TransportState>, NoiseError> {
        if !self.outbound.is_empty() {
            if !flush_bytes(
                self.io,
                self.lower,
                &self.outbound,
                &mut self.outbound_offset,
                wake,
            )? {
                return Ok(None);
            }
            self.outbound.clear();
            self.outbound_offset = 0;
            if self.server_reply {
                return self.finish().map(Some);
            }
        }
        let Some(message) =
            read_frame(self.io, self.lower, &mut self.inbound, MAX_HANDSHAKE, wake)?
        else {
            return Ok(None);
        };
        let state = self.handshake.as_mut().ok_or(NoiseError::State)?;
        let mut payload = [0; MAX_HANDSHAKE];
        let payload_length = state
            .read_message(&message, &mut payload)
            .map_err(NoiseError::Snow)?;
        if payload_length != 0 {
            return Err(NoiseError::HandshakePayload);
        }
        if self.server_reply {
            let mut response = vec![0; MAX_HANDSHAKE];
            let length = state
                .write_message(&[], &mut response)
                .map_err(NoiseError::Snow)?;
            response.truncate(length);
            self.outbound = frame(&response, MAX_HANDSHAKE)?;
            if flush_bytes(
                self.io,
                self.lower,
                &self.outbound,
                &mut self.outbound_offset,
                wake,
            )? {
                self.finish().map(Some)
            } else {
                Ok(None)
            }
        } else {
            self.finish().map(Some)
        }
    }

    fn finish(&mut self) -> Result<TransportState, NoiseError> {
        let state = self.handshake.take().ok_or(NoiseError::State)?;
        if !state.is_handshake_finished() {
            return Err(NoiseError::State);
        }
        state.into_transport_mode().map_err(NoiseError::Snow)
    }
}

unsafe extern "C" fn read(handle: u64, output: SnolBytesMut, wake: SnolWakeHandle) -> SnolIoResult {
    snolc_sdk::catch_io(|| {
        if output.pointer.is_null() && output.length != 0 {
            return SnolIoResult::error(abi::STATUS_INVALID);
        }
        WRAPPED.with(|wrapped| {
            let mut wrapped = wrapped.borrow_mut();
            let Some(state) = wrapped.get_mut(&handle) else {
                return SnolIoResult::error(abi::STATUS_INVALID);
            };
            let output = if output.length == 0 {
                &mut []
            } else {
                unsafe { std::slice::from_raw_parts_mut(output.pointer, output.length) }
            };
            if state.plaintext_offset < state.plaintext.len() {
                return copy_plaintext(state, output);
            }
            if state.received_records >= RECORD_LIMIT {
                return SnolIoResult::error(abi::STATUS_IO);
            }
            let ciphertext = match read_frame(
                state.io,
                state.lower,
                &mut state.inbound,
                MAX_CIPHERTEXT,
                wake,
            ) {
                Ok(Some(ciphertext)) => ciphertext,
                Ok(None) => return SnolIoResult::pending(),
                Err(NoiseError::Eof) => return SnolIoResult::eof(),
                Err(_) => return SnolIoResult::error(abi::STATUS_IO),
            };
            let mut plaintext = vec![0; MAX_PLAINTEXT];
            let length = match state.transport.read_message(&ciphertext, &mut plaintext) {
                Ok(0) | Err(_) => return SnolIoResult::error(abi::STATUS_IO),
                Ok(length) => length,
            };
            plaintext.truncate(length);
            state.received_records += 1;
            state.plaintext = plaintext;
            state.plaintext_offset = 0;
            copy_plaintext(state, output)
        })
    })
}

fn copy_plaintext(state: &mut Wrapped, output: &mut [u8]) -> SnolIoResult {
    if output.is_empty() {
        return SnolIoResult::progress(0);
    }
    let remaining = &state.plaintext[state.plaintext_offset..];
    let count = remaining.len().min(output.len());
    output[..count].copy_from_slice(&remaining[..count]);
    state.plaintext_offset += count;
    if state.plaintext_offset == state.plaintext.len() {
        state.plaintext.clear();
        state.plaintext_offset = 0;
    }
    SnolIoResult::progress(count)
}

unsafe extern "C" fn write(handle: u64, input: SnolBytes, wake: SnolWakeHandle) -> SnolIoResult {
    snolc_sdk::catch_io(|| {
        let input = match unsafe { snolc_sdk::module::input(input) } {
            Ok(input) => input,
            Err(status) => return SnolIoResult::error(status),
        };
        WRAPPED.with(|wrapped| {
            let mut wrapped = wrapped.borrow_mut();
            let Some(state) = wrapped.get_mut(&handle) else {
                return SnolIoResult::error(abi::STATUS_INVALID);
            };
            if !state.outbound.is_empty() {
                match flush_wrapped(state, wake) {
                    Ok(true) => {}
                    Ok(false) => return SnolIoResult::pending(),
                    Err(_) => return SnolIoResult::error(abi::STATUS_IO),
                }
            }
            if input.is_empty() {
                return SnolIoResult::progress(0);
            }
            if state.sent_records >= RECORD_LIMIT {
                return SnolIoResult::error(abi::STATUS_IO);
            }
            let count = input.len().min(MAX_PLAINTEXT);
            let mut ciphertext = vec![0; MAX_CIPHERTEXT];
            let length = match state
                .transport
                .write_message(&input[..count], &mut ciphertext)
            {
                Ok(length) => length,
                Err(_) => return SnolIoResult::error(abi::STATUS_IO),
            };
            ciphertext.truncate(length);
            state.outbound = match frame(&ciphertext, MAX_CIPHERTEXT) {
                Ok(frame) => frame,
                Err(_) => return SnolIoResult::error(abi::STATUS_IO),
            };
            state.outbound_offset = 0;
            state.sent_records += 1;
            SnolIoResult::progress(count)
        })
    })
}

unsafe extern "C" fn flush(handle: u64, wake: SnolWakeHandle) -> SnolIoResult {
    snolc_sdk::catch_io(|| {
        WRAPPED.with(|wrapped| {
            let mut wrapped = wrapped.borrow_mut();
            let Some(state) = wrapped.get_mut(&handle) else {
                return SnolIoResult::error(abi::STATUS_INVALID);
            };
            match flush_wrapped(state, wake) {
                Ok(false) => return SnolIoResult::pending(),
                Err(_) => return SnolIoResult::error(abi::STATUS_IO),
                Ok(true) => {}
            }
            let Some(flush) = (unsafe { &*state.io }).flush else {
                return SnolIoResult::error(abi::STATUS_INVALID);
            };
            unsafe { flush(state.lower, wake) }
        })
    })
}

unsafe extern "C" fn shutdown_write(handle: u64, wake: SnolWakeHandle) -> SnolIoResult {
    snolc_sdk::catch_io(|| {
        WRAPPED.with(|wrapped| {
            let mut wrapped = wrapped.borrow_mut();
            let Some(state) = wrapped.get_mut(&handle) else {
                return SnolIoResult::error(abi::STATUS_INVALID);
            };
            match flush_wrapped(state, wake) {
                Ok(false) => return SnolIoResult::pending(),
                Err(_) => return SnolIoResult::error(abi::STATUS_IO),
                Ok(true) => {}
            }
            let Some(shutdown) = (unsafe { &*state.io }).shutdown_write else {
                return SnolIoResult::error(abi::STATUS_INVALID);
            };
            unsafe { shutdown(state.lower, wake) }
        })
    })
}

unsafe extern "C" fn close(handle: u64) -> u32 {
    snolc_sdk::catch_status(|| {
        let state = WRAPPED.with(|wrapped| wrapped.borrow_mut().remove(&handle));
        let Some(state) = state else {
            return abi::STATUS_INVALID;
        };
        close_lower(state.io, state.lower)
    })
}

fn flush_wrapped(state: &mut Wrapped, wake: SnolWakeHandle) -> Result<bool, NoiseError> {
    let complete = flush_bytes(
        state.io,
        state.lower,
        &state.outbound,
        &mut state.outbound_offset,
        wake,
    )?;
    if complete {
        state.outbound.clear();
        state.outbound_offset = 0;
    }
    Ok(complete)
}

fn flush_bytes(
    io: *const SnolByteIoV1,
    lower: u64,
    bytes: &[u8],
    offset: &mut usize,
    wake: SnolWakeHandle,
) -> Result<bool, NoiseError> {
    let write = unsafe { &*io }.write.ok_or(NoiseError::Io)?;
    while *offset < bytes.len() {
        let input = SnolBytes {
            pointer: bytes[*offset..].as_ptr(),
            length: bytes.len() - *offset,
        };
        let result = unsafe { write(lower, input, wake) };
        match result.tag {
            abi::IO_PROGRESS if result.count > 0 && result.count <= input.length => {
                *offset += result.count;
            }
            abi::IO_PENDING => return Ok(false),
            _ => return Err(NoiseError::Io),
        }
    }
    Ok(true)
}

fn read_frame(
    io: *const SnolByteIoV1,
    lower: u64,
    reader: &mut FrameReader,
    limit: usize,
    wake: SnolWakeHandle,
) -> Result<Option<Vec<u8>>, NoiseError> {
    if let Some(frame) = reader.take() {
        return Ok(Some(frame));
    }
    let read = unsafe { &*io }.read.ok_or(NoiseError::Io)?;
    loop {
        let capacity = reader.remaining_capacity(limit);
        if capacity == 0 {
            return Err(NoiseError::Length);
        }
        let mut buffer = vec![0; capacity];
        let output = SnolBytesMut {
            pointer: buffer.as_mut_ptr(),
            length: buffer.len(),
        };
        let result = unsafe { read(lower, output, wake) };
        match result.tag {
            abi::IO_PROGRESS if result.count <= buffer.len() => {
                if result.count == 0 {
                    return Err(NoiseError::Io);
                }
                reader.push(&buffer[..result.count], limit)?;
                if let Some(frame) = reader.take() {
                    return Ok(Some(frame));
                }
            }
            abi::IO_PENDING => return Ok(None),
            abi::IO_EOF => return Err(NoiseError::Eof),
            _ => return Err(NoiseError::Io),
        }
    }
}

fn valid_io(io: *const SnolByteIoV1) -> bool {
    if io.is_null() {
        return false;
    }
    let io = unsafe { &*io };
    io.struct_size >= size_of::<SnolByteIoV1>() as u32
        && io.reserved == 0
        && io.read.is_some()
        && io.write.is_some()
        && io.flush.is_some()
        && io.shutdown_write.is_some()
        && io.close.is_some()
}

fn close_lower(io: *const SnolByteIoV1, lower: u64) -> u32 {
    let Some(close) = (unsafe { &*io }).close else {
        return abi::STATUS_INVALID;
    };
    unsafe { close(lower) }
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

static PROTECTION: SnolProtectionApiV1 = SnolProtectionApiV1 {
    struct_size: size_of::<SnolProtectionApiV1>() as u32,
    reserved: 0,
    wrap: Some(wrap),
};

static DESCRIPTOR: SnolModuleDescriptor = SnolModuleDescriptor {
    struct_size: size_of::<SnolModuleDescriptor>() as u32,
    wire_version: abi::WIRE_VERSION,
    class_mask: abi::CLASS_PROTECTION,
    reserved: 0,
    name: c"protection-noise".as_ptr(),
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
    protection: &PROTECTION,
    carrier: std::ptr::null(),
    policy: std::ptr::null(),
};

#[unsafe(no_mangle)]
pub extern "C" fn snolc_module_entry() -> *const SnolModuleDescriptor {
    &DESCRIPTOR
}

#[derive(Debug)]
pub enum NoiseError {
    Snow(snow::Error),
    Length,
    State,
    HandshakePayload,
    RecordLimit,
    Io,
    Eof,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (NoiseTransport, NoiseTransport) {
        let params: NoiseParams = PATTERN.parse().unwrap();
        let keypair = Builder::new(params).generate_keypair().unwrap();
        let private: [u8; 32] = keypair.private.try_into().unwrap();
        let public: [u8; 32] = keypair.public.try_into().unwrap();
        let mut client = NoiseHandshake::client(&public).unwrap();
        let mut server = NoiseHandshake::server(&private).unwrap();
        let first = client.initial().unwrap();
        let first = &first[2..];
        let second = server.receive(first).unwrap().unwrap();
        let second = &second[2..];
        assert!(client.receive(second).unwrap().is_none());
        (client.finish().unwrap(), server.finish().unwrap())
    }

    #[test]
    fn nk_transport_interoperates_in_both_directions() {
        let (mut client, mut server) = pair();
        let client_record = client.seal(b"client").unwrap();
        assert_eq!(server.open(&client_record[2..]).unwrap(), b"client");
        let server_record = server.seal(b"server").unwrap();
        assert_eq!(client.open(&server_record[2..]).unwrap(), b"server");
    }

    #[test]
    fn frame_reader_accepts_every_split() {
        let (mut client, _) = pair();
        let record = client.seal(b"payload").unwrap();
        for split in 0..=record.len() {
            let mut reader = FrameReader::default();
            reader.push(&record[..split], MAX_CIPHERTEXT).unwrap();
            assert_eq!(reader.take().is_some(), split == record.len());
            if split < record.len() {
                reader.push(&record[split..], MAX_CIPHERTEXT).unwrap();
                assert_eq!(reader.take().unwrap(), record[2..]);
            }
        }
    }

    #[test]
    fn rejects_oversized_plaintext_and_tampering() {
        let (mut client, mut server) = pair();
        assert!(matches!(
            client.seal(&vec![0; MAX_PLAINTEXT + 1]),
            Err(NoiseError::Length)
        ));
        let mut record = client.seal(b"payload").unwrap();
        *record.last_mut().unwrap() ^= 1;
        assert!(matches!(
            server.open(&record[2..]),
            Err(NoiseError::Snow(_))
        ));
    }
}
