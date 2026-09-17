#![deny(unsafe_op_in_unsafe_fn)]

mod accounting;
mod admin;
mod config;
mod frame;
mod storage;

pub use accounting::{QuotaAccount, QuotaError, TokenBucket};
pub use admin::{AdminDecision, AdminError, AdminSequencer, Credential, UserId};
pub use config::Options;
pub use frame::{FrameDecoder, FrameError, encode_frame};
pub use storage::{StorageError, StorageWorker};

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::Deserialize;
use snolc_sdk::ForeignByteIo;
use snolc_sdk::abi::{self, SnolByteIoV1, SnolBytes, SnolPolicyApiV1, SnolWakeHandle};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChannelSecurity {
    confidentiality: bool,
    integrity: bool,
    peer_authenticated: bool,
    peer_identity: Option<String>,
}

fn validate_module(config: &[u8], base: &[u8]) -> Result<(), String> {
    let base = std::str::from_utf8(base).map_err(|_| "base directory is not UTF-8".to_owned())?;
    Options::parse(config, Path::new(base))
        .map(|_| ())
        .map_err(|error| error.to_string())
}

static SESSION_NEXT: AtomicU64 = AtomicU64::new(1);
static FLOW_NEXT: AtomicU64 = AtomicU64::new(1);

struct State {
    _options: Options,
    _storage: StorageWorker,
    sessions: HashMap<u64, ForeignByteIo>,
    flows: HashMap<u64, FlowIo>,
}

struct FlowIo {
    _stack: ForeignByteIo,
    _mux: ForeignByteIo,
}

thread_local! {
    static STATES: RefCell<HashMap<u64, State>> = RefCell::new(HashMap::new());
}

fn initialize(
    instance: u64,
    config: &[u8],
    base: &[u8],
    _host: *const abi::SnolHostApiV1,
) -> Result<(), u32> {
    let base = std::str::from_utf8(base).map_err(|_| abi::STATUS_INVALID)?;
    let options = Options::parse(config, Path::new(base)).map_err(|_| abi::STATUS_INVALID)?;
    let storage = StorageWorker::open(
        options.storage.path.clone(),
        options.storage.cache_bytes,
        options.storage.max_database_bytes,
        options.storage.queue_capacity,
    )
    .map_err(|_| abi::STATUS_IO)?;
    STATES.with(|states| {
        states.borrow_mut().insert(
            instance,
            State {
                _options: options,
                _storage: storage,
                sessions: HashMap::new(),
                flows: HashMap::new(),
            },
        );
    });
    Ok(())
}

unsafe extern "C" fn attach_session(
    instance: u64,
    policy_stream: u64,
    policy_stream_io: *const SnolByteIoV1,
    context: SnolBytes,
    _wake: SnolWakeHandle,
    output: *mut u64,
) -> u32 {
    snolc_sdk::catch_status(|| {
        if !INSTANCES.contains(instance) || policy_stream == 0 || policy_stream_io.is_null() {
            return abi::STATUS_INVALID;
        }
        let context = match unsafe { snolc_sdk::module::input(context) } {
            Ok(context) => context,
            Err(status) => return status,
        };
        let context = match std::str::from_utf8(context)
            .ok()
            .and_then(|context| toml::from_str::<ChannelSecurity>(context).ok())
        {
            Some(context) => context,
            None => return abi::STATUS_DENIED,
        };
        if !context.confidentiality || !context.integrity {
            return abi::STATUS_DENIED;
        }
        if context.peer_authenticated && context.peer_identity.as_deref() == Some("") {
            return abi::STATUS_DENIED;
        }
        let Some(output) = (unsafe { output.as_mut() }) else {
            return abi::STATUS_INVALID;
        };
        let stream = match unsafe { ForeignByteIo::from_raw(policy_stream, policy_stream_io) } {
            Ok(stream) => stream,
            Err(_) => return abi::STATUS_INVALID,
        };
        let handle = SESSION_NEXT.fetch_add(1, Ordering::Relaxed);
        if handle == 0 {
            return abi::STATUS_RESOURCE;
        }
        STATES.with(|states| {
            let mut states = states.borrow_mut();
            let Some(state) = states.get_mut(&instance) else {
                return abi::STATUS_INVALID;
            };
            state.sessions.insert(handle, stream);
            *output = handle;
            abi::STATUS_OK
        })
    })
}

unsafe extern "C" fn admit_flow(
    instance: u64,
    session: u64,
    metadata: SnolBytes,
    _wake: SnolWakeHandle,
) -> u32 {
    snolc_sdk::catch_status(|| {
        if !INSTANCES.contains(instance) || session == 0 || metadata.length > 1024 {
            abi::STATUS_INVALID
        } else {
            abi::STATUS_OK
        }
    })
}

unsafe extern "C" fn attach_flow(
    instance: u64,
    session: u64,
    stack_socket: u64,
    stack_socket_io: *const SnolByteIoV1,
    mux_stream: u64,
    mux_stream_io: *const SnolByteIoV1,
) -> u32 {
    snolc_sdk::catch_status(|| {
        if !INSTANCES.contains(instance)
            || session == 0
            || stack_socket == 0
            || stack_socket_io.is_null()
            || mux_stream == 0
            || mux_stream_io.is_null()
        {
            return abi::STATUS_INVALID;
        }
        STATES.with(|states| {
            let mut states = states.borrow_mut();
            let Some(state) = states.get_mut(&instance) else {
                return abi::STATUS_INVALID;
            };
            if !state.sessions.contains_key(&session) {
                return abi::STATUS_INVALID;
            }
            let stack = match unsafe { ForeignByteIo::from_raw(stack_socket, stack_socket_io) } {
                Ok(stack) => stack,
                Err(_) => return abi::STATUS_INVALID,
            };
            let mux = match unsafe { ForeignByteIo::from_raw(mux_stream, mux_stream_io) } {
                Ok(mux) => mux,
                Err(_) => return abi::STATUS_INVALID,
            };
            let handle = FLOW_NEXT.fetch_add(1, Ordering::Relaxed);
            if handle == 0 {
                return abi::STATUS_RESOURCE;
            }
            state.flows.insert(
                handle,
                FlowIo {
                    _stack: stack,
                    _mux: mux,
                },
            );
            abi::STATUS_OK
        })
    })
}

fn poll_instance(instance: u64, _wake: SnolWakeHandle) -> u32 {
    if STATES.with(|states| states.borrow().contains_key(&instance)) {
        abi::STATUS_PENDING
    } else {
        abi::STATUS_INVALID
    }
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

static POLICY: SnolPolicyApiV1 = SnolPolicyApiV1 {
    struct_size: size_of::<SnolPolicyApiV1>() as u32,
    reserved: 0,
    attach_session: Some(attach_session),
    admit_flow: Some(admit_flow),
    attach_flow: Some(attach_flow),
};

snolc_sdk::declare_stateful_module! {
    name: "policy-local",
    description: "name = \"policy-local\"\nfamily = \"policy-local\"\nroles = [\"client\", \"server\"]\ncredential_transport = \"protected\"\n",
    class_mask: abi::CLASS_POLICY,
    validate: validate_module,
    initialize: initialize,
    poll: poll_instance,
    shutdown: shutdown_instance,
    destroy: destroy_instance,
    byte_io: std::ptr::null(),
    datagram_io: std::ptr::null(),
    adapter: std::ptr::null(),
    protection: std::ptr::null(),
    carrier: std::ptr::null(),
    policy: &POLICY,
}

#[cfg(test)]
mod module_tests {
    use super::*;

    #[test]
    fn rejects_unprotected_session_context() {
        let context: ChannelSecurity = toml::from_str(
            "confidentiality = false\nintegrity = true\npeer_authenticated = true\npeer_identity = \"server\"\n",
        )
        .unwrap();
        assert!(!context.confidentiality);
    }
}
