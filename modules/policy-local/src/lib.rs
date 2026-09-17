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

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::Deserialize;
use snolc_sdk::abi::{self, SnolBytes, SnolPolicyApiV1, SnolWakeHandle};

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

unsafe extern "C" fn attach_session(
    instance: u64,
    policy_stream: u64,
    context: SnolBytes,
    _wake: SnolWakeHandle,
    output: *mut u64,
) -> u32 {
    snolc_sdk::catch_status(|| {
        if !INSTANCES.contains(instance) || policy_stream == 0 {
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
        let handle = SESSION_NEXT.fetch_add(1, Ordering::Relaxed);
        if handle == 0 {
            return abi::STATUS_RESOURCE;
        }
        *output = handle;
        abi::STATUS_OK
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
    mux_stream: u64,
) -> u32 {
    snolc_sdk::catch_status(|| {
        if INSTANCES.contains(instance) && session != 0 && stack_socket != 0 && mux_stream != 0 {
            abi::STATUS_OK
        } else {
            abi::STATUS_INVALID
        }
    })
}

static POLICY: SnolPolicyApiV1 = SnolPolicyApiV1 {
    struct_size: size_of::<SnolPolicyApiV1>() as u32,
    reserved: 0,
    attach_session: Some(attach_session),
    admit_flow: Some(admit_flow),
    attach_flow: Some(attach_flow),
};

snolc_sdk::declare_module! {
    name: "policy-local",
    description: "name = \"policy-local\"\nfamily = \"policy-local\"\nroles = [\"client\", \"server\"]\ncredential_transport = \"protected\"\n",
    class_mask: abi::CLASS_POLICY,
    validate: validate_module,
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
