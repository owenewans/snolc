#![deny(unsafe_op_in_unsafe_fn)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use serde::Deserialize;
use snolc_sdk::abi::{self, SnolBytes, SnolPolicyApiV1, SnolWakeHandle};
use snolc_sdk::{ByteIo, Pump, PumpError, PumpReport};

pub struct DummyFlow<A, M> {
    stack: A,
    mux: M,
    upload: Pump,
    download: Pump,
}

impl<A: ByteIo, M: ByteIo> DummyFlow<A, M> {
    pub fn new(stack: A, mux: M, buffer_bytes: usize) -> Result<Self, PumpError> {
        Ok(Self {
            stack,
            mux,
            upload: Pump::new(buffer_bytes)?,
            download: Pump::new(buffer_bytes)?,
        })
    }

    pub fn poll(
        &mut self,
        context: &mut Context<'_>,
        max_work: usize,
    ) -> Poll<Result<(PumpReport, PumpReport), PumpError>> {
        let upload = self
            .upload
            .poll(context, &mut self.stack, &mut self.mux, max_work);
        let download = self
            .download
            .poll(context, &mut self.mux, &mut self.stack, max_work);
        match (upload, download) {
            (Poll::Ready(Ok(upload)), Poll::Ready(Ok(download))) => {
                Poll::Ready(Ok((upload, download)))
            }
            (Poll::Ready(Err(error)), _) | (_, Poll::Ready(Err(error))) => Poll::Ready(Err(error)),
            _ => Poll::Pending,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Options {
    pump_buffer_bytes: usize,
}

fn validate_config(config: &[u8], _base: &[u8]) -> Result<(), String> {
    let text = std::str::from_utf8(config).map_err(|_| "config is not UTF-8".to_owned())?;
    let options: Options = toml::from_str(text).map_err(|error| error.to_string())?;
    if options.pump_buffer_bytes == 0 {
        return Err("pump buffer must be nonzero".into());
    }
    Ok(())
}

static SESSION_NEXT: AtomicU64 = AtomicU64::new(1);

unsafe extern "C" fn attach_session(
    instance: u64,
    policy_stream: u64,
    _context: SnolBytes,
    _wake: SnolWakeHandle,
    output: *mut u64,
) -> u32 {
    snolc_sdk::catch_status(|| {
        if !INSTANCES.contains(instance) || policy_stream == 0 {
            return abi::STATUS_INVALID;
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
    name: "policy-dummy",
    description: "name = \"policy-dummy\"\nfamily = \"policy-dummy\"\nroles = [\"client\", \"server\"]\nusers = false\n",
    class_mask: abi::CLASS_POLICY,
    validate: validate_config,
    byte_io: std::ptr::null(),
    datagram_io: std::ptr::null(),
    adapter: std::ptr::null(),
    protection: std::ptr::null(),
    carrier: std::ptr::null(),
    policy: &POLICY,
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io;
    use std::task::Waker;

    use super::*;

    #[derive(Default)]
    struct Memory {
        input: VecDeque<u8>,
        output: Vec<u8>,
    }

    impl ByteIo for Memory {
        fn poll_read(&mut self, _: &mut Context<'_>, output: &mut [u8]) -> Poll<io::Result<usize>> {
            let count = output.len().min(self.input.len());
            for byte in &mut output[..count] {
                *byte = self.input.pop_front().unwrap();
            }
            Poll::Ready(Ok(count))
        }

        fn poll_write(&mut self, _: &mut Context<'_>, input: &[u8]) -> Poll<io::Result<usize>> {
            self.output.extend_from_slice(input);
            Poll::Ready(Ok(input.len()))
        }

        fn poll_flush(&mut self, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown_write(&mut self, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn close(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn pumps_both_directions_without_policy_limits() {
        let stack = Memory {
            input: b"up".iter().copied().collect(),
            ..Memory::default()
        };
        let mux = Memory {
            input: b"down".iter().copied().collect(),
            ..Memory::default()
        };
        let mut flow = DummyFlow::new(stack, mux, 16).unwrap();
        let mut context = Context::from_waker(Waker::noop());
        for _ in 0..4 {
            let _ = flow.poll(&mut context, 16);
        }
        assert_eq!(flow.mux.output, b"up");
        assert_eq!(flow.stack.output, b"down");
    }
}
