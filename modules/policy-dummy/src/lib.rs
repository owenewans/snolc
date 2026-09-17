#![deny(unsafe_op_in_unsafe_fn)]

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, Waker};

use serde::Deserialize;
use snolc_sdk::abi::{
    self, SnolByteIoV1, SnolBytes, SnolDatagramIoV1, SnolPolicyApiV1, SnolWakeHandle,
};
use snolc_sdk::{
    ByteIo, DatagramIo, DatagramPump, DatagramPumpReport, ForeignByteIo, ForeignDatagramIo, Pump,
    PumpError, PumpReport,
};

const MAX_UDP_PAYLOAD: usize = 65_507;

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

pub struct DummyDatagramFlow<A, M> {
    stack: A,
    mux: M,
    upload: DatagramPump,
    download: DatagramPump,
}

impl<A: DatagramIo, M: DatagramIo> DummyDatagramFlow<A, M> {
    pub fn new(stack: A, mux: M) -> Result<Self, PumpError> {
        Ok(Self {
            stack,
            mux,
            upload: DatagramPump::new(MAX_UDP_PAYLOAD)?,
            download: DatagramPump::new(MAX_UDP_PAYLOAD)?,
        })
    }

    pub fn poll(
        &mut self,
        context: &mut Context<'_>,
    ) -> Poll<Result<(DatagramPumpReport, DatagramPumpReport), PumpError>> {
        let upload = self
            .upload
            .poll(context, &mut self.stack, &mut self.mux, MAX_UDP_PAYLOAD);
        let download = self
            .download
            .poll(context, &mut self.mux, &mut self.stack, MAX_UDP_PAYLOAD);
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
    parse_options(config).map(|_| ())
}

fn parse_options(config: &[u8]) -> Result<Options, String> {
    let text = std::str::from_utf8(config).map_err(|_| "config is not UTF-8".to_owned())?;
    let options: Options = toml::from_str(text).map_err(|error| error.to_string())?;
    if options.pump_buffer_bytes == 0 {
        return Err("pump buffer must be nonzero".into());
    }
    Ok(options)
}

static SESSION_NEXT: AtomicU64 = AtomicU64::new(1);
static FLOW_NEXT: AtomicU64 = AtomicU64::new(1);

struct State {
    pump_buffer_bytes: usize,
    sessions: HashMap<u64, ForeignByteIo>,
    flows: HashMap<u64, DummyFlow<ForeignByteIo, ForeignByteIo>>,
    datagram_flows: HashMap<u64, DummyDatagramFlow<ForeignDatagramIo, ForeignDatagramIo>>,
}

thread_local! {
    static STATES: RefCell<HashMap<u64, State>> = RefCell::new(HashMap::new());
}

fn initialize(
    instance: u64,
    config: &[u8],
    _base: &[u8],
    _host: *const abi::SnolHostApiV1,
) -> Result<(), u32> {
    let options = parse_options(config).map_err(|_| abi::STATUS_INVALID)?;
    STATES.with(|states| {
        states.borrow_mut().insert(
            instance,
            State {
                pump_buffer_bytes: options.pump_buffer_bytes,
                sessions: HashMap::new(),
                flows: HashMap::new(),
                datagram_flows: HashMap::new(),
            },
        );
    });
    Ok(())
}

unsafe extern "C" fn attach_session(
    instance: u64,
    policy_stream: u64,
    policy_stream_io: *const SnolByteIoV1,
    _context: SnolBytes,
    _wake: SnolWakeHandle,
    output: *mut u64,
) -> u32 {
    snolc_sdk::catch_status(|| {
        if !INSTANCES.contains(instance) || policy_stream == 0 || policy_stream_io.is_null() {
            return abi::STATUS_INVALID;
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
    metadata: *const abi::SnolFlowMetadataV1,
    _wake: SnolWakeHandle,
) -> u32 {
    snolc_sdk::catch_status(|| {
        if !INSTANCES.contains(instance) || session == 0 {
            return abi::STATUS_INVALID;
        }
        match unsafe { snolc_sdk::module::flow_metadata(metadata) } {
            Ok(_) => abi::STATUS_OK,
            Err(status) => status,
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
            let flow = match DummyFlow::new(stack, mux, state.pump_buffer_bytes) {
                Ok(flow) => flow,
                Err(_) => return abi::STATUS_RESOURCE,
            };
            let handle = FLOW_NEXT.fetch_add(1, Ordering::Relaxed);
            if handle == 0 {
                return abi::STATUS_RESOURCE;
            }
            state.flows.insert(handle, flow);
            abi::STATUS_OK
        })
    })
}

unsafe extern "C" fn attach_datagram_flow(
    instance: u64,
    session: u64,
    stack_socket: u64,
    stack_socket_io: *const SnolDatagramIoV1,
    mux_stream: u64,
    mux_stream_io: *const SnolDatagramIoV1,
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
            let stack = match unsafe { ForeignDatagramIo::from_raw(stack_socket, stack_socket_io) }
            {
                Ok(stack) => stack,
                Err(_) => return abi::STATUS_INVALID,
            };
            let mux = match unsafe { ForeignDatagramIo::from_raw(mux_stream, mux_stream_io) } {
                Ok(mux) => mux,
                Err(_) => return abi::STATUS_INVALID,
            };
            let flow = match DummyDatagramFlow::new(stack, mux) {
                Ok(flow) => flow,
                Err(_) => return abi::STATUS_RESOURCE,
            };
            let handle = FLOW_NEXT.fetch_add(1, Ordering::Relaxed);
            if handle == 0 {
                return abi::STATUS_RESOURCE;
            }
            state.datagram_flows.insert(handle, flow);
            abi::STATUS_OK
        })
    })
}

fn poll_instance(instance: u64, _wake: SnolWakeHandle) -> u32 {
    STATES.with(|states| {
        let mut states = states.borrow_mut();
        let Some(state) = states.get_mut(&instance) else {
            return abi::STATUS_INVALID;
        };
        let mut context = Context::from_waker(Waker::noop());
        let mut finished = Vec::new();
        for (handle, flow) in &mut state.flows {
            match flow.poll(&mut context, state.pump_buffer_bytes) {
                Poll::Ready(Ok((upload, download))) if upload.finished && download.finished => {
                    finished.push(*handle);
                }
                Poll::Ready(Err(_)) => return abi::STATUS_IO,
                Poll::Ready(Ok(_)) | Poll::Pending => {}
            }
        }
        for handle in finished {
            state.flows.remove(&handle);
        }
        let mut finished = Vec::new();
        for (handle, flow) in &mut state.datagram_flows {
            match flow.poll(&mut context) {
                Poll::Ready(Ok((upload, download))) if upload.finished && download.finished => {
                    finished.push(*handle);
                }
                Poll::Ready(Err(_)) => return abi::STATUS_IO,
                Poll::Ready(Ok(_)) | Poll::Pending => {}
            }
        }
        for handle in finished {
            state.datagram_flows.remove(&handle);
        }
        abi::STATUS_PENDING
    })
}

fn control_instance(_instance: u64, _request: &[u8]) -> Result<Vec<u8>, u32> {
    Err(abi::STATUS_UNSUPPORTED)
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
    attach_datagram_flow: Some(attach_datagram_flow),
    admit_resolved: Some(admit_flow),
};

snolc_sdk::declare_stateful_module! {
    name: "policy-dummy",
    description: "name = \"policy-dummy\"\nfamily = \"policy-dummy\"\nroles = [\"client\", \"server\"]\nusers = false\n",
    class_mask: abi::CLASS_POLICY,
    validate: validate_config,
    initialize: initialize,
    poll: poll_instance,
    control: control_instance,
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
