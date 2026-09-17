#![deny(unsafe_op_in_unsafe_fn)]

mod accounting;
mod admin;
mod config;
mod frame;
mod service;
mod sniff;
mod storage;

pub use accounting::{QuotaAccount, QuotaError, TokenBucket};
pub use admin::{
    AdminDecision, AdminError, AdminSequencer, ByteLimit, ControlRequest, CountLimit, Credential,
    CredentialDigest, CredentialRecord, Expiration, RateLimit, RuleApply, UserId, UserRecord,
    UserSpec, UserStatus,
};
pub use config::Options;
pub use frame::{FrameDecoder, FrameError, encode_frame};
pub use storage::{StorageError, StorageWorker};

use admin::{decode_user_record, encode_user_record};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::TryRecvError;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use snolc_sdk::abi::{
    self, SnolByteIoV1, SnolBytes, SnolDatagramIoV1, SnolPolicyApiV1, SnolWakeHandle,
};
use snolc_sdk::{
    ByteIo, DatagramIo, DatagramPump, DatagramPumpReport, DatagramRecv, ForeignByteIo,
    ForeignDatagramIo, Pump, PumpError, PumpReport,
};
use zeroize::Zeroize;

use service::{ClientRequest, SessionChannel};
use sniff::{Classification, Observed};

const MAX_UDP_PAYLOAD: usize = 65_507;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChannelSecurity {
    role: PolicyRole,
    confidentiality: bool,
    integrity: bool,
    peer_authenticated: bool,
    peer_identity: Option<String>,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum PolicyRole {
    Client,
    Server,
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
    started: Instant,
    global_rate: Option<TokenBucket>,
    user_deficit: HashMap<String, u64>,
    user_cursor: usize,
    options: Options,
    storage: StorageWorker,
    admin: AdminState,
    pending_control: Option<PendingControl>,
    client_credential: Option<Credential>,
    sessions: HashMap<u64, PolicySession>,
    flows: HashMap<u64, PolicyFlow<ForeignByteIo, ForeignByteIo>>,
    datagram_flows: HashMap<u64, PolicyDatagramFlow<ForeignDatagramIo, ForeignDatagramIo>>,
    traffic: HashMap<String, UserTraffic>,
    flow_cursor: HashMap<String, usize>,
}

struct UserTraffic {
    quota: QuotaAccount,
    upload: Option<TokenBucket>,
    download: Option<TokenBucket>,
    combined: Option<TokenBucket>,
    debit: Option<PendingDebit>,
    refund: Option<PendingRefund>,
    failed: bool,
}

struct PendingDebit {
    amount: u64,
    record: UserRecord,
    reply: storage::WriteReply,
}

struct PendingRefund {
    amount: u64,
    record: UserRecord,
    reply: storage::WriteReply,
}

#[derive(Clone, Copy, Default)]
struct RateGrant {
    stack_to_mux: u64,
    mux_to_stack: u64,
    combined: u64,
    global: u64,
}

struct PolicySession {
    channel: SessionChannel<ForeignByteIo>,
    role: PolicyRole,
    auth: AuthState,
    subscribed: bool,
    last_status: Instant,
    credential_digest: Option<String>,
    pending_flows: VecDeque<FlowIdentity>,
}

struct FlowIdentity {
    user_id: String,
    credential_digest: Option<String>,
    sniff: Option<SniffPolicy>,
}

#[derive(Clone)]
struct SniffPolicy {
    entries: Vec<config::RuleEntry>,
    terminal: config::Action,
    unknown: config::UnknownAction,
    max_bytes: usize,
    timeout: Duration,
}

struct TcpSniff {
    policy: SniffPolicy,
    prefix: Vec<u8>,
    deadline: Instant,
    allowed: bool,
}

enum AuthState {
    Waiting,
    Credential {
        digest: String,
        reply: storage::ReadReply,
    },
    User {
        user_id: String,
        reply: storage::ReadReply,
    },
    Authenticated(String),
}

struct AdminState {
    sequencer: AdminSequencer,
    users: HashMap<String, UserRecord>,
    loaded_users: HashSet<String>,
    credentials: HashMap<String, CredentialRecord>,
    loaded_credentials: HashSet<String>,
    rules: HashMap<String, String>,
}

enum PendingControl {
    Write(PendingWrite),
    Read(PendingRead),
}

struct PendingWrite {
    request: Vec<u8>,
    client_id: String,
    receipt: Vec<u8>,
    response: Vec<u8>,
    mutation: AdminMutation,
    reply: storage::WriteReply,
}

struct PendingRead {
    request: Vec<u8>,
    kind: ReadKind,
    reply: storage::ReadReply,
}

enum ReadKind {
    User(String),
    Credential(String),
}

#[derive(Default)]
struct AdminMutation {
    users: Vec<(String, Option<UserRecord>)>,
    credentials: Vec<(String, Option<CredentialRecord>)>,
    rules: Vec<(String, String)>,
    active_rule_profiles: Vec<String>,
    disconnect: Option<u64>,
}

struct PreparedAdmin {
    response: Vec<u8>,
    mutation: AdminMutation,
    changes: Vec<(String, Option<Vec<u8>>)>,
}

struct PolicyFlow<S, M> {
    session: u64,
    user_id: Option<String>,
    credential_digest: Option<String>,
    stack: S,
    mux: M,
    upload: Pump,
    download: Pump,
    sniff: Option<TcpSniff>,
    prefix_offset: usize,
}

struct PolicyDatagramFlow<S, M> {
    session: u64,
    user_id: Option<String>,
    credential_digest: Option<String>,
    stack: S,
    mux: DatagramSniff<M>,
    upload: DatagramPump,
    download: DatagramPump,
}

struct DatagramSniff<M> {
    inner: M,
    policy: Option<SniffPolicy>,
}

impl<M> DatagramSniff<M> {
    fn new(inner: M, policy: Option<SniffPolicy>) -> Self {
        Self { inner, policy }
    }
}

impl<M: DatagramIo> DatagramIo for DatagramSniff<M> {
    fn poll_recv_datagram(
        &mut self,
        context: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<io::Result<DatagramRecv>> {
        match self.inner.poll_recv_datagram(context, output) {
            Poll::Ready(Ok(DatagramRecv::Datagram(length))) if length <= output.len() => {
                if let Some(policy) = &self.policy {
                    let prefix = &output[..length.min(policy.max_bytes)];
                    if !observed_allowed(policy, &sniff::classify_udp(prefix)) {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "observed protocol denied",
                        )));
                    }
                    self.policy = None;
                }
                Poll::Ready(Ok(DatagramRecv::Datagram(length)))
            }
            Poll::Ready(Ok(DatagramRecv::Datagram(_))) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "datagram I/O returned an invalid length",
            ))),
            result => result,
        }
    }

    fn poll_send_datagram(
        &mut self,
        context: &mut Context<'_>,
        datagram: &[u8],
    ) -> Poll<io::Result<()>> {
        self.inner.poll_send_datagram(context, datagram)
    }

    fn close(&mut self) -> io::Result<()> {
        self.inner.close()
    }
}

impl<S: ByteIo, M: ByteIo> PolicyFlow<S, M> {
    fn new(
        stack: S,
        mux: M,
        buffer_bytes: usize,
        session: u64,
        user_id: Option<String>,
        credential_digest: Option<String>,
        sniff: Option<SniffPolicy>,
    ) -> Result<Self, PumpError> {
        Ok(Self {
            session,
            user_id,
            credential_digest,
            stack,
            mux,
            upload: Pump::new(buffer_bytes)?,
            download: Pump::new(buffer_bytes)?,
            sniff: sniff.map(|policy| TcpSniff {
                prefix: Vec::with_capacity(policy.max_bytes),
                deadline: Instant::now() + policy.timeout,
                allowed: false,
                policy,
            }),
            prefix_offset: 0,
        })
    }

    fn poll(
        &mut self,
        context: &mut Context<'_>,
        max_stack_to_mux: usize,
        max_mux_to_stack: usize,
        max_total: usize,
    ) -> Poll<Result<(PumpReport, PumpReport), PumpError>> {
        let prefix = match self.poll_sniff(context, max_mux_to_stack.min(max_total)) {
            Poll::Ready(Ok(report)) => report,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        };
        if self.sniff.is_some() {
            return Poll::Ready(Ok((PumpReport::default(), prefix)));
        }
        let upload = self.upload.poll(
            context,
            &mut self.stack,
            &mut self.mux,
            max_stack_to_mux.min(max_total),
        );
        let upload = match upload {
            Poll::Ready(Ok(report)) => report,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => PumpReport::default(),
        };
        let remaining = max_total
            .saturating_sub(upload.written)
            .saturating_sub(prefix.written);
        let download = self.download.poll(
            context,
            &mut self.mux,
            &mut self.stack,
            max_mux_to_stack.min(remaining),
        );
        let mut download = match download {
            Poll::Ready(Ok(report)) => report,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => PumpReport::default(),
        };
        download.read = download.read.saturating_add(prefix.read);
        download.written = download.written.saturating_add(prefix.written);
        if upload == PumpReport::default() && download == PumpReport::default() {
            Poll::Pending
        } else {
            Poll::Ready(Ok((upload, download)))
        }
    }

    fn poll_sniff(
        &mut self,
        context: &mut Context<'_>,
        max_write: usize,
    ) -> Poll<Result<PumpReport, PumpError>> {
        let Some(sniff) = &mut self.sniff else {
            return Poll::Ready(Ok(PumpReport::default()));
        };
        if !sniff.allowed {
            loop {
                let complete = sniff.prefix.len() >= sniff.policy.max_bytes
                    || Instant::now() >= sniff.deadline;
                match sniff::classify_tcp(&sniff.prefix, complete) {
                    Classification::Complete(observed) => {
                        if !observed_allowed(&sniff.policy, &observed) {
                            return Poll::Ready(Err(PumpError::Io(io::Error::new(
                                io::ErrorKind::PermissionDenied,
                                "observed protocol denied",
                            ))));
                        }
                        sniff.allowed = true;
                        break;
                    }
                    Classification::NeedMore => {}
                }
                let remaining = sniff.policy.max_bytes.saturating_sub(sniff.prefix.len());
                if remaining == 0 {
                    continue;
                }
                let mut buffer = [0; 1024];
                let length = remaining.min(buffer.len());
                match self.mux.poll_read(context, &mut buffer[..length]) {
                    Poll::Ready(Ok(0)) => {
                        let observed = match sniff::classify_tcp(&sniff.prefix, true) {
                            Classification::Complete(observed) => observed,
                            Classification::NeedMore => Observed::Unknown,
                        };
                        if !observed_allowed(&sniff.policy, &observed) {
                            return Poll::Ready(Err(PumpError::Io(io::Error::new(
                                io::ErrorKind::PermissionDenied,
                                "observed protocol denied",
                            ))));
                        }
                        sniff.allowed = true;
                        break;
                    }
                    Poll::Ready(Ok(read)) => sniff.prefix.extend_from_slice(&buffer[..read]),
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(PumpError::Io(error))),
                    Poll::Pending => return Poll::Pending,
                }
            }
        }
        if self.prefix_offset < sniff.prefix.len() {
            if max_write == 0 {
                return Poll::Pending;
            }
            let end = sniff.prefix.len().min(self.prefix_offset + max_write);
            match self
                .stack
                .poll_write(context, &sniff.prefix[self.prefix_offset..end])
            {
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(PumpError::WriteZero)),
                Poll::Ready(Ok(written)) => {
                    self.prefix_offset += written;
                    let report = PumpReport {
                        read: 0,
                        written,
                        finished: false,
                    };
                    if self.prefix_offset == sniff.prefix.len() {
                        self.sniff = None;
                        self.prefix_offset = 0;
                    }
                    return Poll::Ready(Ok(report));
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(PumpError::Io(error))),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.sniff = None;
        self.prefix_offset = 0;
        Poll::Ready(Ok(PumpReport::default()))
    }
}

impl<S: DatagramIo, M: DatagramIo> PolicyDatagramFlow<S, M> {
    fn new(
        stack: S,
        mux: M,
        session: u64,
        user_id: Option<String>,
        credential_digest: Option<String>,
        sniff: Option<SniffPolicy>,
    ) -> Result<Self, PumpError> {
        Ok(Self {
            session,
            user_id,
            credential_digest,
            stack,
            mux: DatagramSniff::new(mux, sniff),
            upload: DatagramPump::new(MAX_UDP_PAYLOAD)?,
            download: DatagramPump::new(MAX_UDP_PAYLOAD)?,
        })
    }

    fn poll(
        &mut self,
        context: &mut Context<'_>,
        max_stack_to_mux: usize,
        max_mux_to_stack: usize,
        max_total: usize,
    ) -> Poll<Result<(DatagramPumpReport, DatagramPumpReport), PumpError>> {
        let upload = self.upload.poll(
            context,
            &mut self.stack,
            &mut self.mux,
            max_stack_to_mux.min(max_total),
        );
        let upload = match upload {
            Poll::Ready(Ok(report)) => report,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => DatagramPumpReport::default(),
        };
        let remaining = max_total.saturating_sub(upload.sent);
        let download = self.download.poll(
            context,
            &mut self.mux,
            &mut self.stack,
            max_mux_to_stack.min(remaining),
        );
        let download = match download {
            Poll::Ready(Ok(report)) => report,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => DatagramPumpReport::default(),
        };
        if upload == DatagramPumpReport::default() && download == DatagramPumpReport::default() {
            Poll::Pending
        } else {
            Poll::Ready(Ok((upload, download)))
        }
    }
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
    let started = Instant::now();
    let global_rate = match &options.global_rate {
        config::GlobalRate::Unlimited => None,
        config::GlobalRate::Limited {
            bytes_per_second,
            burst_bytes,
        } => Some(
            TokenBucket::new(*bytes_per_second, *burst_bytes, 0)
                .map_err(|_| abi::STATUS_INVALID)?,
        ),
    };
    let storage = StorageWorker::open(
        options.storage.path.clone(),
        options.storage.cache_bytes,
        options.storage.max_database_bytes,
        options.storage.queue_capacity,
    )
    .map_err(|_| abi::STATUS_IO)?;
    let mut sequencer =
        AdminSequencer::new(options.max_admin_clients).map_err(|_| abi::STATUS_INVALID)?;
    let receipts = storage
        .scan("client/".into(), options.max_admin_clients)
        .map_err(storage_status)?
        .recv()
        .map_err(|_| abi::STATUS_IO)?
        .map_err(storage_status)?;
    for (key, receipt) in receipts {
        let client_id = key.strip_prefix("client/").ok_or(abi::STATUS_INTERNAL)?;
        sequencer
            .restore(client_id.to_owned(), &receipt)
            .map_err(admin_status)?;
    }
    let client_credential = options
        .client
        .as_ref()
        .map(|client| client.credential.resolve())
        .transpose()
        .map_err(|_| abi::STATUS_INVALID)?
        .map(|mut secret| {
            let credential = Credential::parse_hex(&secret).map_err(admin_status);
            secret.zeroize();
            credential
        })
        .transpose()?;
    STATES.with(|states| {
        states.borrow_mut().insert(
            instance,
            State {
                started,
                global_rate,
                user_deficit: HashMap::new(),
                user_cursor: 0,
                options,
                admin: AdminState {
                    sequencer,
                    users: HashMap::new(),
                    loaded_users: HashSet::new(),
                    credentials: HashMap::new(),
                    loaded_credentials: HashSet::new(),
                    rules: HashMap::new(),
                },
                storage,
                pending_control: None,
                client_credential,
                sessions: HashMap::new(),
                flows: HashMap::new(),
                datagram_flows: HashMap::new(),
                traffic: HashMap::new(),
                flow_cursor: HashMap::new(),
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
        if matches!(context.role, PolicyRole::Client) && !context.peer_authenticated {
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
            let mut channel =
                match SessionChannel::new(stream, state.options.max_control_frame_bytes) {
                    Ok(channel) => channel,
                    Err(_) => return abi::STATUS_RESOURCE,
                };
            if matches!(context.role, PolicyRole::Client) {
                let Some(credential) = state.client_credential.as_ref() else {
                    return abi::STATUS_DENIED;
                };
                let mut credential = credential.hex();
                let mut request = format!("method = \"auth\"\ncredential = \"{credential}\"\n");
                credential.zeroize();
                let queued = channel.queue_secret(&request);
                request.zeroize();
                if queued.is_err() {
                    return abi::STATUS_RESOURCE;
                }
            }
            state.sessions.insert(
                handle,
                PolicySession {
                    channel,
                    role: context.role,
                    auth: AuthState::Waiting,
                    subscribed: false,
                    last_status: Instant::now(),
                    credential_digest: None,
                    pending_flows: VecDeque::new(),
                },
            );
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
        let metadata = match unsafe { snolc_sdk::module::flow_metadata(metadata) } {
            Ok(metadata) => metadata,
            Err(status) => return status,
        };
        STATES.with(|states| {
            let mut states = states.borrow_mut();
            let Some(state) = states.get_mut(&instance) else {
                return abi::STATUS_INVALID;
            };
            let (role, user_id) = match state.sessions.get(&session) {
                Some(PolicySession {
                    role,
                    auth: AuthState::Authenticated(user_id),
                    ..
                }) => (*role, user_id.clone()),
                Some(_) => return abi::STATUS_PENDING,
                None => return abi::STATUS_INVALID,
            };
            if matches!(role, PolicyRole::Client) {
                return abi::STATUS_OK;
            }
            let Some(user) = state.admin.users.get(&user_id) else {
                return abi::STATUS_DENIED;
            };
            if !user_available(user) || flow_limit_reached(state, user) {
                return abi::STATUS_DENIED;
            }
            let sniff = match destination_policy(state, user, &metadata) {
                Ok(sniff) => sniff,
                Err(()) => return abi::STATUS_DENIED,
            };
            let Some(session) = state.sessions.get_mut(&session) else {
                return abi::STATUS_INVALID;
            };
            session.pending_flows.push_back(FlowIdentity {
                user_id,
                credential_digest: session.credential_digest.clone(),
                sniff,
            });
            abi::STATUS_OK
        })
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
            let identity = match state.sessions.get_mut(&session) {
                Some(session) if matches!(session.role, PolicyRole::Server) => {
                    match session.pending_flows.pop_front() {
                        Some(identity) => Some(identity),
                        None => return abi::STATUS_DENIED,
                    }
                }
                Some(_) => None,
                None => return abi::STATUS_INVALID,
            };
            let stack = match unsafe { ForeignByteIo::from_raw(stack_socket, stack_socket_io) } {
                Ok(stack) => stack,
                Err(_) => return abi::STATUS_INVALID,
            };
            let mux = match unsafe { ForeignByteIo::from_raw(mux_stream, mux_stream_io) } {
                Ok(mux) => mux,
                Err(_) => return abi::STATUS_INVALID,
            };
            let flow = match PolicyFlow::new(
                stack,
                mux,
                state.options.sniff_bytes,
                session,
                identity.as_ref().map(|identity| identity.user_id.clone()),
                identity
                    .as_ref()
                    .and_then(|identity| identity.credential_digest.clone()),
                identity.and_then(|identity| identity.sniff),
            ) {
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
            let identity = match state.sessions.get_mut(&session) {
                Some(session) if matches!(session.role, PolicyRole::Server) => {
                    match session.pending_flows.pop_front() {
                        Some(identity) => Some(identity),
                        None => return abi::STATUS_DENIED,
                    }
                }
                Some(_) => None,
                None => return abi::STATUS_INVALID,
            };
            let stack = match unsafe { ForeignDatagramIo::from_raw(stack_socket, stack_socket_io) }
            {
                Ok(stack) => stack,
                Err(_) => return abi::STATUS_INVALID,
            };
            let mux = match unsafe { ForeignDatagramIo::from_raw(mux_stream, mux_stream_io) } {
                Ok(mux) => mux,
                Err(_) => return abi::STATUS_INVALID,
            };
            let flow = match PolicyDatagramFlow::new(
                stack,
                mux,
                session,
                identity.as_ref().map(|identity| identity.user_id.clone()),
                identity
                    .as_ref()
                    .and_then(|identity| identity.credential_digest.clone()),
                identity.and_then(|identity| identity.sniff),
            ) {
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
        let stopped_users = advance_quota(state);
        if !stopped_users.is_empty() {
            state.flows.retain(|_, flow| {
                !flow
                    .user_id
                    .as_ref()
                    .is_some_and(|id| stopped_users.contains(id))
            });
            state.datagram_flows.retain(|_, flow| {
                !flow
                    .user_id
                    .as_ref()
                    .is_some_and(|id| stopped_users.contains(id))
            });
        }
        let mut finished = Vec::new();
        let mut usage = Vec::new();
        let now_nanos = u64::try_from(state.started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        let mut user_flows: HashMap<String, Vec<u64>> = HashMap::new();
        for (handle, flow) in &state.flows {
            if let Some(user_id) = &flow.user_id {
                user_flows.entry(user_id.clone()).or_default().push(*handle);
            }
        }
        for (handle, flow) in &state.datagram_flows {
            if let Some(user_id) = &flow.user_id {
                user_flows.entry(user_id.clone()).or_default().push(*handle);
            }
        }
        let mut scheduled: Vec<_> = user_flows.into_iter().collect();
        scheduled.sort_by(|left, right| left.0.cmp(&right.0));
        if !scheduled.is_empty() {
            let offset = state.user_cursor % scheduled.len();
            scheduled.rotate_left(offset);
            state.user_cursor = state.user_cursor.wrapping_add(1);
        }
        let total_weight = scheduled
            .iter()
            .map(|(user_id, _)| {
                state
                    .admin
                    .users
                    .get(user_id)
                    .map(|user| u64::from(user.spec.weight))
                    .unwrap_or(1)
            })
            .fold(0_u64, u64::saturating_add);
        let global_available = state
            .global_rate
            .as_mut()
            .and_then(|bucket| bucket.available(now_nanos).ok());
        let mut grants = HashMap::new();
        for (user_id, mut flows) in scheduled {
            flows.sort_unstable();
            let cursor = state.flow_cursor.entry(user_id.clone()).or_default();
            let flow = select_flow(cursor, &flows);
            let max_work = if state.datagram_flows.contains_key(&flow) {
                MAX_UDP_PAYLOAD
            } else {
                state.options.sniff_bytes
            };
            let Some(traffic) = state.traffic.get_mut(&user_id) else {
                continue;
            };
            let quota_budget = usize::try_from(traffic.quota.credit_remaining())
                .unwrap_or(usize::MAX)
                .min(max_work);
            let weight = state
                .admin
                .users
                .get(&user_id)
                .map(|user| u64::from(user.spec.weight))
                .unwrap_or(1);
            let quantum = u64::try_from(max_work)
                .unwrap_or(u64::MAX)
                .saturating_mul(weight);
            let deficit = state.user_deficit.entry(user_id.clone()).or_default();
            *deficit = deficit.saturating_add(quantum);
            let weighted = global_available
                .map(|available| weighted_share(available, weight, total_weight))
                .unwrap_or(u64::MAX);
            let budget = quota_budget
                .min(usize::try_from(*deficit).unwrap_or(usize::MAX))
                .min(usize::try_from(weighted).unwrap_or(usize::MAX));
            let global = match &mut state.global_rate {
                Some(bucket) => bucket.take(budget as u64, now_nanos).unwrap_or(0),
                None => budget as u64,
            };
            if let Ok(mut grant) = take_rate_grant(
                traffic,
                usize::try_from(global).unwrap_or(usize::MAX),
                now_nanos,
            ) {
                grant.global = grant.combined;
                if let Some(bucket) = &mut state.global_rate {
                    bucket.refund(global.saturating_sub(grant.global));
                }
                grants.insert(flow, grant);
            }
        }
        for (handle, flow) in &mut state.flows {
            let grant = flow
                .user_id
                .as_ref()
                .and_then(|_| grants.remove(handle))
                .unwrap_or_else(|| {
                    if flow.user_id.is_none() {
                        let work = state.options.sniff_bytes as u64;
                        RateGrant {
                            stack_to_mux: work,
                            mux_to_stack: work,
                            combined: work,
                            global: work,
                        }
                    } else {
                        RateGrant::default()
                    }
                });
            if grant.combined == 0 {
                continue;
            }
            let result = flow.poll(
                &mut context,
                usize::try_from(grant.stack_to_mux).unwrap_or(usize::MAX),
                usize::try_from(grant.mux_to_stack).unwrap_or(usize::MAX),
                usize::try_from(grant.combined).unwrap_or(usize::MAX),
            );
            match result {
                Poll::Ready(Ok((upload, download))) if upload.finished && download.finished => {
                    usage.push((*handle, flow.user_id.clone(), grant, upload, download));
                    finished.push(*handle);
                }
                Poll::Ready(Ok((upload, download))) => {
                    usage.push((*handle, flow.user_id.clone(), grant, upload, download));
                }
                Poll::Ready(Err(_)) => {
                    usage.push((
                        *handle,
                        flow.user_id.clone(),
                        grant,
                        PumpReport::default(),
                        PumpReport::default(),
                    ));
                    finished.push(*handle);
                }
                Poll::Pending => usage.push((
                    *handle,
                    flow.user_id.clone(),
                    grant,
                    PumpReport::default(),
                    PumpReport::default(),
                )),
            }
        }
        for (handle, user_id, grant, upload, download) in usage {
            refund_rate(state, user_id.as_deref(), grant, upload, download);
            if charge_flow(state, user_id.as_deref(), upload, download).is_err() {
                finished.push(handle);
            }
        }
        for handle in finished {
            state.flows.remove(&handle);
        }
        let mut finished = Vec::new();
        let mut usage = Vec::new();
        for (handle, flow) in &mut state.datagram_flows {
            let grant = flow
                .user_id
                .as_ref()
                .and_then(|_| grants.remove(handle))
                .unwrap_or_else(|| {
                    if flow.user_id.is_none() {
                        let work = MAX_UDP_PAYLOAD as u64;
                        RateGrant {
                            stack_to_mux: work,
                            mux_to_stack: work,
                            combined: work,
                            global: work,
                        }
                    } else {
                        RateGrant::default()
                    }
                });
            if grant.combined == 0 {
                continue;
            }
            let result = flow.poll(
                &mut context,
                usize::try_from(grant.stack_to_mux).unwrap_or(usize::MAX),
                usize::try_from(grant.mux_to_stack).unwrap_or(usize::MAX),
                usize::try_from(grant.combined).unwrap_or(usize::MAX),
            );
            match result {
                Poll::Ready(Ok((upload, download))) if upload.finished && download.finished => {
                    usage.push((*handle, flow.user_id.clone(), grant, upload, download));
                    finished.push(*handle);
                }
                Poll::Ready(Ok((upload, download))) => {
                    usage.push((*handle, flow.user_id.clone(), grant, upload, download));
                }
                Poll::Ready(Err(_)) => {
                    usage.push((
                        *handle,
                        flow.user_id.clone(),
                        grant,
                        DatagramPumpReport::default(),
                        DatagramPumpReport::default(),
                    ));
                    finished.push(*handle);
                }
                Poll::Pending => usage.push((
                    *handle,
                    flow.user_id.clone(),
                    grant,
                    DatagramPumpReport::default(),
                    DatagramPumpReport::default(),
                )),
            }
        }
        for (handle, user_id, grant, upload, download) in usage {
            let upload = PumpReport {
                read: upload.received,
                written: upload.sent,
                finished: upload.finished,
            };
            let download = PumpReport {
                read: download.received,
                written: download.sent,
                finished: download.finished,
            };
            refund_rate(state, user_id.as_deref(), grant, upload, download);
            if charge_flow(state, user_id.as_deref(), upload, download).is_err() {
                finished.push(handle);
            }
        }
        for handle in finished {
            state.datagram_flows.remove(&handle);
        }
        let handles: Vec<u64> = state.sessions.keys().copied().collect();
        for handle in handles {
            let Some(mut session) = state.sessions.remove(&handle) else {
                continue;
            };
            if poll_policy_session(state, &mut session, &mut context).is_ok() {
                state.sessions.insert(handle, session);
            }
        }
        let sessions = &state.sessions;
        state
            .flows
            .retain(|_, flow| sessions.contains_key(&flow.session));
        state
            .datagram_flows
            .retain(|_, flow| sessions.contains_key(&flow.session));
        abi::STATUS_PENDING
    })
}

fn select_flow(cursor: &mut usize, flows: &[u64]) -> u64 {
    let flow = flows[*cursor % flows.len()];
    *cursor = cursor.wrapping_add(1);
    flow
}

fn weighted_share(available: u64, weight: u64, total_weight: u64) -> u64 {
    if total_weight == 0 {
        return 0;
    }
    u128::from(available)
        .saturating_mul(u128::from(weight))
        .checked_div(u128::from(total_weight))
        .and_then(|share| u64::try_from(share).ok())
        .unwrap_or(u64::MAX)
}

fn advance_quota(state: &mut State) -> HashSet<String> {
    let active_users: HashSet<String> = state
        .flows
        .values()
        .filter_map(|flow| flow.user_id.clone())
        .chain(
            state
                .datagram_flows
                .values()
                .filter_map(|flow| flow.user_id.clone()),
        )
        .collect();
    let users: HashSet<String> = active_users
        .iter()
        .cloned()
        .chain(state.traffic.keys().cloned())
        .collect();
    let mut stopped = HashSet::new();
    let mut remove_traffic = Vec::new();
    for user_id in users {
        let active = active_users.contains(&user_id);
        if !state.traffic.contains_key(&user_id) {
            if !active {
                continue;
            }
            let Some(user) = state.admin.users.get(&user_id) else {
                stopped.insert(user_id);
                continue;
            };
            let limit = match user.spec.quota {
                ByteLimit::Unlimited => None,
                ByteLimit::Limited { bytes } => Some(bytes),
            };
            let quota = match QuotaAccount::new(
                limit,
                user.durable_charged_bytes,
                state.options.storage.accounting_block_bytes,
            ) {
                Ok(quota) => quota,
                Err(_) => {
                    stopped.insert(user_id);
                    continue;
                }
            };
            let now_nanos = u64::try_from(state.started.elapsed().as_nanos()).unwrap_or(u64::MAX);
            let upload = match rate_bucket(&user.spec.upload_rate, user.spec.burst_bytes, now_nanos)
            {
                Ok(bucket) => bucket,
                Err(_) => {
                    stopped.insert(user_id);
                    continue;
                }
            };
            let download =
                match rate_bucket(&user.spec.download_rate, user.spec.burst_bytes, now_nanos) {
                    Ok(bucket) => bucket,
                    Err(_) => {
                        stopped.insert(user_id);
                        continue;
                    }
                };
            let combined =
                match rate_bucket(&user.spec.combined_rate, user.spec.burst_bytes, now_nanos) {
                    Ok(bucket) => bucket,
                    Err(_) => {
                        stopped.insert(user_id);
                        continue;
                    }
                };
            state.traffic.insert(
                user_id.clone(),
                UserTraffic {
                    quota,
                    upload,
                    download,
                    combined,
                    debit: None,
                    refund: None,
                    failed: false,
                },
            );
        }
        let Some(traffic) = state.traffic.get_mut(&user_id) else {
            stopped.insert(user_id);
            continue;
        };
        if traffic.failed {
            if active {
                stopped.insert(user_id);
            } else {
                remove_traffic.push(user_id);
            }
            continue;
        }
        if let Some(pending) = traffic.debit.take() {
            match pending.reply.try_recv() {
                Ok(Ok(())) => {
                    if traffic.quota.commit_credit(pending.amount).is_err() {
                        traffic.failed = true;
                        stopped.insert(user_id.clone());
                        continue;
                    }
                    state.admin.users.insert(user_id.clone(), pending.record);
                }
                Ok(Err(_)) | Err(TryRecvError::Disconnected) => {
                    traffic.quota.fail_credit();
                    traffic.failed = true;
                    stopped.insert(user_id.clone());
                    continue;
                }
                Err(TryRecvError::Empty) => {
                    traffic.debit = Some(pending);
                    continue;
                }
            }
        }
        if let Some(pending) = traffic.refund.take() {
            match pending.reply.try_recv() {
                Ok(Ok(())) => {
                    if traffic.quota.commit_refund(pending.amount).is_err() {
                        traffic.failed = true;
                        if active {
                            stopped.insert(user_id.clone());
                        }
                        continue;
                    }
                    state.admin.users.insert(user_id.clone(), pending.record);
                    if !active {
                        remove_traffic.push(user_id.clone());
                        continue;
                    }
                }
                Ok(Err(_)) | Err(TryRecvError::Disconnected) => {
                    traffic.quota.fail_refund();
                    traffic.failed = true;
                    if active {
                        stopped.insert(user_id.clone());
                    }
                    continue;
                }
                Err(TryRecvError::Empty) => {
                    traffic.refund = Some(pending);
                    continue;
                }
            }
        }
        if !active {
            let amount = match traffic.quota.request_refund() {
                Ok(amount) => amount,
                Err(_) if traffic.quota.credit_remaining() == 0 => {
                    remove_traffic.push(user_id.clone());
                    continue;
                }
                Err(_) => {
                    traffic.failed = true;
                    continue;
                }
            };
            let Some(mut record) = state.admin.users.get(&user_id).cloned() else {
                traffic.quota.fail_refund();
                traffic.failed = true;
                continue;
            };
            record.durable_charged_bytes = match record.durable_charged_bytes.checked_sub(amount) {
                Some(charged) => charged,
                None => {
                    traffic.quota.fail_refund();
                    traffic.failed = true;
                    continue;
                }
            };
            let value = match encode_user_record(&record) {
                Ok(value) => value,
                Err(_) => {
                    traffic.quota.fail_refund();
                    traffic.failed = true;
                    continue;
                }
            };
            match state.storage.put(format!("user/{user_id}"), value) {
                Ok(reply) => {
                    traffic.refund = Some(PendingRefund {
                        amount,
                        record,
                        reply,
                    });
                }
                Err(_) => {
                    traffic.quota.fail_refund();
                    traffic.failed = true;
                }
            }
            continue;
        }
        if traffic.quota.credit_remaining() != 0 {
            continue;
        }
        let amount = match traffic.quota.request_credit() {
            Ok(amount) => amount,
            Err(QuotaError::Exhausted) => {
                stopped.insert(user_id.clone());
                continue;
            }
            Err(_) => {
                traffic.failed = true;
                stopped.insert(user_id.clone());
                continue;
            }
        };
        let Some(mut record) = state.admin.users.get(&user_id).cloned() else {
            traffic.quota.fail_credit();
            traffic.failed = true;
            stopped.insert(user_id.clone());
            continue;
        };
        record.durable_charged_bytes = match record.durable_charged_bytes.checked_add(amount) {
            Some(charged) => charged,
            None => {
                traffic.quota.fail_credit();
                traffic.failed = true;
                stopped.insert(user_id.clone());
                continue;
            }
        };
        let value = match encode_user_record(&record) {
            Ok(value) => value,
            Err(_) => {
                traffic.quota.fail_credit();
                traffic.failed = true;
                stopped.insert(user_id.clone());
                continue;
            }
        };
        match state.storage.put(format!("user/{user_id}"), value) {
            Ok(reply) => {
                traffic.debit = Some(PendingDebit {
                    amount,
                    record,
                    reply,
                });
            }
            Err(_) => {
                traffic.quota.fail_credit();
                traffic.failed = true;
                stopped.insert(user_id);
            }
        }
    }
    for user_id in remove_traffic {
        state.traffic.remove(&user_id);
        state.flow_cursor.remove(&user_id);
        state.user_deficit.remove(&user_id);
    }
    stopped
}

fn rate_bucket(
    rate: &RateLimit,
    burst_bytes: u64,
    now_nanos: u64,
) -> Result<Option<TokenBucket>, QuotaError> {
    match rate {
        RateLimit::Unlimited => Ok(None),
        RateLimit::Limited { bytes_per_second } => {
            TokenBucket::new(*bytes_per_second, burst_bytes, now_nanos).map(Some)
        }
    }
}

fn take_rate_grant(
    traffic: &mut UserTraffic,
    budget: usize,
    now_nanos: u64,
) -> Result<RateGrant, QuotaError> {
    let budget = u64::try_from(budget).map_err(|_| QuotaError::Overflow)?;
    let combined = match &mut traffic.combined {
        Some(bucket) => bucket.take(budget, now_nanos)?,
        None => budget,
    };
    let user_upload = match &mut traffic.upload {
        Some(bucket) => bucket.take(combined, now_nanos)?,
        None => combined,
    };
    let user_download = match &mut traffic.download {
        Some(bucket) => bucket.take(combined, now_nanos)?,
        None => combined,
    };
    Ok(RateGrant {
        stack_to_mux: user_download,
        mux_to_stack: user_upload,
        combined,
        global: combined,
    })
}

fn refund_rate(
    state: &mut State,
    user_id: Option<&str>,
    grant: RateGrant,
    stack_to_mux: PumpReport,
    mux_to_stack: PumpReport,
) {
    let Some(user_id) = user_id else {
        return;
    };
    let Some(traffic) = state.traffic.get_mut(user_id) else {
        return;
    };
    let stack_written = u64::try_from(stack_to_mux.written).unwrap_or(u64::MAX);
    let mux_written = u64::try_from(mux_to_stack.written).unwrap_or(u64::MAX);
    if let Some(bucket) = &mut traffic.download {
        bucket.refund(grant.stack_to_mux.saturating_sub(stack_written));
    }
    if let Some(bucket) = &mut traffic.upload {
        bucket.refund(grant.mux_to_stack.saturating_sub(mux_written));
    }
    if let Some(bucket) = &mut traffic.combined {
        bucket.refund(
            grant
                .combined
                .saturating_sub(stack_written.saturating_add(mux_written)),
        );
    }
    let written = stack_written.saturating_add(mux_written);
    if let Some(bucket) = &mut state.global_rate {
        bucket.refund(grant.global.saturating_sub(written));
    }
    if let Some(deficit) = state.user_deficit.get_mut(user_id) {
        *deficit = deficit.saturating_sub(written);
    }
}

fn charge_flow(
    state: &mut State,
    user_id: Option<&str>,
    upload: PumpReport,
    download: PumpReport,
) -> Result<(), QuotaError> {
    let Some(user_id) = user_id else {
        return Ok(());
    };
    let accepted = upload
        .written
        .checked_add(download.written)
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(QuotaError::Overflow)?;
    let traffic = state.traffic.get_mut(user_id).ok_or(QuotaError::State)?;
    traffic.quota.charge(accepted)?;
    let user = state
        .admin
        .users
        .get_mut(user_id)
        .ok_or(QuotaError::State)?;
    user.upload_bytes = user
        .upload_bytes
        .checked_add(u64::try_from(download.written).map_err(|_| QuotaError::Overflow)?)
        .ok_or(QuotaError::Overflow)?;
    user.download_bytes = user
        .download_bytes
        .checked_add(u64::try_from(upload.written).map_err(|_| QuotaError::Overflow)?)
        .ok_or(QuotaError::Overflow)?;
    Ok(())
}

fn poll_policy_session(
    state: &mut State,
    session: &mut PolicySession,
    context: &mut Context<'_>,
) -> Result<(), u32> {
    let messages = match session.channel.poll(context) {
        Poll::Ready(Ok(messages)) => messages,
        Poll::Ready(Err(_)) => return Err(abi::STATUS_IO),
        Poll::Pending => Vec::new(),
    };
    for message in messages {
        match session.role {
            PolicyRole::Server => handle_client_request(state, session, &message)?,
            PolicyRole::Client => handle_server_status(session, &message)?,
        }
    }
    advance_authentication(state, session)?;
    if session.subscribed
        && session.last_status.elapsed() >= Duration::from_millis(state.options.status_interval_ms)
        && let AuthState::Authenticated(user_id) = &session.auth
    {
        let status = status_message(state, user_id, "ok")?;
        session
            .channel
            .replace_snapshot(&status)
            .map_err(|_| abi::STATUS_RESOURCE)?;
        session.last_status = Instant::now();
    }
    Ok(())
}

fn handle_client_request(
    state: &mut State,
    session: &mut PolicySession,
    input: &str,
) -> Result<(), u32> {
    match ClientRequest::parse(input).map_err(|_| abi::STATUS_DENIED)? {
        ClientRequest::Auth { credential } => {
            if !matches!(session.auth, AuthState::Waiting) {
                return Err(abi::STATUS_DENIED);
            }
            let credential = Credential::parse_hex(&credential).map_err(admin_status)?;
            let digest = credential.digest_id().hex();
            session.credential_digest = Some(digest.clone());
            let reply = state
                .storage
                .get(format!("credential/{digest}"))
                .map_err(storage_status)?;
            session.auth = AuthState::Credential { digest, reply };
        }
        ClientRequest::Status => {
            let AuthState::Authenticated(user_id) = &session.auth else {
                return Err(abi::STATUS_DENIED);
            };
            let status = status_message(state, user_id, "ok")?;
            session
                .channel
                .queue_response(&status)
                .map_err(|_| abi::STATUS_RESOURCE)?;
        }
        ClientRequest::Subscribe => {
            let AuthState::Authenticated(user_id) = &session.auth else {
                return Err(abi::STATUS_DENIED);
            };
            let status = status_message(state, user_id, "ok")?;
            session
                .channel
                .replace_snapshot(&status)
                .map_err(|_| abi::STATUS_RESOURCE)?;
            session.subscribed = true;
            session.last_status = Instant::now();
        }
        ClientRequest::DisconnectSelf => return Err(abi::STATUS_OK),
    }
    Ok(())
}

fn handle_server_status(session: &mut PolicySession, input: &str) -> Result<(), u32> {
    let value: toml::Value = toml::from_str(input).map_err(|_| abi::STATUS_DENIED)?;
    let status = value
        .get("status")
        .and_then(toml::Value::as_str)
        .ok_or(abi::STATUS_DENIED)?;
    match status {
        "authenticated" | "ok" => {
            let user_id = value
                .get("user_id")
                .and_then(toml::Value::as_str)
                .unwrap_or("remote")
                .to_owned();
            session.auth = AuthState::Authenticated(user_id);
            Ok(())
        }
        _ => Err(abi::STATUS_DENIED),
    }
}

fn advance_authentication(state: &mut State, session: &mut PolicySession) -> Result<(), u32> {
    let auth = std::mem::replace(&mut session.auth, AuthState::Waiting);
    match auth {
        AuthState::Credential { digest, reply } => match reply.try_recv() {
            Ok(Ok(Some(value))) => {
                let credential: CredentialRecord =
                    postcard::from_bytes(&value).map_err(|_| abi::STATUS_IO)?;
                if credential.digest != digest || credential.revoked {
                    queue_denied(session, "credential-revoked")?;
                    return Ok(());
                }
                let user_id = credential.user_id;
                let reply = state
                    .storage
                    .get(format!("user/{user_id}"))
                    .map_err(storage_status)?;
                session.auth = AuthState::User { user_id, reply };
            }
            Ok(Ok(None)) => queue_denied(session, "credential-unknown")?,
            Ok(Err(_)) | Err(TryRecvError::Disconnected) => return Err(abi::STATUS_IO),
            Err(TryRecvError::Empty) => {
                session.auth = AuthState::Credential { digest, reply };
            }
        },
        AuthState::User { user_id, reply } => match reply.try_recv() {
            Ok(Ok(Some(value))) => {
                let user = decode_user_record(&value).map_err(|_| abi::STATUS_IO)?;
                if user.id != user_id || !user_available(&user) {
                    queue_denied(session, "user-disabled")?;
                    return Ok(());
                }
                if session_limit_reached(state, &user) {
                    queue_denied(session, "session-limit")?;
                    return Ok(());
                }
                state.admin.loaded_users.insert(user_id.clone());
                state.admin.users.insert(user_id.clone(), user);
                session.auth = AuthState::Authenticated(user_id.clone());
                let status = status_message(state, &user_id, "authenticated")?;
                session
                    .channel
                    .queue_response(&status)
                    .map_err(|_| abi::STATUS_RESOURCE)?;
            }
            Ok(Ok(None)) => queue_denied(session, "user-unknown")?,
            Ok(Err(_)) | Err(TryRecvError::Disconnected) => return Err(abi::STATUS_IO),
            Err(TryRecvError::Empty) => {
                session.auth = AuthState::User { user_id, reply };
            }
        },
        auth => session.auth = auth,
    }
    Ok(())
}

fn queue_denied(session: &mut PolicySession, reason: &str) -> Result<(), u32> {
    session
        .channel
        .queue_response(&format!("status = \"denied\"\nreason = \"{reason}\"\n"))
        .map_err(|_| abi::STATUS_RESOURCE)
}

fn user_available(user: &UserRecord) -> bool {
    if user.spec.status != UserStatus::Enabled {
        return false;
    }
    if let Expiration::AtUtc { unix_seconds } = user.spec.expiration {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(u64::MAX);
        if now >= unix_seconds {
            return false;
        }
    }
    !matches!(
        user.spec.quota,
        ByteLimit::Limited { bytes } if user.durable_charged_bytes >= bytes
    )
}

fn session_limit_reached(state: &State, user: &UserRecord) -> bool {
    let CountLimit::Limited { count } = user.spec.max_sessions else {
        return false;
    };
    let active = state
        .sessions
        .values()
        .filter(|session| matches!(&session.auth, AuthState::Authenticated(id) if id == &user.id))
        .count();
    active >= count as usize
}

fn flow_limit_reached(state: &State, user: &UserRecord) -> bool {
    let CountLimit::Limited { count } = user.spec.max_flows else {
        return false;
    };
    let active = state
        .flows
        .values()
        .filter(|flow| flow.user_id.as_deref() == Some(user.id.as_str()))
        .count()
        .saturating_add(
            state
                .datagram_flows
                .values()
                .filter(|flow| flow.user_id.as_deref() == Some(user.id.as_str()))
                .count(),
        );
    let pending = state
        .sessions
        .values()
        .map(|session| {
            session
                .pending_flows
                .iter()
                .filter(|identity| identity.user_id == user.id)
                .count()
        })
        .sum::<usize>();
    active.saturating_add(pending) >= count as usize
}

fn destination_policy(
    state: &State,
    user: &UserRecord,
    metadata: &snolc_sdk::module::BorrowedFlowMetadata<'_>,
) -> Result<Option<SniffPolicy>, ()> {
    let dynamic = match state.admin.rules.get(&user.spec.rule_profile) {
        Some(rules) => Some(toml::from_str::<config::Rules>(rules).map_err(|_| ())?),
        None => None,
    };
    let rules = dynamic.as_ref().unwrap_or(&state.options.rules);
    let mut observed = Vec::new();
    for entry in &rules.entries {
        if !matches!(
            entry.direction,
            config::Direction::Upload | config::Direction::Both
        ) || entry
            .user_group
            .as_deref()
            .is_some_and(|group| group != user.spec.group)
            || entry.port.is_some_and(|port| port != metadata.port)
            || !address_rule_matches(entry, metadata)
        {
            continue;
        }
        if rule_requires_observation(entry) {
            observed.push(entry.clone());
        } else if observed.is_empty() {
            return match entry.action {
                config::Action::Allow => Ok(None),
                config::Action::Deny => Err(()),
            };
        } else {
            observed.push(entry.clone());
        }
    }
    if observed.is_empty() {
        return match rules.terminal {
            config::Action::Allow => Ok(None),
            config::Action::Deny => Err(()),
        };
    }
    Ok(Some(SniffPolicy {
        entries: observed,
        terminal: rules.terminal,
        unknown: state.options.on_unknown_protocol,
        max_bytes: state.options.sniff_bytes,
        timeout: Duration::from_millis(state.options.sniff_timeout_ms),
    }))
}

fn rule_requires_observation(entry: &config::RuleEntry) -> bool {
    entry.tls_sni.is_some()
        || entry.http_host.is_some()
        || entry.protocol != config::ObservedProtocol::Any
}

fn observed_allowed(policy: &SniffPolicy, observed: &Observed) -> bool {
    for entry in &policy.entries {
        if matches!(observed, Observed::Unknown)
            && entry.protocol != config::ObservedProtocol::Unknown
        {
            return entry.unavailable == config::Action::Allow;
        }
        if !observed_protocol_matches(entry.protocol, observed) {
            continue;
        }
        if let Some(expected) = &entry.tls_sni {
            match observed {
                Observed::Tls { sni: Some(sni) } if sni.eq_ignore_ascii_case(expected) => {}
                Observed::Tls { sni: Some(_) } => continue,
                _ => return entry.unavailable == config::Action::Allow,
            }
        }
        if let Some(expected) = &entry.http_host {
            match observed {
                Observed::Http { host: Some(host) } if host.eq_ignore_ascii_case(expected) => {}
                Observed::Http { host: Some(_) } => continue,
                _ => return entry.unavailable == config::Action::Allow,
            }
        }
        return entry.action == config::Action::Allow;
    }
    if matches!(observed, Observed::Unknown) {
        return matches!(policy.unknown, config::UnknownAction::Allow);
    }
    policy.terminal == config::Action::Allow
}

fn observed_protocol_matches(protocol: config::ObservedProtocol, observed: &Observed) -> bool {
    matches!(
        (protocol, observed),
        (config::ObservedProtocol::Any, _)
            | (config::ObservedProtocol::Tls, Observed::Tls { .. })
            | (config::ObservedProtocol::Http, Observed::Http { .. })
            | (config::ObservedProtocol::Ssh, Observed::Ssh)
            | (config::ObservedProtocol::Quic, Observed::Quic)
            | (config::ObservedProtocol::Unknown, Observed::Unknown)
    )
}

fn address_rule_matches(
    entry: &config::RuleEntry,
    metadata: &snolc_sdk::module::BorrowedFlowMetadata<'_>,
) -> bool {
    if let Some(cidr) = &entry.cidr {
        let Some(address) = metadata_ip(metadata) else {
            return false;
        };
        if !cidr_matches(cidr, address) {
            return false;
        }
    }
    let domain = if metadata.address_type == abi::ADDRESS_DOMAIN {
        std::str::from_utf8(metadata.address).ok()
    } else {
        None
    };
    if entry
        .domain_exact
        .as_deref()
        .is_some_and(|expected| domain != Some(expected))
    {
        return false;
    }
    if let Some(suffix) = &entry.domain_suffix
        && !domain.is_some_and(|domain| {
            domain == suffix
                || domain
                    .strip_suffix(suffix)
                    .is_some_and(|prefix| prefix.ends_with('.'))
        })
    {
        return false;
    }
    true
}

fn metadata_ip(metadata: &snolc_sdk::module::BorrowedFlowMetadata<'_>) -> Option<std::net::IpAddr> {
    match metadata.address_type {
        abi::ADDRESS_IPV4 => metadata
            .address
            .try_into()
            .map(|bytes: [u8; 4]| bytes)
            .ok()
            .map(std::net::Ipv4Addr::from)
            .map(Into::into),
        abi::ADDRESS_IPV6 => metadata
            .address
            .try_into()
            .map(|bytes: [u8; 16]| bytes)
            .ok()
            .map(std::net::Ipv6Addr::from)
            .map(Into::into),
        _ => None,
    }
}

fn cidr_matches(cidr: &str, address: std::net::IpAddr) -> bool {
    let Some((network, prefix)) = cidr.split_once('/') else {
        return false;
    };
    let (Ok(network), Ok(prefix)) = (network.parse::<std::net::IpAddr>(), prefix.parse::<u8>())
    else {
        return false;
    };
    match (network, address) {
        (std::net::IpAddr::V4(network), std::net::IpAddr::V4(address)) if prefix <= 32 => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            u32::from(network) & mask == u32::from(address) & mask
        }
        (std::net::IpAddr::V6(network), std::net::IpAddr::V6(address)) if prefix <= 128 => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            u128::from(network) & mask == u128::from(address) & mask
        }
        _ => false,
    }
}

fn status_message(state: &State, user_id: &str, status: &'static str) -> Result<String, u32> {
    let user = state.admin.users.get(user_id).ok_or(abi::STATUS_INVALID)?;
    toml::to_string(&PolicyStatus {
        status,
        server_id: &state.options.server_id,
        user_id,
        used_bytes: user.durable_charged_bytes,
        limit_bytes: match user.spec.quota {
            ByteLimit::Unlimited => None,
            ByteLimit::Limited { bytes } => Some(bytes),
        },
        upload_bytes_per_second: rate_value(&user.spec.upload_rate),
        download_bytes_per_second: rate_value(&user.spec.download_rate),
        expires_at: match user.spec.expiration {
            Expiration::Unlimited => None,
            Expiration::AtUtc { unix_seconds } => Some(unix_seconds),
        },
        revision: user.revision,
        reason: "ok",
    })
    .map_err(|_| abi::STATUS_INTERNAL)
}

fn rate_value(rate: &RateLimit) -> Option<u64> {
    match rate {
        RateLimit::Unlimited => None,
        RateLimit::Limited { bytes_per_second } => Some(*bytes_per_second),
    }
}

#[derive(Serialize)]
struct PolicyStatus<'a> {
    status: &'static str,
    server_id: &'a str,
    user_id: &'a str,
    used_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    limit_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    upload_bytes_per_second: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    download_bytes_per_second: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<u64>,
    revision: u64,
    reason: &'static str,
}

fn control_instance(instance: u64, request: &[u8]) -> Result<Vec<u8>, u32> {
    STATES.with(|states| {
        let mut states = states.borrow_mut();
        let state = states.get_mut(&instance).ok_or(abi::STATUS_INVALID)?;
        if let Some(pending) = state.pending_control.take() {
            let pending_request = match &pending {
                PendingControl::Write(pending) => &pending.request,
                PendingControl::Read(pending) => &pending.request,
            };
            if pending_request != request {
                state.pending_control = Some(pending);
                return Err(abi::STATUS_PENDING);
            }
            match pending {
                PendingControl::Write(pending) => match pending.reply.try_recv() {
                    Ok(Ok(())) => {
                        state
                            .admin
                            .sequencer
                            .apply_commit(pending.client_id, &pending.receipt)
                            .map_err(|_| abi::STATUS_INTERNAL)?;
                        apply_admin_mutation(state, pending.mutation);
                        return Ok(pending.response);
                    }
                    Ok(Err(_)) | Err(TryRecvError::Disconnected) => {
                        return Err(abi::STATUS_IO);
                    }
                    Err(TryRecvError::Empty) => {
                        state.pending_control = Some(PendingControl::Write(pending));
                        return Err(abi::STATUS_PENDING);
                    }
                },
                PendingControl::Read(pending) => match pending.reply.try_recv() {
                    Ok(Ok(value)) => finish_admin_read(state, pending.kind, value)?,
                    Ok(Err(_)) | Err(TryRecvError::Disconnected) => {
                        return Err(abi::STATUS_IO);
                    }
                    Err(TryRecvError::Empty) => {
                        state.pending_control = Some(PendingControl::Read(pending));
                        return Err(abi::STATUS_PENDING);
                    }
                },
            }
        }

        if request.len() > state.options.max_control_frame_bytes {
            return Err(abi::STATUS_RESOURCE);
        }
        let parsed = ControlRequest::parse(request).map_err(|_| abi::STATUS_INVALID)?;
        if let Some((key, kind)) = required_admin_read(state, &parsed) {
            let reply = state.storage.get(key).map_err(storage_status)?;
            state.pending_control = Some(PendingControl::Read(PendingRead {
                request: request.to_vec(),
                kind,
                reply,
            }));
            return Err(abi::STATUS_PENDING);
        }
        if parsed.sequence().is_none() {
            return read_admin_state(state, parsed);
        }
        let (client_id, seq) = parsed.sequence().ok_or(abi::STATUS_INVALID)?;
        let client_id = client_id.to_owned();
        let request_hash = match state
            .admin
            .sequencer
            .check(&client_id, seq, request)
            .map_err(admin_status)?
        {
            AdminDecision::Replay(response) => return Ok(response),
            AdminDecision::Execute { request_hash } => request_hash,
        };
        let PreparedAdmin {
            response,
            mutation,
            mut changes,
        } = prepare_admin_mutation(state, parsed)?;
        let receipt = state
            .admin
            .sequencer
            .prepare_commit(&client_id, seq, request_hash, response.clone())
            .map_err(admin_status)?;
        changes.push((format!("client/{client_id}"), Some(receipt.clone())));
        let reply = state.storage.apply(changes).map_err(storage_status)?;
        state.pending_control = Some(PendingControl::Write(PendingWrite {
            request: request.to_vec(),
            client_id,
            receipt,
            response,
            mutation,
            reply,
        }));
        Err(abi::STATUS_PENDING)
    })
}

fn required_admin_read(state: &State, request: &ControlRequest) -> Option<(String, ReadKind)> {
    let user_id = match request {
        ControlRequest::UserUpdate { user_id, .. }
        | ControlRequest::UserDisable { user_id, .. }
        | ControlRequest::UserDelete { user_id, .. }
        | ControlRequest::CredentialAdd { user_id, .. }
        | ControlRequest::QuotaAdd { user_id, .. }
        | ControlRequest::QuotaNewPeriod { user_id, .. }
        | ControlRequest::UsageGet { user_id } => Some(user_id),
        ControlRequest::SessionsList {
            user_id: Some(user_id),
        } => Some(user_id),
        _ => None,
    };
    if let Some(user_id) = user_id
        && !state.admin.loaded_users.contains(user_id)
    {
        return Some((format!("user/{user_id}"), ReadKind::User(user_id.clone())));
    }
    let digest = match request {
        ControlRequest::CredentialAdd {
            credential_sha256, ..
        }
        | ControlRequest::CredentialRevoke {
            credential_sha256, ..
        } => Some(credential_sha256),
        _ => None,
    };
    if let Some(digest) = digest
        && !state.admin.loaded_credentials.contains(digest)
    {
        return Some((
            format!("credential/{digest}"),
            ReadKind::Credential(digest.clone()),
        ));
    }
    None
}

fn finish_admin_read(state: &mut State, kind: ReadKind, value: Option<Vec<u8>>) -> Result<(), u32> {
    match kind {
        ReadKind::User(id) => {
            state.admin.loaded_users.insert(id.clone());
            if let Some(value) = value {
                let user = decode_user_record(&value).map_err(|_| abi::STATUS_IO)?;
                if user.id != id {
                    return Err(abi::STATUS_IO);
                }
                if state.admin.users.len() >= state.options.max_cached_users
                    && let Some(evicted) = state.admin.users.keys().next().cloned()
                {
                    state.admin.users.remove(&evicted);
                    state.admin.loaded_users.remove(&evicted);
                }
                state.admin.users.insert(id, user);
            }
        }
        ReadKind::Credential(digest) => {
            state.admin.loaded_credentials.insert(digest.clone());
            if let Some(value) = value {
                let credential: CredentialRecord =
                    postcard::from_bytes(&value).map_err(|_| abi::STATUS_IO)?;
                if credential.digest != digest {
                    return Err(abi::STATUS_IO);
                }
                state.admin.credentials.insert(digest, credential);
            }
        }
    }
    Ok(())
}

fn read_admin_state(state: &State, request: ControlRequest) -> Result<Vec<u8>, u32> {
    match request {
        ControlRequest::UsageGet { user_id } => {
            let user = state.admin.users.get(&user_id).ok_or(abi::STATUS_INVALID)?;
            encode_response(&UsageResponse {
                status: "ok",
                user_id: &user.id,
                revision: user.revision,
                used_bytes: user.durable_charged_bytes,
                limit_bytes: match user.spec.quota {
                    ByteLimit::Unlimited => None,
                    ByteLimit::Limited { bytes } => Some(bytes),
                },
                upload_bytes: user.upload_bytes,
                download_bytes: user.download_bytes,
            })
        }
        ControlRequest::SessionsList { user_id } => {
            let sessions = state
                .sessions
                .iter()
                .filter_map(|(handle, session)| match &session.auth {
                    AuthState::Authenticated(authenticated)
                        if user_id
                            .as_ref()
                            .is_none_or(|requested| requested == authenticated) =>
                    {
                        Some(*handle)
                    }
                    _ => None,
                })
                .collect();
            encode_response(&SessionsResponse {
                status: "ok",
                sessions,
            })
        }
        _ => Err(abi::STATUS_INVALID),
    }
}

fn prepare_admin_mutation(state: &State, request: ControlRequest) -> Result<PreparedAdmin, u32> {
    let mut mutation = AdminMutation::default();
    let mut changes = Vec::new();
    let (response, revision) = match request {
        ControlRequest::UserCreate { user, .. } => {
            let id = UserId::generate().map_err(admin_status)?.hex();
            let record = UserRecord {
                id: id.clone(),
                spec: user,
                revision: 1,
                durable_charged_bytes: 0,
                upload_bytes: 0,
                download_bytes: 0,
                max_observed_utc: 0,
            };
            put_user(&mut mutation, &mut changes, record)?;
            (Some(id), 1)
        }
        ControlRequest::UserUpdate {
            user_id,
            expected_revision,
            user,
            ..
        } => {
            let mut record = checked_user(state, &user_id, expected_revision)?.clone();
            record.spec = user;
            record.revision = next_revision(record.revision)?;
            let revision = record.revision;
            put_user(&mut mutation, &mut changes, record)?;
            (Some(user_id), revision)
        }
        ControlRequest::UserDisable {
            user_id,
            expected_revision,
            ..
        } => {
            let mut record = checked_user(state, &user_id, expected_revision)?.clone();
            record.spec.status = UserStatus::Disabled;
            record.revision = next_revision(record.revision)?;
            let revision = record.revision;
            put_user(&mut mutation, &mut changes, record)?;
            (Some(user_id), revision)
        }
        ControlRequest::UserDelete {
            user_id,
            expected_revision,
            ..
        } => {
            let record = checked_user(state, &user_id, expected_revision)?;
            let revision = next_revision(record.revision)?;
            mutation.users.push((user_id.clone(), None));
            changes.push((format!("user/{user_id}"), None));
            for (digest, credential) in &state.admin.credentials {
                if credential.user_id == user_id {
                    mutation.credentials.push((digest.clone(), None));
                    changes.push((format!("credential/{digest}"), None));
                }
            }
            (Some(user_id), revision)
        }
        ControlRequest::CredentialAdd {
            user_id,
            credential_sha256,
            ..
        } => {
            let user = state.admin.users.get(&user_id).ok_or(abi::STATUS_INVALID)?;
            let revision = next_revision(user.revision)?;
            if let Some(existing) = state.admin.credentials.get(&credential_sha256) {
                if existing.user_id != user_id || existing.revoked {
                    return Err(abi::STATUS_DENIED);
                }
            } else {
                let record = CredentialRecord {
                    digest: credential_sha256.clone(),
                    user_id: user_id.clone(),
                    revoked: false,
                    revision,
                };
                changes.push((
                    format!("credential/{credential_sha256}"),
                    Some(postcard::to_allocvec(&record).map_err(|_| abi::STATUS_INTERNAL)?),
                ));
                mutation.credentials.push((credential_sha256, Some(record)));
            }
            (Some(user_id), revision)
        }
        ControlRequest::CredentialRevoke {
            credential_sha256, ..
        } => {
            let mut record = state
                .admin
                .credentials
                .get(&credential_sha256)
                .ok_or(abi::STATUS_INVALID)?
                .clone();
            record.revoked = true;
            record.revision = next_revision(record.revision)?;
            let revision = record.revision;
            let user_id = record.user_id.clone();
            changes.push((
                format!("credential/{credential_sha256}"),
                Some(postcard::to_allocvec(&record).map_err(|_| abi::STATUS_INTERNAL)?),
            ));
            mutation.credentials.push((credential_sha256, Some(record)));
            (Some(user_id), revision)
        }
        ControlRequest::QuotaAdd { user_id, bytes, .. } => {
            let mut record = state
                .admin
                .users
                .get(&user_id)
                .ok_or(abi::STATUS_INVALID)?
                .clone();
            let ByteLimit::Limited { bytes: limit } = &mut record.spec.quota else {
                return Err(abi::STATUS_INVALID);
            };
            *limit = limit.checked_add(bytes).ok_or(abi::STATUS_RESOURCE)?;
            record.revision = next_revision(record.revision)?;
            let revision = record.revision;
            put_user(&mut mutation, &mut changes, record)?;
            (Some(user_id), revision)
        }
        ControlRequest::QuotaNewPeriod { user_id, quota, .. } => {
            let mut record = state
                .admin
                .users
                .get(&user_id)
                .ok_or(abi::STATUS_INVALID)?
                .clone();
            record.spec.quota = quota;
            record.durable_charged_bytes = 0;
            record.upload_bytes = 0;
            record.download_bytes = 0;
            record.revision = next_revision(record.revision)?;
            let revision = record.revision;
            put_user(&mut mutation, &mut changes, record)?;
            (Some(user_id), revision)
        }
        ControlRequest::SessionsDisconnect { session_id, .. } => {
            if !state.sessions.contains_key(&session_id) {
                return Err(abi::STATUS_INVALID);
            }
            mutation.disconnect = Some(session_id);
            (None, 0)
        }
        ControlRequest::RulesReplace {
            profile,
            apply,
            rules_toml,
            ..
        } => {
            toml::from_str::<config::Rules>(&rules_toml)
                .map_err(|_| abi::STATUS_INVALID)?
                .validate()
                .map_err(|_| abi::STATUS_INVALID)?;
            changes.push((
                format!("meta/rules/{profile}"),
                Some(rules_toml.as_bytes().to_vec()),
            ));
            if apply == RuleApply::Active {
                mutation.active_rule_profiles.push(profile.clone());
            }
            mutation.rules.push((profile, rules_toml));
            (None, 0)
        }
        ControlRequest::UsageGet { .. } | ControlRequest::SessionsList { .. } => {
            return Err(abi::STATUS_INVALID);
        }
    };
    let response = encode_response(&MutationResponse {
        status: "ok",
        revision,
        user_id: response.as_deref(),
    })?;
    Ok(PreparedAdmin {
        response,
        mutation,
        changes,
    })
}

fn checked_user<'a>(
    state: &'a State,
    user_id: &str,
    expected_revision: u64,
) -> Result<&'a UserRecord, u32> {
    let user = state.admin.users.get(user_id).ok_or(abi::STATUS_INVALID)?;
    if user.revision != expected_revision {
        return Err(abi::STATUS_DENIED);
    }
    Ok(user)
}

fn put_user(
    mutation: &mut AdminMutation,
    changes: &mut Vec<(String, Option<Vec<u8>>)>,
    user: UserRecord,
) -> Result<(), u32> {
    changes.push((
        format!("user/{}", user.id),
        Some(encode_user_record(&user).map_err(admin_status)?),
    ));
    mutation.users.push((user.id.clone(), Some(user)));
    Ok(())
}

fn apply_admin_mutation(state: &mut State, mutation: AdminMutation) {
    let active_rule_profiles: HashSet<String> = mutation.active_rule_profiles.into_iter().collect();
    let stopped_users: HashSet<String> = mutation
        .users
        .iter()
        .filter_map(|(id, user)| match user {
            Some(user) if user_available(user) => None,
            _ => Some(id.clone()),
        })
        .collect();
    let revoked_credentials: HashSet<String> = mutation
        .credentials
        .iter()
        .filter_map(|(digest, credential)| match credential {
            Some(credential) if !credential.revoked => None,
            _ => Some(digest.clone()),
        })
        .collect();
    for (id, user) in mutation.users {
        match user {
            Some(user) => {
                if !state.admin.users.contains_key(&id)
                    && state.admin.users.len() >= state.options.max_cached_users
                    && let Some(evicted) = state.admin.users.keys().next().cloned()
                {
                    state.admin.users.remove(&evicted);
                    state.admin.loaded_users.remove(&evicted);
                }
                state.admin.loaded_users.insert(id.clone());
                state.admin.users.insert(id, user);
            }
            None => {
                state.admin.users.remove(&id);
                state.admin.loaded_users.insert(id);
            }
        }
    }
    for (digest, credential) in mutation.credentials {
        match credential {
            Some(credential) => {
                state.admin.loaded_credentials.insert(digest.clone());
                state.admin.credentials.insert(digest, credential);
            }
            None => {
                state.admin.credentials.remove(&digest);
                state.admin.loaded_credentials.insert(digest);
            }
        }
    }
    for (profile, rules) in mutation.rules {
        state.admin.rules.insert(profile, rules);
    }
    if !active_rule_profiles.is_empty() {
        let affected_users: HashSet<String> = state
            .admin
            .users
            .values()
            .filter(|user| active_rule_profiles.contains(&user.spec.rule_profile))
            .map(|user| user.id.clone())
            .collect();
        state.flows.retain(|_, flow| {
            !flow
                .user_id
                .as_ref()
                .is_some_and(|id| affected_users.contains(id))
        });
        state.datagram_flows.retain(|_, flow| {
            !flow
                .user_id
                .as_ref()
                .is_some_and(|id| affected_users.contains(id))
        });
    }
    if let Some(session) = mutation.disconnect {
        state.sessions.remove(&session);
    }
    if !stopped_users.is_empty() {
        state.traffic.retain(|id, _| !stopped_users.contains(id));
        state
            .flow_cursor
            .retain(|id, _| !stopped_users.contains(id));
        state
            .user_deficit
            .retain(|id, _| !stopped_users.contains(id));
        state.flows.retain(|_, flow| {
            !flow
                .user_id
                .as_ref()
                .is_some_and(|id| stopped_users.contains(id))
        });
        state.datagram_flows.retain(|_, flow| {
            !flow
                .user_id
                .as_ref()
                .is_some_and(|id| stopped_users.contains(id))
        });
        state.sessions.retain(|_, session| {
            !matches!(&session.auth, AuthState::Authenticated(id) if stopped_users.contains(id))
        });
    }
    if !revoked_credentials.is_empty() {
        state.flows.retain(|_, flow| {
            !flow
                .credential_digest
                .as_ref()
                .is_some_and(|digest| revoked_credentials.contains(digest))
        });
        state.datagram_flows.retain(|_, flow| {
            !flow
                .credential_digest
                .as_ref()
                .is_some_and(|digest| revoked_credentials.contains(digest))
        });
        state.sessions.retain(|_, session| {
            !session
                .credential_digest
                .as_ref()
                .is_some_and(|digest| revoked_credentials.contains(digest))
        });
    }
}

fn next_revision(revision: u64) -> Result<u64, u32> {
    revision.checked_add(1).ok_or(abi::STATUS_RESOURCE)
}

fn admin_status(error: AdminError) -> u32 {
    match error {
        AdminError::ClientLimit => abi::STATUS_RESOURCE,
        AdminError::Invalid | AdminError::Sequence | AdminError::State => abi::STATUS_DENIED,
        AdminError::Random | AdminError::Encode => abi::STATUS_INTERNAL,
    }
}

fn storage_status(error: StorageError) -> u32 {
    match error {
        StorageError::QueueFull | StorageError::Limit => abi::STATUS_RESOURCE,
        StorageError::Invalid => abi::STATUS_INVALID,
        StorageError::Stopped
        | StorageError::Permissions
        | StorageError::Io(_)
        | StorageError::Database(_) => abi::STATUS_IO,
    }
}

fn encode_response(response: &impl Serialize) -> Result<Vec<u8>, u32> {
    toml::to_string(response)
        .map(String::into_bytes)
        .map_err(|_| abi::STATUS_INTERNAL)
}

#[derive(Serialize)]
struct MutationResponse<'a> {
    status: &'static str,
    revision: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_id: Option<&'a str>,
}

#[derive(Serialize)]
struct UsageResponse<'a> {
    status: &'static str,
    user_id: &'a str,
    revision: u64,
    used_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    limit_bytes: Option<u64>,
    upload_bytes: u64,
    download_bytes: u64,
}

#[derive(Serialize)]
struct SessionsResponse {
    status: &'static str,
    sessions: Vec<u64>,
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
};

snolc_sdk::declare_stateful_module! {
    name: "policy-local",
    description: "name = \"policy-local\"\nfamily = \"policy-local\"\nroles = [\"client\", \"server\"]\ncredential_transport = \"protected\"\n",
    class_mask: abi::CLASS_POLICY,
    validate: validate_module,
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
mod module_tests {
    use std::collections::VecDeque;
    use std::fs;
    use std::io;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use super::*;

    #[derive(Default)]
    struct MemoryIo {
        input: VecDeque<u8>,
        output: Vec<u8>,
        shutdown: bool,
    }

    impl ByteIo for MemoryIo {
        fn poll_read(
            &mut self,
            _context: &mut Context<'_>,
            output: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            let count = output.len().min(self.input.len());
            for byte in &mut output[..count] {
                *byte = self.input.pop_front().unwrap();
            }
            Poll::Ready(Ok(count))
        }

        fn poll_write(
            &mut self,
            _context: &mut Context<'_>,
            input: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.output.extend_from_slice(input);
            Poll::Ready(Ok(input.len()))
        }

        fn poll_flush(&mut self, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown_write(&mut self, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.shutdown = true;
            Poll::Ready(Ok(()))
        }

        fn close(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct MemoryDatagram {
        input: VecDeque<Vec<u8>>,
    }

    impl DatagramIo for MemoryDatagram {
        fn poll_recv_datagram(
            &mut self,
            _context: &mut Context<'_>,
            output: &mut [u8],
        ) -> Poll<io::Result<DatagramRecv>> {
            let Some(datagram) = self.input.front() else {
                return Poll::Pending;
            };
            if output.len() < datagram.len() {
                return Poll::Ready(Ok(DatagramRecv::BufferTooSmall(datagram.len())));
            }
            let datagram = self.input.pop_front().expect("front checked");
            output[..datagram.len()].copy_from_slice(&datagram);
            Poll::Ready(Ok(DatagramRecv::Datagram(datagram.len())))
        }

        fn poll_send_datagram(
            &mut self,
            _context: &mut Context<'_>,
            _datagram: &[u8],
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn close(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn sniff_policy(rule: &str) -> SniffPolicy {
        SniffPolicy {
            entries: vec![toml::from_str(rule).unwrap()],
            terminal: config::Action::Allow,
            unknown: config::UnknownAction::Allow,
            max_bytes: 16_384,
            timeout: Duration::from_secs(2),
        }
    }

    #[test]
    fn rejects_unprotected_session_context() {
        let context: ChannelSecurity = toml::from_str(
            "role = \"client\"\nconfidentiality = false\nintegrity = true\npeer_authenticated = true\npeer_identity = \"server\"\n",
        )
        .unwrap();
        assert!(!context.confidentiality);
    }

    #[test]
    fn policy_flow_owns_both_transfer_directions() {
        let stack = MemoryIo {
            input: b"upload".iter().copied().collect(),
            ..MemoryIo::default()
        };
        let mux = MemoryIo {
            input: b"download".iter().copied().collect(),
            ..MemoryIo::default()
        };
        let mut flow = PolicyFlow::new(stack, mux, 16, 1, None, None, None).unwrap();
        let mut context = Context::from_waker(Waker::noop());
        while !flow.upload.is_finished() || !flow.download.is_finished() {
            let _ = flow.poll(&mut context, 16, 16, 16);
        }
        assert_eq!(flow.mux.output, b"upload");
        assert_eq!(flow.stack.output, b"download");
        assert!(flow.mux.shutdown);
        assert!(flow.stack.shutdown);
    }

    #[test]
    fn runtime_rate_grant_limits_pump_writes() {
        let mut quota = QuotaAccount::new(None, 0, 100).unwrap();
        let credit = quota.request_credit().unwrap();
        quota.commit_credit(credit).unwrap();
        let mut traffic = UserTraffic {
            quota,
            upload: Some(TokenBucket::new(10, 10, 0).unwrap()),
            download: Some(TokenBucket::new(10, 10, 0).unwrap()),
            combined: Some(TokenBucket::new(15, 15, 0).unwrap()),
            debit: None,
            refund: None,
            failed: false,
        };
        let stack = MemoryIo {
            input: vec![b'x'; 100].into(),
            ..MemoryIo::default()
        };
        let mux = MemoryIo::default();
        let mut flow = PolicyFlow::new(
            stack,
            mux,
            100,
            1,
            Some("user".into()),
            Some("key".into()),
            None,
        )
        .unwrap();
        let grant = take_rate_grant(&mut traffic, 100, 0).unwrap();
        let mut context = Context::from_waker(Waker::noop());
        let Poll::Ready(Ok((stack_to_mux, mux_to_stack))) = flow.poll(
            &mut context,
            grant.stack_to_mux as usize,
            grant.mux_to_stack as usize,
            grant.combined as usize,
        ) else {
            panic!("pump did not make progress");
        };
        assert_eq!(stack_to_mux.written, 10);
        assert_eq!(mux_to_stack.written, 0);
        traffic
            .combined
            .as_mut()
            .unwrap()
            .refund(grant.combined - 10);
        traffic.upload.as_mut().unwrap().refund(grant.mux_to_stack);
        assert_eq!(
            take_rate_grant(&mut traffic, 100, 0).unwrap().stack_to_mux,
            0
        );
        assert_eq!(
            take_rate_grant(&mut traffic, 100, 1_000_000_000)
                .unwrap()
                .stack_to_mux,
            10
        );
    }

    #[test]
    fn tcp_sniff_denies_http_host_before_forwarding_prefix() {
        let request = b"GET / HTTP/1.1\r\nHost: denied.example\r\n\r\n";
        let stack = MemoryIo::default();
        let mux = MemoryIo {
            input: request.iter().copied().collect(),
            ..MemoryIo::default()
        };
        let policy = sniff_policy(
            "action = \"deny\"\ndirection = \"upload\"\nprotocol = \"http\"\nunavailable = \"deny\"\nhttp_host = \"denied.example\"\n",
        );
        let mut flow = PolicyFlow::new(stack, mux, 16_384, 1, None, None, Some(policy)).unwrap();
        let mut context = Context::from_waker(Waker::noop());
        assert!(matches!(
            flow.poll(&mut context, 16_384, 16_384, 16_384),
            Poll::Ready(Err(PumpError::Io(error)))
                if error.kind() == io::ErrorKind::PermissionDenied
        ));
        assert!(flow.stack.output.is_empty());
    }

    #[test]
    fn tcp_sniff_forwards_allowed_prefix_once() {
        let request = b"GET / HTTP/1.1\r\nHost: allowed.example\r\n\r\n";
        let stack = MemoryIo::default();
        let mux = MemoryIo {
            input: request.iter().copied().collect(),
            ..MemoryIo::default()
        };
        let policy = sniff_policy(
            "action = \"allow\"\ndirection = \"upload\"\nprotocol = \"http\"\nunavailable = \"deny\"\nhttp_host = \"allowed.example\"\n",
        );
        let mut flow = PolicyFlow::new(stack, mux, 16_384, 1, None, None, Some(policy)).unwrap();
        let mut context = Context::from_waker(Waker::noop());
        for _ in 0..4 {
            let _ = flow.poll(&mut context, 16_384, 16_384, 16_384);
        }
        assert_eq!(flow.stack.output, request);
    }

    #[test]
    fn udp_sniff_denies_quic_without_forwarding_datagram() {
        let inner = MemoryDatagram {
            input: [vec![0xc0, 0, 0, 1]].into(),
        };
        let policy = sniff_policy(
            "action = \"deny\"\ndirection = \"upload\"\nprotocol = \"quic\"\nunavailable = \"deny\"\n",
        );
        let mut sniff = DatagramSniff::new(inner, Some(policy));
        let mut output = [0; 16];
        let mut context = Context::from_waker(Waker::noop());
        assert!(matches!(
            sniff.poll_recv_datagram(&mut context, &mut output),
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::PermissionDenied
        ));
    }

    #[test]
    fn active_flows_rotate_within_one_user() {
        let mut cursor = 0;
        let flows = [3, 7, 11];
        assert_eq!(select_flow(&mut cursor, &flows), 3);
        assert_eq!(select_flow(&mut cursor, &flows), 7);
        assert_eq!(select_flow(&mut cursor, &flows), 11);
        assert_eq!(select_flow(&mut cursor, &flows), 3);
    }

    #[test]
    fn global_rate_share_respects_user_weight() {
        assert_eq!(weighted_share(4_000, 1, 4), 1_000);
        assert_eq!(weighted_share(4_000, 3, 4), 3_000);
        assert_eq!(weighted_share(1, 1, 2), 0);
    }

    #[test]
    fn static_destination_rules_match_cidr_and_domain_boundaries() {
        assert!(cidr_matches("10.0.0.0/8", "10.42.0.1".parse().unwrap()));
        assert!(!cidr_matches("10.0.0.0/8", "11.0.0.1".parse().unwrap()));
        let rule: config::RuleEntry = toml::from_str(
            "action = \"deny\"\ndirection = \"upload\"\nprotocol = \"any\"\nunavailable = \"deny\"\ndomain_suffix = \"example.com\"\n",
        )
        .unwrap();
        let address = b"api.example.com";
        let metadata = abi::SnolFlowMetadataV1 {
            struct_size: size_of::<abi::SnolFlowMetadataV1>() as u32,
            kind: abi::FLOW_TCP,
            address_type: abi::ADDRESS_DOMAIN,
            reserved: 0,
            address: SnolBytes {
                pointer: address.as_ptr(),
                length: address.len(),
            },
            port: 443,
            reserved2: [0; 6],
            metadata: SnolBytes {
                pointer: std::ptr::null(),
                length: 0,
            },
        };
        let metadata = unsafe { snolc_sdk::module::flow_metadata(&metadata) }.unwrap();
        assert!(address_rule_matches(&rule, &metadata));
        let unrelated = b"badexample.com";
        let metadata = abi::SnolFlowMetadataV1 {
            address: SnolBytes {
                pointer: unrelated.as_ptr(),
                length: unrelated.len(),
            },
            ..metadata_to_owned(&metadata)
        };
        let metadata = unsafe { snolc_sdk::module::flow_metadata(&metadata) }.unwrap();
        assert!(!address_rule_matches(&rule, &metadata));
    }

    fn metadata_to_owned(
        metadata: &snolc_sdk::module::BorrowedFlowMetadata<'_>,
    ) -> abi::SnolFlowMetadataV1 {
        abi::SnolFlowMetadataV1 {
            struct_size: size_of::<abi::SnolFlowMetadataV1>() as u32,
            kind: metadata.kind,
            address_type: metadata.address_type,
            reserved: 0,
            address: SnolBytes {
                pointer: metadata.address.as_ptr(),
                length: metadata.address.len(),
            },
            port: metadata.port,
            reserved2: [0; 6],
            metadata: SnolBytes {
                pointer: metadata.metadata.as_ptr(),
                length: metadata.metadata.len(),
            },
        }
    }

    #[test]
    fn admin_control_commits_before_reply_and_replays() {
        let root = std::env::temp_dir().join(format!(
            "snolc-policy-control-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let database = root.join("policy.redb");
        let template = include_str!("../../../config/templates/modules/policy.toml");
        let mut template: toml::Value = toml::from_str(template).unwrap();
        template["options"]["storage"]["path"] =
            toml::Value::String(database.to_string_lossy().into_owned());
        let options = toml::to_string(&template["options"]).unwrap();
        let instance = 10_001;
        initialize(instance, options.as_bytes(), b"/tmp", std::ptr::null()).unwrap();

        let create = br#"
method = "user.create"
client_id = "panel"
seq = 1

[user]
status = "enabled"
burst_bytes = 65507
weight = 1
group = "default"
rule_profile = "default"

[user.expiration]
mode = "unlimited"
[user.quota]
mode = "limited"
bytes = 1000000
[user.upload_rate]
mode = "unlimited"
[user.download_rate]
mode = "unlimited"
[user.combined_rate]
mode = "unlimited"
[user.max_sessions]
mode = "limited"
count = 2
[user.max_flows]
mode = "limited"
count = 16
"#;
        assert!(matches!(
            control_instance(instance, create),
            Err(abi::STATUS_PENDING)
        ));
        let response = drive_control(instance, create);
        let response_text = std::str::from_utf8(&response).unwrap();
        let response_value: toml::Value = toml::from_str(response_text).unwrap();
        let user_id = response_value["user_id"].as_str().unwrap();
        assert_eq!(response_value["revision"].as_integer(), Some(1));
        assert_eq!(drive_control(instance, create), response);

        let usage = format!("method = \"usage.get\"\nuser_id = \"{user_id}\"\n");
        let usage = drive_control(instance, usage.as_bytes());
        let usage: toml::Value = toml::from_str(std::str::from_utf8(&usage).unwrap()).unwrap();
        assert_eq!(usage["used_bytes"].as_integer(), Some(0));
        assert_eq!(usage["limit_bytes"].as_integer(), Some(1_000_000));

        let credential_add = format!(
            "method = \"credential.add\"\nclient_id = \"panel\"\nseq = 2\nuser_id = \"{user_id}\"\ncredential_sha256 = \"{}\"\n",
            "aa".repeat(32)
        );
        let credential_response = drive_control(instance, credential_add.as_bytes());

        let skipped = format!(
            "method = \"user.disable\"\nclient_id = \"panel\"\nseq = 4\nuser_id = \"{user_id}\"\nexpected_revision = 1\n"
        );
        assert!(matches!(
            control_instance(instance, skipped.as_bytes()),
            Err(abi::STATUS_DENIED)
        ));
        shutdown_instance(instance);
        initialize(instance, options.as_bytes(), b"/tmp", std::ptr::null()).unwrap();
        assert_eq!(
            drive_control(instance, credential_add.as_bytes()),
            credential_response
        );
        let restored_usage = drive_control(instance, usage_request(user_id).as_bytes());
        let restored_usage: toml::Value =
            toml::from_str(std::str::from_utf8(&restored_usage).unwrap()).unwrap();
        assert_eq!(restored_usage["limit_bytes"].as_integer(), Some(1_000_000));
        let revoke = format!(
            "method = \"credential.revoke\"\nclient_id = \"panel\"\nseq = 3\ncredential_sha256 = \"{}\"\n",
            "aa".repeat(32)
        );
        let revoke_response = drive_control(instance, revoke.as_bytes());
        let revoke_response: toml::Value =
            toml::from_str(std::str::from_utf8(&revoke_response).unwrap()).unwrap();
        assert_eq!(revoke_response["status"].as_str(), Some("ok"));
        shutdown_instance(instance);
        fs::remove_dir_all(root).unwrap();
    }

    fn drive_control(instance: u64, request: &[u8]) -> Vec<u8> {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match control_instance(instance, request) {
                Ok(response) => return response,
                Err(abi::STATUS_PENDING) if Instant::now() < deadline => std::thread::yield_now(),
                result => panic!("control failed: {result:?}"),
            }
        }
    }

    fn usage_request(user_id: &str) -> String {
        format!("method = \"usage.get\"\nuser_id = \"{user_id}\"\n")
    }
}
