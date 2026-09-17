#![deny(unsafe_op_in_unsafe_fn)]

mod accounting;
mod admin;
mod config;
mod frame;
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
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::TryRecvError;
use std::task::{Context, Poll, Waker};

use serde::{Deserialize, Serialize};
use snolc_sdk::abi::{self, SnolByteIoV1, SnolBytes, SnolPolicyApiV1, SnolWakeHandle};
use snolc_sdk::{ByteIo, ForeignByteIo, Pump, PumpError, PumpReport};

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
    options: Options,
    storage: StorageWorker,
    admin: AdminState,
    pending_control: Option<PendingControl>,
    sessions: HashMap<u64, ForeignByteIo>,
    flows: HashMap<u64, PolicyFlow<ForeignByteIo, ForeignByteIo>>,
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
    disconnect: Option<u64>,
}

struct PreparedAdmin {
    response: Vec<u8>,
    mutation: AdminMutation,
    changes: Vec<(String, Option<Vec<u8>>)>,
}

struct PolicyFlow<S, M> {
    stack: S,
    mux: M,
    upload: Pump,
    download: Pump,
}

impl<S: ByteIo, M: ByteIo> PolicyFlow<S, M> {
    fn new(stack: S, mux: M, buffer_bytes: usize) -> Result<Self, PumpError> {
        Ok(Self {
            stack,
            mux,
            upload: Pump::new(buffer_bytes)?,
            download: Pump::new(buffer_bytes)?,
        })
    }

    fn poll(
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
    STATES.with(|states| {
        states.borrow_mut().insert(
            instance,
            State {
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
            let flow = match PolicyFlow::new(stack, mux, state.options.sniff_bytes) {
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

fn poll_instance(instance: u64, _wake: SnolWakeHandle) -> u32 {
    STATES.with(|states| {
        let mut states = states.borrow_mut();
        let Some(state) = states.get_mut(&instance) else {
            return abi::STATUS_INVALID;
        };
        let mut context = Context::from_waker(Waker::noop());
        let mut finished = Vec::new();
        for (handle, flow) in &mut state.flows {
            match flow.poll(&mut context, state.options.sniff_bytes) {
                Poll::Ready(Ok((upload, download))) if upload.finished && download.finished => {
                    finished.push(*handle);
                }
                Poll::Ready(Err(_)) => finished.push(*handle),
                Poll::Ready(Ok(_)) | Poll::Pending => {}
            }
        }
        for handle in finished {
            state.flows.remove(&handle);
        }
        abi::STATUS_PENDING
    })
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
            let sessions: Vec<u64> = if user_id.is_none() {
                state.sessions.keys().copied().collect()
            } else {
                Vec::new()
            };
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
            rules_toml,
            ..
        } => {
            toml::from_str::<config::Rules>(&rules_toml).map_err(|_| abi::STATUS_INVALID)?;
            changes.push((
                format!("meta/rules/{profile}"),
                Some(rules_toml.as_bytes().to_vec()),
            ));
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
    if let Some(session) = mutation.disconnect {
        state.sessions.remove(&session);
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

    #[test]
    fn rejects_unprotected_session_context() {
        let context: ChannelSecurity = toml::from_str(
            "confidentiality = false\nintegrity = true\npeer_authenticated = true\npeer_identity = \"server\"\n",
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
        let mut flow = PolicyFlow::new(stack, mux, 16).unwrap();
        let mut context = Context::from_waker(Waker::noop());
        while !flow.upload.is_finished() || !flow.download.is_finished() {
            let _ = flow.poll(&mut context, 16);
        }
        assert_eq!(flow.mux.output, b"upload");
        assert_eq!(flow.stack.output, b"download");
        assert!(flow.mux.shutdown);
        assert!(flow.stack.shutdown);
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
        let template = include_str!("../../../config/templates/policy-local-server.toml");
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

        let skipped = format!(
            "method = \"user.disable\"\nclient_id = \"panel\"\nseq = 3\nuser_id = \"{user_id}\"\nexpected_revision = 1\n"
        );
        assert!(matches!(
            control_instance(instance, skipped.as_bytes()),
            Err(abi::STATUS_DENIED)
        ));
        shutdown_instance(instance);
        initialize(instance, options.as_bytes(), b"/tmp", std::ptr::null()).unwrap();
        assert_eq!(drive_control(instance, create), response);
        let restored_usage = drive_control(instance, usage_request(user_id).as_bytes());
        let restored_usage: toml::Value =
            toml::from_str(std::str::from_utf8(&restored_usage).unwrap()).unwrap();
        assert_eq!(restored_usage["limit_bytes"].as_integer(), Some(1_000_000));
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
