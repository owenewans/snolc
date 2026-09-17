use std::collections::HashMap;

use getrandom::fill;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Clone, Copy, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct UserId([u8; 16]);

impl UserId {
    pub fn generate() -> Result<Self, AdminError> {
        let mut bytes = [0; 16];
        fill(&mut bytes).map_err(|_| AdminError::Random)?;
        Ok(Self(bytes))
    }

    pub fn hex(self) -> String {
        encode_hex(&self.0)
    }

    pub fn parse(input: &str) -> Result<Self, AdminError> {
        Ok(Self(decode_hex(input)?))
    }
}

#[derive(Clone, Copy, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct CredentialDigest([u8; 32]);

impl CredentialDigest {
    pub fn parse(input: &str) -> Result<Self, AdminError> {
        Ok(Self(decode_hex(input)?))
    }

    pub fn hex(self) -> String {
        encode_hex(&self.0)
    }
}

pub struct Credential([u8; 32]);

impl Credential {
    pub fn generate() -> Result<Self, AdminError> {
        let mut bytes = [0; 32];
        fill(&mut bytes).map_err(|_| AdminError::Random)?;
        Ok(Self(bytes))
    }

    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.0).into()
    }

    pub fn digest_id(&self) -> CredentialDigest {
        CredentialDigest(self.digest())
    }

    pub fn parse_hex(input: &str) -> Result<Self, AdminError> {
        Ok(Self(decode_hex(input)?))
    }

    pub fn hex(&self) -> String {
        encode_hex(&self.0)
    }

    pub fn expose_once(mut self) -> [u8; 32] {
        let output = self.0;
        self.0.fill(0);
        output
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum UserStatus {
    Enabled,
    Disabled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "mode", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Expiration {
    Unlimited,
    AtUtc { unix_seconds: u64 },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "mode", rename_all = "lowercase", deny_unknown_fields)]
pub enum ByteLimit {
    Unlimited,
    Limited { bytes: u64 },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "mode", rename_all = "lowercase", deny_unknown_fields)]
pub enum RateLimit {
    Unlimited,
    Limited { bytes_per_second: u64 },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "mode", rename_all = "lowercase", deny_unknown_fields)]
pub enum CountLimit {
    Unlimited,
    Limited { count: u32 },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UserSpec {
    pub status: UserStatus,
    pub expiration: Expiration,
    pub quota: ByteLimit,
    pub upload_rate: RateLimit,
    pub download_rate: RateLimit,
    pub combined_rate: RateLimit,
    pub burst_bytes: u64,
    pub max_sessions: CountLimit,
    pub max_flows: CountLimit,
    pub weight: u32,
    pub group: String,
    pub rule_profile: String,
}

impl UserSpec {
    pub fn validate(&self) -> Result<(), AdminError> {
        if self.weight == 0
            || self.burst_bytes < 65_507
            || self.group.is_empty()
            || self.group.len() > 64
            || self.rule_profile.is_empty()
            || self.rule_profile.len() > 64
            || matches!(self.quota, ByteLimit::Limited { bytes: 0 })
            || matches!(
                self.upload_rate,
                RateLimit::Limited {
                    bytes_per_second: 0
                }
            )
            || matches!(
                self.download_rate,
                RateLimit::Limited {
                    bytes_per_second: 0
                }
            )
            || matches!(
                self.combined_rate,
                RateLimit::Limited {
                    bytes_per_second: 0
                }
            )
            || matches!(self.max_sessions, CountLimit::Limited { count: 0 })
            || matches!(self.max_flows, CountLimit::Limited { count: 0 })
        {
            return Err(AdminError::Invalid);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserRecord {
    pub id: String,
    pub spec: UserSpec,
    pub revision: u64,
    pub durable_charged_bytes: u64,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub max_observed_utc: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CredentialRecord {
    pub digest: String,
    pub user_id: String,
    pub revoked: bool,
    pub revision: u64,
}

#[derive(Deserialize, Serialize)]
struct StoredUserRecord {
    id: String,
    status: UserStatus,
    expiration: StoredExpiration,
    quota: StoredByteLimit,
    upload_rate: StoredRateLimit,
    download_rate: StoredRateLimit,
    combined_rate: StoredRateLimit,
    burst_bytes: u64,
    max_sessions: StoredCountLimit,
    max_flows: StoredCountLimit,
    weight: u32,
    group: String,
    rule_profile: String,
    revision: u64,
    durable_charged_bytes: u64,
    upload_bytes: u64,
    download_bytes: u64,
    max_observed_utc: u64,
}

#[derive(Deserialize, Serialize)]
enum StoredExpiration {
    Unlimited,
    AtUtc(u64),
}

#[derive(Deserialize, Serialize)]
enum StoredByteLimit {
    Unlimited,
    Limited(u64),
}

#[derive(Deserialize, Serialize)]
enum StoredRateLimit {
    Unlimited,
    Limited(u64),
}

#[derive(Deserialize, Serialize)]
enum StoredCountLimit {
    Unlimited,
    Limited(u32),
}

pub(crate) fn encode_user_record(user: &UserRecord) -> Result<Vec<u8>, AdminError> {
    let stored = StoredUserRecord {
        id: user.id.clone(),
        status: user.spec.status,
        expiration: match user.spec.expiration {
            Expiration::Unlimited => StoredExpiration::Unlimited,
            Expiration::AtUtc { unix_seconds } => StoredExpiration::AtUtc(unix_seconds),
        },
        quota: match user.spec.quota {
            ByteLimit::Unlimited => StoredByteLimit::Unlimited,
            ByteLimit::Limited { bytes } => StoredByteLimit::Limited(bytes),
        },
        upload_rate: stored_rate(&user.spec.upload_rate),
        download_rate: stored_rate(&user.spec.download_rate),
        combined_rate: stored_rate(&user.spec.combined_rate),
        burst_bytes: user.spec.burst_bytes,
        max_sessions: stored_count(&user.spec.max_sessions),
        max_flows: stored_count(&user.spec.max_flows),
        weight: user.spec.weight,
        group: user.spec.group.clone(),
        rule_profile: user.spec.rule_profile.clone(),
        revision: user.revision,
        durable_charged_bytes: user.durable_charged_bytes,
        upload_bytes: user.upload_bytes,
        download_bytes: user.download_bytes,
        max_observed_utc: user.max_observed_utc,
    };
    postcard::to_allocvec(&stored).map_err(|_| AdminError::Encode)
}

pub(crate) fn decode_user_record(input: &[u8]) -> Result<UserRecord, AdminError> {
    let stored: StoredUserRecord = postcard::from_bytes(input).map_err(|_| AdminError::Encode)?;
    Ok(UserRecord {
        id: stored.id,
        spec: UserSpec {
            status: stored.status,
            expiration: match stored.expiration {
                StoredExpiration::Unlimited => Expiration::Unlimited,
                StoredExpiration::AtUtc(unix_seconds) => Expiration::AtUtc { unix_seconds },
            },
            quota: match stored.quota {
                StoredByteLimit::Unlimited => ByteLimit::Unlimited,
                StoredByteLimit::Limited(bytes) => ByteLimit::Limited { bytes },
            },
            upload_rate: runtime_rate(stored.upload_rate),
            download_rate: runtime_rate(stored.download_rate),
            combined_rate: runtime_rate(stored.combined_rate),
            burst_bytes: stored.burst_bytes,
            max_sessions: runtime_count(stored.max_sessions),
            max_flows: runtime_count(stored.max_flows),
            weight: stored.weight,
            group: stored.group,
            rule_profile: stored.rule_profile,
        },
        revision: stored.revision,
        durable_charged_bytes: stored.durable_charged_bytes,
        upload_bytes: stored.upload_bytes,
        download_bytes: stored.download_bytes,
        max_observed_utc: stored.max_observed_utc,
    })
}

fn stored_rate(rate: &RateLimit) -> StoredRateLimit {
    match rate {
        RateLimit::Unlimited => StoredRateLimit::Unlimited,
        RateLimit::Limited { bytes_per_second } => StoredRateLimit::Limited(*bytes_per_second),
    }
}

fn runtime_rate(rate: StoredRateLimit) -> RateLimit {
    match rate {
        StoredRateLimit::Unlimited => RateLimit::Unlimited,
        StoredRateLimit::Limited(bytes_per_second) => RateLimit::Limited { bytes_per_second },
    }
}

fn stored_count(limit: &CountLimit) -> StoredCountLimit {
    match limit {
        CountLimit::Unlimited => StoredCountLimit::Unlimited,
        CountLimit::Limited { count } => StoredCountLimit::Limited(*count),
    }
}

fn runtime_count(limit: StoredCountLimit) -> CountLimit {
    match limit {
        StoredCountLimit::Unlimited => CountLimit::Unlimited,
        StoredCountLimit::Limited(count) => CountLimit::Limited { count },
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "method", deny_unknown_fields)]
pub enum ControlRequest {
    #[serde(rename = "user.create")]
    UserCreate {
        client_id: String,
        seq: u64,
        user: UserSpec,
    },
    #[serde(rename = "user.update")]
    UserUpdate {
        client_id: String,
        seq: u64,
        user_id: String,
        expected_revision: u64,
        user: UserSpec,
    },
    #[serde(rename = "user.disable")]
    UserDisable {
        client_id: String,
        seq: u64,
        user_id: String,
        expected_revision: u64,
    },
    #[serde(rename = "user.delete")]
    UserDelete {
        client_id: String,
        seq: u64,
        user_id: String,
        expected_revision: u64,
    },
    #[serde(rename = "credential.add")]
    CredentialAdd {
        client_id: String,
        seq: u64,
        user_id: String,
        credential_sha256: String,
    },
    #[serde(rename = "credential.revoke")]
    CredentialRevoke {
        client_id: String,
        seq: u64,
        credential_sha256: String,
    },
    #[serde(rename = "quota.add")]
    QuotaAdd {
        client_id: String,
        seq: u64,
        user_id: String,
        bytes: u64,
    },
    #[serde(rename = "quota.new_period")]
    QuotaNewPeriod {
        client_id: String,
        seq: u64,
        user_id: String,
        quota: ByteLimit,
    },
    #[serde(rename = "usage.get")]
    UsageGet { user_id: String },
    #[serde(rename = "sessions.list")]
    SessionsList { user_id: Option<String> },
    #[serde(rename = "sessions.disconnect")]
    SessionsDisconnect {
        client_id: String,
        seq: u64,
        session_id: u64,
    },
    #[serde(rename = "rules.replace")]
    RulesReplace {
        client_id: String,
        seq: u64,
        profile: String,
        apply: RuleApply,
        rules_toml: String,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleApply {
    New,
    Active,
}

impl ControlRequest {
    pub fn parse(input: &[u8]) -> Result<Self, AdminError> {
        let input = std::str::from_utf8(input).map_err(|_| AdminError::Invalid)?;
        let request: Self = toml::from_str(input).map_err(|_| AdminError::Invalid)?;
        request.validate()?;
        Ok(request)
    }

    pub fn sequence(&self) -> Option<(&str, u64)> {
        match self {
            Self::UserCreate { client_id, seq, .. }
            | Self::UserUpdate { client_id, seq, .. }
            | Self::UserDisable { client_id, seq, .. }
            | Self::UserDelete { client_id, seq, .. }
            | Self::CredentialAdd { client_id, seq, .. }
            | Self::CredentialRevoke { client_id, seq, .. }
            | Self::QuotaAdd { client_id, seq, .. }
            | Self::QuotaNewPeriod { client_id, seq, .. }
            | Self::SessionsDisconnect { client_id, seq, .. }
            | Self::RulesReplace { client_id, seq, .. } => Some((client_id, *seq)),
            Self::UsageGet { .. } | Self::SessionsList { .. } => None,
        }
    }

    fn validate(&self) -> Result<(), AdminError> {
        if let Some((client_id, seq)) = self.sequence() {
            validate_client_id(client_id)?;
            if seq == 0 {
                return Err(AdminError::Sequence);
            }
        }
        match self {
            Self::UserCreate { user, .. } => user.validate(),
            Self::UserUpdate { user_id, user, .. } => {
                user.validate()?;
                UserId::parse(user_id).map(|_| ())
            }
            Self::UserDisable { user_id, .. }
            | Self::UserDelete { user_id, .. }
            | Self::QuotaNewPeriod { user_id, .. }
            | Self::UsageGet { user_id }
            | Self::SessionsList {
                user_id: Some(user_id),
            } => UserId::parse(user_id).map(|_| ()),
            Self::CredentialAdd {
                user_id,
                credential_sha256,
                ..
            } => {
                UserId::parse(user_id)?;
                CredentialDigest::parse(credential_sha256).map(|_| ())
            }
            Self::CredentialRevoke {
                credential_sha256, ..
            } => CredentialDigest::parse(credential_sha256).map(|_| ()),
            Self::QuotaAdd { user_id, bytes, .. } => {
                UserId::parse(user_id)?;
                if *bytes == 0 {
                    return Err(AdminError::Invalid);
                }
                Ok(())
            }
            Self::RulesReplace {
                profile,
                rules_toml,
                ..
            } if profile.is_empty()
                || profile.len() > 64
                || rules_toml.is_empty()
                || rules_toml.len() > 65_536 =>
            {
                Err(AdminError::Invalid)
            }
            Self::SessionsDisconnect { session_id: 0, .. } => Err(AdminError::Invalid),
            _ => Ok(()),
        }
    }
}

impl Drop for Credential {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[derive(Clone, Deserialize, Serialize)]
struct Receipt {
    seq: u64,
    request_hash: [u8; 32],
    response: Vec<u8>,
}

pub struct AdminSequencer {
    max_clients: usize,
    clients: HashMap<String, Receipt>,
}

pub enum AdminDecision {
    Execute { request_hash: [u8; 32] },
    Replay(Vec<u8>),
}

impl AdminSequencer {
    pub fn new(max_clients: usize) -> Result<Self, AdminError> {
        if max_clients == 0 {
            return Err(AdminError::Invalid);
        }
        Ok(Self {
            max_clients,
            clients: HashMap::new(),
        })
    }

    pub fn check(
        &self,
        client_id: &str,
        seq: u64,
        request: &[u8],
    ) -> Result<AdminDecision, AdminError> {
        validate_client_id(client_id)?;
        let request_hash: [u8; 32] = Sha256::digest(request).into();
        match self.clients.get(client_id) {
            None if self.clients.len() >= self.max_clients => Err(AdminError::ClientLimit),
            None if seq == 1 => Ok(AdminDecision::Execute { request_hash }),
            None => Err(AdminError::Sequence),
            Some(receipt) if seq == receipt.seq && request_hash == receipt.request_hash => {
                Ok(AdminDecision::Replay(receipt.response.clone()))
            }
            Some(receipt) if seq == receipt.seq + 1 => Ok(AdminDecision::Execute { request_hash }),
            Some(_) => Err(AdminError::Sequence),
        }
    }

    pub fn commit(
        &mut self,
        client_id: String,
        seq: u64,
        request_hash: [u8; 32],
        response: Vec<u8>,
    ) -> Result<Vec<u8>, AdminError> {
        let encoded = self.prepare_commit(&client_id, seq, request_hash, response)?;
        self.apply_commit(client_id, &encoded)?;
        Ok(encoded)
    }

    pub fn prepare_commit(
        &self,
        client_id: &str,
        seq: u64,
        request_hash: [u8; 32],
        response: Vec<u8>,
    ) -> Result<Vec<u8>, AdminError> {
        validate_client_id(client_id)?;
        match self.clients.get(client_id) {
            None if self.clients.len() >= self.max_clients => {
                return Err(AdminError::ClientLimit);
            }
            None if seq == 1 => {}
            Some(receipt) if seq == receipt.seq + 1 => {}
            _ => return Err(AdminError::State),
        }
        let receipt = Receipt {
            seq,
            request_hash,
            response,
        };
        postcard::to_allocvec(&receipt).map_err(|_| AdminError::Encode)
    }

    pub fn apply_commit(&mut self, client_id: String, encoded: &[u8]) -> Result<(), AdminError> {
        let receipt: Receipt = postcard::from_bytes(encoded).map_err(|_| AdminError::Encode)?;
        self.prepare_commit(
            &client_id,
            receipt.seq,
            receipt.request_hash,
            receipt.response.clone(),
        )?;
        self.clients.insert(client_id, receipt);
        Ok(())
    }

    pub fn restore(&mut self, client_id: String, encoded: &[u8]) -> Result<(), AdminError> {
        validate_client_id(&client_id)?;
        if !self.clients.contains_key(&client_id) && self.clients.len() >= self.max_clients {
            return Err(AdminError::ClientLimit);
        }
        let receipt = postcard::from_bytes(encoded).map_err(|_| AdminError::Encode)?;
        self.clients.insert(client_id, receipt);
        Ok(())
    }
}

fn validate_client_id(client_id: &str) -> Result<(), AdminError> {
    if client_id.is_empty()
        || client_id.len() > 64
        || !client_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(AdminError::Invalid);
    }
    Ok(())
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[usize::from(byte >> 4)] as char);
        output.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    output
}

fn decode_hex<const N: usize>(input: &str) -> Result<[u8; N], AdminError> {
    if input.len() != N * 2 || !input.is_ascii() {
        return Err(AdminError::Invalid);
    }
    let mut output = [0; N];
    let (pairs, remainder) = input.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(AdminError::Invalid);
    }
    for (index, pair) in pairs.iter().enumerate() {
        let high = decode_nibble(pair[0])?;
        let low = decode_nibble(pair[1])?;
        output[index] = high
            .checked_mul(16)
            .and_then(|high| high.checked_add(low))
            .ok_or(AdminError::Invalid)?;
    }
    Ok(output)
}

fn decode_nibble(byte: u8) -> Result<u8, AdminError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(AdminError::Invalid),
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum AdminError {
    #[error("administrative client is invalid")]
    Invalid,
    #[error("administrative client limit is exhausted")]
    ClientLimit,
    #[error("administrative sequence is invalid")]
    Sequence,
    #[error("administrative state transition is invalid")]
    State,
    #[error("system random source failed")]
    Random,
    #[error("administrative record encoding failed")]
    Encode,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeats_last_response_without_reapplying() {
        let mut sequencer = AdminSequencer::new(2).unwrap();
        let request = b"quota.add";
        let hash = match sequencer.check("panel", 1, request).unwrap() {
            AdminDecision::Execute { request_hash } => request_hash,
            AdminDecision::Replay(_) => panic!("new request replayed"),
        };
        sequencer
            .commit("panel".into(), 1, hash, b"revision=2".to_vec())
            .unwrap();
        assert!(matches!(
            sequencer.check("panel", 1, request).unwrap(),
            AdminDecision::Replay(response) if response == b"revision=2"
        ));
        assert!(matches!(
            sequencer.check("panel", 1, b"different"),
            Err(AdminError::Sequence)
        ));
        assert!(matches!(
            sequencer.check("panel", 3, b"skip"),
            Err(AdminError::Sequence)
        ));
    }

    #[test]
    fn prepared_receipt_is_invisible_until_durable_commit() {
        let mut sequencer = AdminSequencer::new(1).unwrap();
        let request = b"user.disable";
        let request_hash = match sequencer.check("panel", 1, request).unwrap() {
            AdminDecision::Execute { request_hash } => request_hash,
            AdminDecision::Replay(_) => panic!("new request replayed"),
        };
        let encoded = sequencer
            .prepare_commit("panel", 1, request_hash, b"status = \"ok\"".to_vec())
            .unwrap();
        assert!(matches!(
            sequencer.check("panel", 1, request).unwrap(),
            AdminDecision::Execute { .. }
        ));
        sequencer.apply_commit("panel".into(), &encoded).unwrap();
        assert!(matches!(
            sequencer.check("panel", 1, request).unwrap(),
            AdminDecision::Replay(_)
        ));
    }

    #[test]
    fn credentials_hash_and_clear_secret() {
        let credential = Credential::generate().unwrap();
        let digest = credential.digest();
        let secret = credential.expose_once();
        assert_eq!(digest.as_slice(), Sha256::digest(secret).as_slice());
        assert_eq!(UserId::generate().unwrap().hex().len(), 32);
    }

    #[test]
    fn control_schema_requires_complete_user_limits() {
        let request = br#"
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
        let parsed = ControlRequest::parse(request).unwrap();
        assert_eq!(parsed.sequence(), Some(("panel", 1)));
        let missing = std::str::from_utf8(request)
            .unwrap()
            .replace("weight = 1\n", "");
        assert!(ControlRequest::parse(missing.as_bytes()).is_err());
        let unknown = std::str::from_utf8(request)
            .unwrap()
            .replace("weight = 1", "weight = 1\nunknown = true");
        assert!(ControlRequest::parse(unknown.as_bytes()).is_err());
    }

    #[test]
    fn identifiers_reject_noncanonical_hex() {
        assert!(UserId::parse("00").is_err());
        assert!(UserId::parse("GG000000000000000000000000000000").is_err());
        let digest = Credential::generate().unwrap().digest_id();
        assert_eq!(
            CredentialDigest::parse(&digest.hex()).unwrap().hex(),
            digest.hex()
        );
    }
}
