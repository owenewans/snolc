use std::path::{Path, PathBuf};

use serde::Deserialize;
use thiserror::Error;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Options {
    pub server_id: String,
    pub credential_transport: CredentialTransport,
    pub max_cached_users: usize,
    pub max_admin_clients: usize,
    pub max_control_frame_bytes: usize,
    pub status_interval_ms: u64,
    pub control_grace_ms: u64,
    pub sniff_bytes: usize,
    pub sniff_timeout_ms: u64,
    pub on_unknown_protocol: UnknownAction,
    pub checkpoint_interval_ms: u64,
    pub storage: StorageOptions,
    pub global_rate: GlobalRate,
    pub rules: Rules,
    pub client: Option<ClientOptions>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientOptions {
    pub credential: SecretSource,
}

impl std::fmt::Debug for ClientOptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClientOptions")
            .field("credential", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Deserialize)]
#[serde(tag = "source", rename_all = "lowercase", deny_unknown_fields)]
pub enum SecretSource {
    Toml { value: String },
    Env { name: String },
}

impl std::fmt::Debug for SecretSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Toml { .. } => formatter.write_str("Toml([redacted])"),
            Self::Env { name } => formatter.debug_tuple("Env").field(name).finish(),
        }
    }
}

impl SecretSource {
    pub fn resolve(&self) -> Result<String, ConfigError> {
        match self {
            Self::Toml { value } => Ok(value.clone()),
            Self::Env { name } if valid_name(name) => {
                std::env::var(name).map_err(|_| ConfigError::Secret)
            }
            Self::Env { .. } => Err(ConfigError::Secret),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum CredentialTransport {
    Protected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum UnknownAction {
    Allow,
    Deny,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageOptions {
    pub path: PathBuf,
    pub cache_bytes: usize,
    pub max_database_bytes: u64,
    pub queue_capacity: usize,
    pub accounting_block_bytes: u64,
    pub batch_max_delay_ms: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "mode", rename_all = "lowercase", deny_unknown_fields)]
pub enum GlobalRate {
    Unlimited,
    Limited {
        bytes_per_second: u64,
        burst_bytes: u64,
    },
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rules {
    pub terminal: Action,
    pub entries: Vec<RuleEntry>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Deny,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleEntry {
    pub action: Action,
    pub direction: Direction,
    pub protocol: ObservedProtocol,
    pub unavailable: Action,
    pub cidr: Option<String>,
    pub port: Option<u16>,
    pub domain_exact: Option<String>,
    pub domain_suffix: Option<String>,
    pub tls_sni: Option<String>,
    pub http_host: Option<String>,
    pub user_group: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Upload,
    Download,
    Both,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ObservedProtocol {
    Tls,
    Http,
    Ssh,
    Quic,
    Unknown,
    Any,
}

impl Options {
    pub fn parse(input: &[u8], base: &Path) -> Result<Self, ConfigError> {
        let input = std::str::from_utf8(input).map_err(|_| ConfigError::Utf8)?;
        let mut options: Self = toml::from_str(input)?;
        if !options.storage.path.is_absolute() {
            options.storage.path = base.join(&options.storage.path);
        }
        options.validate()?;
        Ok(options)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.server_id.is_empty() || self.server_id.len() > 128 {
            return Err(ConfigError::Invalid("server_id is invalid"));
        }
        if self.max_cached_users == 0
            || self.max_admin_clients == 0
            || self.max_control_frame_bytes == 0
            || self.max_control_frame_bytes > 65_536
            || self.status_interval_ms == 0
            || self.control_grace_ms == 0
            || self.sniff_bytes == 0
            || self.sniff_bytes > 16_384
            || self.sniff_timeout_ms == 0
            || self.checkpoint_interval_ms == 0
        {
            return Err(ConfigError::Invalid("policy limits are inconsistent"));
        }
        if self.storage.cache_bytes == 0
            || self.storage.max_database_bytes == 0
            || self.storage.queue_capacity == 0
            || self.storage.accounting_block_bytes == 0
            || self.storage.batch_max_delay_ms == 0
        {
            return Err(ConfigError::Invalid("storage limits are inconsistent"));
        }
        if let GlobalRate::Limited {
            bytes_per_second,
            burst_bytes,
        } = self.global_rate
            && (bytes_per_second == 0 || burst_bytes < 65_507)
        {
            return Err(ConfigError::Invalid("global rate is inconsistent"));
        }
        for entry in &self.rules.entries {
            if entry.port == Some(0)
                || entry
                    .domain_exact
                    .as_deref()
                    .is_some_and(|domain| !valid_domain(domain))
                || entry
                    .domain_suffix
                    .as_deref()
                    .is_some_and(|domain| !valid_domain(domain))
                || entry
                    .tls_sni
                    .as_deref()
                    .is_some_and(|domain| !valid_domain(domain))
                || entry
                    .http_host
                    .as_deref()
                    .is_some_and(|domain| !valid_domain(domain))
            {
                return Err(ConfigError::Invalid("rule is invalid"));
            }
        }
        if let Some(client) = &self.client {
            let credential = client.credential.resolve()?;
            if credential.len() != 64
                || !credential
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            {
                return Err(ConfigError::Secret);
            }
        }
        Ok(())
    }
}

fn valid_domain(domain: &str) -> bool {
    !domain.is_empty()
        && domain.len() <= 253
        && domain.is_ascii()
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("policy config is not UTF-8")]
    Utf8,
    #[error("policy config TOML is invalid: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("policy config is invalid: {0}")]
    Invalid(&'static str),
    #[error("policy credential source is missing or invalid")]
    Secret,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normative_template_is_valid() {
        let module = include_str!("../../../config/templates/policy-local-server.toml");
        let value: toml::Value = toml::from_str(module).unwrap();
        let options = toml::to_string(value.get("options").unwrap()).unwrap();
        let parsed = Options::parse(options.as_bytes(), Path::new("/etc/snolc/modules")).unwrap();
        assert_eq!(parsed.storage.queue_capacity, 64);
        assert!(parsed.storage.path.is_absolute());
    }

    #[test]
    fn rejects_unknown_and_missing_fields() {
        let input = b"server_id = \"node\"\ncredential_transport = \"protected\"\n";
        assert!(Options::parse(input, Path::new("/tmp")).is_err());
    }

    #[test]
    fn client_secret_is_explicit_and_redacted() {
        let module = include_str!("../../../config/templates/policy-local-server.toml");
        let mut value: toml::Value = toml::from_str(module).unwrap();
        let client: toml::Value = toml::from_str(
            "[client.credential]\nsource = \"toml\"\nvalue = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n",
        )
        .unwrap();
        value["options"]
            .as_table_mut()
            .unwrap()
            .insert("client".into(), client["client"].clone());
        let options = toml::to_string(&value["options"]).unwrap();
        let parsed = Options::parse(options.as_bytes(), Path::new("/tmp")).unwrap();
        let debug = format!("{:?}", parsed.client.unwrap());
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("aaaaaaaa"));
    }
}
