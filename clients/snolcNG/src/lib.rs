use std::fmt;
use std::io::Read;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MAX_PROFILE_BYTES: usize = 65_536;
pub const MAX_SUBSCRIPTION_BYTES: usize = 1_048_576;
pub const MAX_SUBSCRIPTION_PROFILES: usize = 64;
const URI_PREFIX: &str = "snolc://profile/";
const MAX_ENCODED_PROFILE_BYTES: usize = MAX_PROFILE_BYTES.div_ceil(3) * 4;

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[redacted]")
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub wire_version: u32,
    pub server_id: String,
    pub endpoint: String,
    pub modules: Vec<ProfileModule>,
    pub server_pin: String,
    pub credential: Secret,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileModule {
    pub instance: String,
    pub package: String,
    pub class: ModuleClass,
    pub options: toml::Table,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ModuleClass {
    Adapter,
    Protection,
    Carrier,
    Policy,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct SubscriptionDocument {
    profiles: Vec<String>,
}

impl Profile {
    pub fn parse_toml(input: &str) -> Result<Self, ProfileError> {
        if input.is_empty() || input.len() > MAX_PROFILE_BYTES {
            return Err(ProfileError::Size);
        }
        let profile: Self = toml::from_str(input)?;
        profile.validate()?;
        Ok(profile)
    }

    pub fn from_uri(input: &str) -> Result<Self, ProfileError> {
        let encoded = input.strip_prefix(URI_PREFIX).ok_or(ProfileError::Scheme)?;
        if encoded.is_empty()
            || encoded.len() > MAX_ENCODED_PROFILE_BYTES
            || encoded.contains('=')
            || !encoded.is_ascii()
        {
            return Err(ProfileError::Size);
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| ProfileError::Base64)?;
        if bytes.len() > MAX_PROFILE_BYTES {
            return Err(ProfileError::Size);
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| ProfileError::Utf8)?;
        Self::parse_toml(text)
    }

    pub fn to_uri(&self) -> Result<String, ProfileError> {
        self.validate()?;
        let text = toml::to_string(self)?;
        if text.len() > MAX_PROFILE_BYTES {
            return Err(ProfileError::Size);
        }
        Ok(format!("{URI_PREFIX}{}", URL_SAFE_NO_PAD.encode(text)))
    }

    pub fn validate(&self) -> Result<(), ProfileError> {
        if self.wire_version != 1
            || !valid_name(&self.server_id)
            || self.endpoint.is_empty()
            || self.endpoint.len() > 512
            || self.server_pin.is_empty()
            || self.server_pin.len() > 512
            || self.credential.0.is_empty()
            || self.credential.0.len() > 1024
            || self.modules.is_empty()
            || self.modules.len() > 16
        {
            return Err(ProfileError::Value);
        }
        let mut adapters = 0;
        let mut protections = 0;
        let mut carriers = 0;
        let mut policies = 0;
        let mut instances = std::collections::BTreeSet::new();
        for module in &self.modules {
            if !valid_name(&module.instance)
                || !valid_package(&module.package)
                || !instances.insert(&module.instance)
                || contains_privileged_option(&module.options)
            {
                return Err(ProfileError::Value);
            }
            match module.class {
                ModuleClass::Adapter => adapters += 1,
                ModuleClass::Protection => protections += 1,
                ModuleClass::Carrier => carriers += 1,
                ModuleClass::Policy => policies += 1,
            }
        }
        if adapters == 0 || protections != 1 || carriers != 1 || policies != 1 {
            return Err(ProfileError::Value);
        }
        Ok(())
    }
}

pub fn fetch_subscription(url: &str, bearer: &Secret) -> Result<Vec<Profile>, ProfileError> {
    if !url.starts_with("https://") || bearer.0.is_empty() {
        return Err(ProfileError::Subscription);
    }
    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .map_err(|error| ProfileError::Network(error.to_string()))?;
    let response = client
        .get(url)
        .bearer_auth(bearer.expose())
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .map_err(|error| ProfileError::Network(error.to_string()))?;
    if response
        .content_length()
        .is_some_and(|length| length > MAX_SUBSCRIPTION_BYTES as u64)
    {
        return Err(ProfileError::Size);
    }
    let mut bytes = Vec::new();
    response
        .take(MAX_SUBSCRIPTION_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    parse_subscription(&bytes)
}

pub fn parse_subscription(input: &[u8]) -> Result<Vec<Profile>, ProfileError> {
    if input.is_empty() || input.len() > MAX_SUBSCRIPTION_BYTES {
        return Err(ProfileError::Size);
    }
    let text = std::str::from_utf8(input).map_err(|_| ProfileError::Utf8)?;
    let document: SubscriptionDocument = toml::from_str(text)?;
    if document.profiles.is_empty() || document.profiles.len() > MAX_SUBSCRIPTION_PROFILES {
        return Err(ProfileError::Subscription);
    }
    document
        .profiles
        .iter()
        .map(|profile| Profile::from_uri(profile))
        .collect()
}

fn contains_privileged_option(table: &toml::Table) -> bool {
    table.iter().any(|(key, value)| {
        let key = key.to_ascii_lowercase();
        matches!(
            key.as_str(),
            "path"
                | "file"
                | "directory"
                | "socket"
                | "command"
                | "script"
                | "packages"
                | "state"
                | "log"
        ) || match value {
            toml::Value::Table(table) => contains_privileged_option(table),
            toml::Value::Array(values) => values.iter().any(|value| match value {
                toml::Value::Table(table) => contains_privileged_option(table),
                _ => false,
            }),
            _ => false,
        }
    })
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_package(value: &str) -> bool {
    let Some((name, version)) = value.rsplit_once('@') else {
        return false;
    };
    let Some((owner, module)) = name.split_once('/') else {
        return false;
    };
    !owner.is_empty()
        && !module.is_empty()
        && !module.contains('/')
        && !version.is_empty()
        && owner.bytes().all(package_character)
        && module.bytes().all(package_character)
        && version
            .bytes()
            .all(|byte| package_character(byte) || byte == b'+')
}

fn package_character(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
}

#[derive(Debug, Error)]
pub enum ProfileError {
    #[error("profile size is invalid")]
    Size,
    #[error("profile URI scheme is invalid")]
    Scheme,
    #[error("profile base64 is invalid")]
    Base64,
    #[error("profile is not UTF-8")]
    Utf8,
    #[error("profile TOML is invalid: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("profile TOML cannot be encoded: {0}")]
    TomlEncode(#[from] toml::ser::Error),
    #[error("profile value is invalid")]
    Value,
    #[error("subscription is invalid")]
    Subscription,
    #[error("network request failed: {0}")]
    Network(String),
    #[error("subscription I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> Profile {
        Profile {
            wire_version: 1,
            server_id: "node-1".into(),
            endpoint: "203.0.113.1:443".into(),
            modules: vec![
                module("tun", ModuleClass::Adapter),
                module("noise", ModuleClass::Protection),
                module("tcp", ModuleClass::Carrier),
                module("policy", ModuleClass::Policy),
            ],
            server_pin: "server-pin".into(),
            credential: Secret("credential".into()),
        }
    }

    fn module(instance: &str, class: ModuleClass) -> ProfileModule {
        ProfileModule {
            instance: instance.into(),
            package: format!("owenewans/{instance}@0.0.1"),
            class,
            options: toml::Table::new(),
        }
    }

    #[test]
    fn uri_round_trip_uses_hostless_base64url_without_padding() {
        let profile = profile();
        let uri = profile.to_uri().unwrap();
        assert!(uri.starts_with(URI_PREFIX));
        assert!(!uri.contains('='));
        assert_eq!(Profile::from_uri(&uri).unwrap(), profile);
    }

    #[test]
    fn rejects_admin_paths_unknown_fields_and_oversized_input() {
        let mut profile = profile();
        profile.modules[0]
            .options
            .insert("path".into(), "/etc/passwd".into());
        assert!(matches!(profile.validate(), Err(ProfileError::Value)));
        assert!(matches!(
            Profile::from_uri("https://profile/value"),
            Err(ProfileError::Scheme)
        ));
        let unknown = "wire_version = 1\nunknown = true\n";
        assert!(Profile::parse_toml(unknown).is_err());
        assert!(matches!(
            Profile::parse_toml(&"x".repeat(MAX_PROFILE_BYTES + 1)),
            Err(ProfileError::Size)
        ));
    }

    #[test]
    fn secret_debug_is_redacted() {
        assert_eq!(format!("{:?}", profile().credential), "[redacted]");
    }

    #[test]
    fn subscription_limits_count_and_reuses_profile_parser() {
        let uri = profile().to_uri().unwrap();
        let input = toml::to_string(&toml::toml! { profiles = [uri] }).unwrap();
        assert_eq!(parse_subscription(input.as_bytes()).unwrap().len(), 1);
        let profiles = vec![profile().to_uri().unwrap(); MAX_SUBSCRIPTION_PROFILES + 1];
        let input = toml::to_string(&toml::toml! { profiles = profiles }).unwrap();
        assert!(matches!(
            parse_subscription(input.as_bytes()),
            Err(ProfileError::Subscription)
        ));
    }
}
