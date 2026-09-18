use std::collections::BTreeSet;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

#[cfg(all(feature = "gui", target_os = "android"))]
mod android;
#[cfg(feature = "gui")]
pub mod native_ui;
pub mod runtime;
#[cfg(feature = "gui")]
pub mod ui;

pub const MAX_PROFILE_BYTES: usize = 65_536;
pub const MAX_SUBSCRIPTION_BYTES: usize = 1_048_576;
pub const MAX_SUBSCRIPTION_PROFILES: usize = 64;
const URI_PREFIX: &str = "snolc://profile/";
const MAX_ENCODED_PROFILE_BYTES: usize = MAX_PROFILE_BYTES.div_ceil(3) * 4;
static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    fn new(value: String) -> Self {
        Self(value)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
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
pub struct ProvisionProfile {
    pub wire_version: u32,
    pub server_id: String,
    pub endpoint: String,
    pub modules: Vec<ProfileModule>,
    pub server_pin: String,
}

pub struct AccessProvisioning {
    profile: ProvisionProfile,
    user_id: String,
    secret: [u8; 32],
    request: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProvisionedAccess {
    pub uri: String,
    pub user_id: String,
    pub revision: u64,
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedClient {
    pub main_path: PathBuf,
    pub main_toml: String,
    pub files: Vec<GeneratedFile>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedFile {
    pub path: PathBuf,
    pub contents: Vec<u8>,
    pub secret: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Screen {
    Profiles,
    Connection,
    Advanced,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Denied(String),
    Stopped(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerStatus {
    pub used_bytes: u64,
    pub limit_bytes: Option<u64>,
    pub upload_bytes_per_second: Option<u64>,
    pub download_bytes_per_second: Option<u64>,
    pub expires_at: Option<String>,
    pub revision: u64,
    pub reason: Option<String>,
    pub stale: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ImportedProfile {
    pub source: String,
    pub profile: Profile,
    pub pending_packages: BTreeSet<String>,
}

#[derive(Debug)]
pub struct AppState {
    pub screen: Screen,
    pub profiles: Vec<ImportedProfile>,
    pub selected: Option<usize>,
    pub connection: ConnectionState,
    pub status: Option<ServerStatus>,
    repaint_requested: bool,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            screen: Screen::Profiles,
            profiles: Vec::new(),
            selected: None,
            connection: ConnectionState::Disconnected,
            status: None,
            repaint_requested: true,
        }
    }
}

impl AppState {
    pub fn import_profile(
        &mut self,
        uri: &str,
        source: String,
        trusted_packages: &BTreeSet<String>,
    ) -> Result<usize, ProfileError> {
        let profile = Profile::from_uri(uri)?;
        if self
            .profiles
            .iter()
            .any(|existing| existing.profile.server_id == profile.server_id)
        {
            return Err(ProfileError::DuplicateServer);
        }
        let pending_packages = profile
            .modules
            .iter()
            .filter(|module| !trusted_packages.contains(&module.package))
            .map(|module| module.package.clone())
            .collect();
        self.profiles.push(ImportedProfile {
            source,
            profile,
            pending_packages,
        });
        let index = self.profiles.len() - 1;
        self.selected = Some(index);
        self.repaint_requested = true;
        Ok(index)
    }

    pub fn approve_package(&mut self, package: &str) -> Result<(), ProfileError> {
        let profile = self.selected_profile_mut()?;
        if !profile.pending_packages.remove(package) {
            return Err(ProfileError::PackageApproval);
        }
        self.repaint_requested = true;
        Ok(())
    }

    pub fn select(&mut self, index: usize) -> Result<(), ProfileError> {
        if index >= self.profiles.len() {
            return Err(ProfileError::Selection);
        }
        self.selected = Some(index);
        self.status = None;
        self.connection = ConnectionState::Disconnected;
        self.repaint_requested = true;
        Ok(())
    }

    pub fn begin_connect(&mut self) -> Result<(), ProfileError> {
        if !self.selected_profile()?.pending_packages.is_empty() {
            return Err(ProfileError::PackageApproval);
        }
        self.connection = ConnectionState::Connecting;
        self.screen = Screen::Connection;
        self.repaint_requested = true;
        Ok(())
    }

    pub fn connected(&mut self) {
        self.connection = ConnectionState::Connected;
        self.repaint_requested = true;
    }

    pub fn denied(&mut self, reason: String) {
        self.connection = ConnectionState::Denied(reason);
        self.repaint_requested = true;
    }

    pub fn stopped(&mut self, reason: String) {
        self.connection = ConnectionState::Stopped(reason);
        if let Some(status) = &mut self.status {
            status.stale = true;
        }
        self.repaint_requested = true;
    }

    pub fn apply_status(&mut self, mut status: ServerStatus) {
        if self
            .status
            .as_ref()
            .is_some_and(|current| current.revision > status.revision)
        {
            return;
        }
        status.stale = false;
        self.status = Some(status);
        self.repaint_requested = true;
    }

    pub fn mark_stale(&mut self) {
        if let Some(status) = &mut self.status {
            status.stale = true;
            self.repaint_requested = true;
        }
    }

    pub fn set_screen(&mut self, screen: Screen) {
        if self.screen != screen {
            self.screen = screen;
            self.repaint_requested = true;
        }
    }

    pub fn take_repaint_request(&mut self) -> bool {
        std::mem::take(&mut self.repaint_requested)
    }

    pub fn selected_profile(&self) -> Result<&ImportedProfile, ProfileError> {
        self.selected
            .and_then(|index| self.profiles.get(index))
            .ok_or(ProfileError::Selection)
    }

    fn selected_profile_mut(&mut self) -> Result<&mut ImportedProfile, ProfileError> {
        self.selected
            .and_then(|index| self.profiles.get_mut(index))
            .ok_or(ProfileError::Selection)
    }
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

impl ProvisionProfile {
    #[cfg(any(feature = "gui", test))]
    fn from_profile(profile: &Profile) -> Self {
        Self {
            wire_version: profile.wire_version,
            server_id: profile.server_id.clone(),
            endpoint: profile.endpoint.clone(),
            modules: profile.modules.clone(),
            server_pin: profile.server_pin.clone(),
        }
    }

    pub fn parse_toml(input: &str) -> Result<Self, ProfileError> {
        if input.is_empty() || input.len() > MAX_PROFILE_BYTES {
            return Err(ProfileError::Size);
        }
        let profile: Self = toml::from_str(input)?;
        profile
            .clone()
            .with_credential("provisioning-check")?
            .validate()?;
        Ok(profile)
    }

    fn with_credential(self, credential: &str) -> Result<Profile, ProfileError> {
        self.with_secret(Secret::new(credential.to_owned()))
    }

    fn with_secret(self, credential: Secret) -> Result<Profile, ProfileError> {
        let profile = Profile {
            wire_version: self.wire_version,
            server_id: self.server_id,
            endpoint: self.endpoint,
            modules: self.modules,
            server_pin: self.server_pin,
            credential,
        };
        profile.validate()?;
        Ok(profile)
    }
}

impl AccessProvisioning {
    pub fn new(
        profile: ProvisionProfile,
        user_id: &str,
        client_id: &str,
        seq: u64,
    ) -> Result<Self, ProfileError> {
        profile.clone().with_credential("provisioning-check")?;
        if user_id.len() != 32
            || !user_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            || !valid_name(client_id)
            || seq == 0
        {
            return Err(ProfileError::Provisioning);
        }
        let mut secret = [0; 32];
        getrandom::fill(&mut secret).map_err(|_| ProfileError::Random)?;
        let digest = encode_hex(&Sha256::digest(secret));
        let request = toml::to_string(&CredentialAddRequest {
            method: "credential.add",
            client_id,
            seq,
            user_id,
            credential_sha256: &digest,
        })?
        .into_bytes();
        Ok(Self {
            profile,
            user_id: user_id.to_owned(),
            secret,
            request,
        })
    }

    pub fn request(&self) -> &[u8] {
        &self.request
    }

    pub fn finish(mut self, response: &[u8]) -> Result<ProvisionedAccess, ProfileError> {
        if response.is_empty() || response.len() > 16_384 {
            return Err(ProfileError::ControlResponse);
        }
        let response = std::str::from_utf8(response).map_err(|_| ProfileError::ControlResponse)?;
        let response: CredentialAddResponse =
            toml::from_str(response).map_err(|_| ProfileError::ControlResponse)?;
        if response.status != "ok" || response.revision == 0 || response.user_id != self.user_id {
            return Err(ProfileError::ControlResponse);
        }
        let mut credential = encode_hex(&self.secret);
        let profile = self.profile.clone().with_credential(&credential)?;
        credential.zeroize();
        self.secret.zeroize();
        let uri = profile.to_uri()?;
        Ok(ProvisionedAccess {
            uri,
            user_id: response.user_id,
            revision: response.revision,
        })
    }
}

impl Drop for AccessProvisioning {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

#[derive(Serialize)]
struct CredentialAddRequest<'a> {
    method: &'static str,
    client_id: &'a str,
    seq: u64,
    user_id: &'a str,
    credential_sha256: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialAddResponse {
    status: String,
    revision: u64,
    user_id: String,
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

pub fn generate_client_config(
    profile: &Profile,
    root: &Path,
) -> Result<GeneratedClient, ProfileError> {
    profile.validate()?;
    if !root.is_absolute() {
        return Err(ProfileError::Path);
    }
    let config_directory = root.join("config");
    let module_directory = config_directory.join("modules");
    let secret_directory = root.join("secrets");
    let state_directory = root.join("state");
    let package_directory = root.join("packages");
    let mut files = Vec::new();
    let mut adapter_paths = Vec::new();
    let mut protection_path = None;
    let mut carrier_path = None;
    let mut policy_path = None;
    for module in &profile.modules {
        let path = module_directory.join(format!("{}.toml", module.instance));
        let mut options = module.options.clone();
        let package_name = module.package.rsplit_once('@').unwrap().0;
        match (module.class, package_name) {
            (ModuleClass::Protection, "owenewans/protection-noise") => {
                let pin_path = secret_directory.join("server-noise-key.hex");
                options.insert("mode".into(), "client".into());
                options.insert("server_public_key_file".into(), path_value(&pin_path)?);
                files.push(GeneratedFile {
                    path: pin_path,
                    contents: format!("{}\n", profile.server_pin).into_bytes(),
                    secret: true,
                });
            }
            (ModuleClass::Carrier, "owenewans/carrier-tcp")
            | (ModuleClass::Carrier, "owenewans/carrier-ssh") => {
                options.insert("mode".into(), "connect".into());
                options.insert("endpoint_ip".into(), profile.endpoint.clone().into());
            }
            (ModuleClass::Policy, "owenewans/policy-local") => {
                options.insert("server_id".into(), profile.server_id.clone().into());
                options.insert("credential_transport".into(), "protected".into());
                let storage = options
                    .entry("storage")
                    .or_insert_with(|| toml::Value::Table(toml::Table::new()));
                let storage = storage.as_table_mut().ok_or(ProfileError::Value)?;
                storage.insert(
                    "path".into(),
                    path_value(&state_directory.join("policy-client.redb"))?,
                );
                let mut credential = toml::Table::new();
                credential.insert("source".into(), "toml".into());
                credential.insert("value".into(), profile.credential.expose().into());
                let mut client = toml::Table::new();
                client.insert("credential".into(), toml::Value::Table(credential));
                options.insert("client".into(), toml::Value::Table(client));
            }
            _ => {}
        }
        let module_toml = module_toml(module, options)?;
        snolc::module_config::ModuleConfig::parse(&module_toml, &path)
            .map_err(|error| ProfileError::Generated(error.to_string()))?;
        files.push(GeneratedFile {
            path: path.clone(),
            contents: module_toml.into_bytes(),
            secret: module.class == ModuleClass::Policy,
        });
        match module.class {
            ModuleClass::Adapter => adapter_paths.push(path),
            ModuleClass::Protection => protection_path = Some(path),
            ModuleClass::Carrier => carrier_path = Some(path),
            ModuleClass::Policy => policy_path = Some(path),
        }
    }
    let main_path = config_directory.join("snolc.toml");
    let main_toml = main_toml(
        &package_directory,
        &state_directory,
        &adapter_paths,
        protection_path.as_deref().ok_or(ProfileError::Value)?,
        carrier_path.as_deref().ok_or(ProfileError::Value)?,
        policy_path.as_deref().ok_or(ProfileError::Value)?,
    )?;
    snolc::config::Config::parse(&main_toml, &config_directory)
        .map_err(|error| ProfileError::Generated(error.to_string()))?;
    Ok(GeneratedClient {
        main_path,
        main_toml,
        files,
    })
}

pub fn persist_client_config(
    generated: &GeneratedClient,
    root: &Path,
) -> Result<PathBuf, ProfileError> {
    if !root.is_absolute()
        || !generated.main_path.starts_with(root)
        || generated
            .files
            .iter()
            .any(|file| !file.path.starts_with(root))
    {
        return Err(ProfileError::Path);
    }
    secure_directory(root)?;
    for file in &generated.files {
        atomic_write(&file.path, &file.contents)?;
    }
    atomic_write(&generated.main_path, generated.main_toml.as_bytes())?;
    Ok(generated.main_path.clone())
}

pub fn install_bundled_modules(
    profile: &Profile,
    root: &Path,
    native_library_directory: &Path,
) -> Result<(), ProfileError> {
    profile.validate()?;
    if !root.is_absolute() || !native_library_directory.is_absolute() {
        return Err(ProfileError::Path);
    }
    let packages = root.join("packages");
    secure_directory(&packages)?;
    let mut installed = BTreeSet::new();
    for module in &profile.modules {
        if !installed.insert(module.package.clone()) {
            continue;
        }
        let (identity, version) = module.package.rsplit_once('@').ok_or(ProfileError::Value)?;
        let (owner, name) = identity.split_once('/').ok_or(ProfileError::Value)?;
        if owner != "owenewans" {
            continue;
        }
        let Some(library_name) = bundled_library_name(name) else {
            continue;
        };
        let source = native_library_directory.join(library_name);
        if !source.is_file() {
            return Err(ProfileError::BundledModule);
        }
        let hash = hash_file(&source)?;
        let store = packages
            .join("store")
            .join("bundled")
            .join(owner)
            .join(name)
            .join(version)
            .join(android_target())
            .join(&hash);
        let library = store.join(library_name);
        if library.exists() {
            if hash_file(&library)? != hash {
                return Err(ProfileError::BundledModule);
            }
        } else {
            atomic_copy(&source, &library)?;
        }
        let mut lock = toml::Table::new();
        lock.insert("wire_version".into(), 1.into());
        lock.insert("package".into(), module.package.clone().into());
        lock.insert("target".into(), android_target().into());
        lock.insert("content_sha256".into(), hash.into());
        lock.insert("library".into(), path_value(&library)?);
        lock.insert("store".into(), path_value(&store)?);
        lock.insert("dependencies".into(), toml::Value::Array(Vec::new()));
        let lock_path = packages
            .join("locks")
            .join(owner)
            .join(name)
            .join(format!("{version}.toml"));
        atomic_write(&lock_path, toml::to_string(&lock)?.as_bytes())?;
    }
    Ok(())
}

fn bundled_library_name(package: &str) -> Option<&'static str> {
    match package {
        "adapter-tun" => Some("libsnolc_adapter_tun.so"),
        "adapter-socks5" => Some("libsnolc_adapter_socks5.so"),
        "adapter-http-connect" => Some("libsnolc_adapter_http_connect.so"),
        "adapter-direct" => Some("libsnolc_adapter_direct.so"),
        "protection-dummy" => Some("libsnolc_protection_dummy.so"),
        "protection-noise" => Some("libsnolc_protection_noise.so"),
        "carrier-tcp" => Some("libsnolc_carrier_tcp.so"),
        "carrier-ssh" => Some("libsnolc_carrier_ssh.so"),
        "policy-dummy" => Some("libsnolc_policy_dummy.so"),
        "policy-local" => Some("libsnolc_policy_local.so"),
        _ => None,
    }
}

fn android_target() -> &'static str {
    #[cfg(target_arch = "aarch64")]
    return "aarch64-linux-android";
    #[cfg(target_arch = "arm")]
    return "armv7-linux-androideabi";
    #[cfg(not(any(target_arch = "aarch64", target_arch = "arm")))]
    "android-test"
}

fn atomic_copy(source: &Path, destination: &Path) -> Result<(), ProfileError> {
    let parent = destination.parent().ok_or(ProfileError::Path)?;
    secure_directory(parent)?;
    let name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(ProfileError::Path)?;
    let temporary = parent.join(format!(
        ".{name}.{}-{}.tmp",
        std::process::id(),
        TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        let mut input = File::open(source)?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        std::io::copy(&mut input, &mut output)?;
        output.sync_all()?;
        fs::rename(&temporary, destination)?;
        readonly_file(destination)?;
        File::open(parent)?.sync_all()?;
        Ok::<(), std::io::Error>(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result.map_err(ProfileError::Io)
}

fn readonly_file(path: &Path) -> Result<(), std::io::Error> {
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_readonly(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        permissions.set_mode(0o400);
    }
    fs::set_permissions(path, permissions)
}

fn hash_file(path: &Path) -> Result<String, ProfileError> {
    let mut input = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 16 * 1024];
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(encode_hex(&hasher.finalize()))
}

fn encode_hex(input: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(input.len() * 2);
    for byte in input {
        output.push(DIGITS[usize::from(byte >> 4)] as char);
        output.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    output
}

fn atomic_write(path: &Path, contents: &[u8]) -> Result<(), ProfileError> {
    let parent = path.parent().ok_or(ProfileError::Path)?;
    secure_directory(parent)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(ProfileError::Path)?;
    let temporary = parent.join(format!(
        ".{name}.{}-{}.tmp",
        std::process::id(),
        TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        secure_file(&temporary)?;
        file.write_all(contents)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        secure_file(path)?;
        File::open(parent)?.sync_all()?;
        Ok::<(), std::io::Error>(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result.map_err(ProfileError::Io)
}

fn secure_directory(path: &Path) -> Result<(), std::io::Error> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn secure_file(path: &Path) -> Result<(), std::io::Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn module_toml(module: &ProfileModule, options: toml::Table) -> Result<String, ProfileError> {
    let mut table = toml::Table::new();
    table.insert("wire_version".into(), 1.into());
    table.insert("instance".into(), module.instance.clone().into());
    table.insert("package".into(), module.package.clone().into());
    table.insert("role".into(), "client".into());
    table.insert("options".into(), toml::Value::Table(options));
    toml::to_string(&table).map_err(Into::into)
}

fn main_toml(
    packages: &Path,
    state: &Path,
    adapters: &[PathBuf],
    protection: &Path,
    carrier: &Path,
    policy: &Path,
) -> Result<String, ProfileError> {
    let mut root = toml::Table::new();
    root.insert("wire_version".into(), 1.into());
    root.insert(
        "paths".into(),
        table_value([
            ("packages", path_value(packages)?),
            ("state", path_value(state)?),
        ]),
    );
    root.insert(
        "engine".into(),
        table_value([
            ("max_sessions", 2.into()),
            ("max_flows", 32.into()),
            ("max_pending_sessions", 2.into()),
            ("max_pending_opens", 8.into()),
            ("max_managed_bytes", 33_554_432.into()),
            ("max_commands", 64.into()),
            ("max_events", 256.into()),
            ("max_io_chunk", 16_384.into()),
            ("max_ingress_packets_per_tick", 32.into()),
            ("connect_timeout_ms", 15_000.into()),
            ("handshake_timeout_ms", 15_000.into()),
            ("shutdown_timeout_ms", 5_000.into()),
        ]),
    );
    root.insert(
        "stack".into(),
        table_value([
            ("ipv4", true.into()),
            ("ipv6", true.into()),
            ("mtu", 1_280.into()),
            ("tcp_socket_rx_bytes", 16_384.into()),
            ("tcp_socket_tx_bytes", 16_384.into()),
            ("udp_socket_rx_bytes", 131_072.into()),
            ("udp_socket_tx_bytes", 131_072.into()),
            ("udp_metadata_slots", 8.into()),
            ("packet_queue_bytes", 262_144.into()),
            ("max_udp_payload_bytes", 65_507.into()),
            ("reassembly_slots", 4.into()),
            ("reassembly_timeout_ms", 15_000.into()),
        ]),
    );
    root.insert(
        "yamux".into(),
        table_value([
            ("max_streams_per_session", 17.into()),
            ("receive_window_bytes", 4_456_448.into()),
            ("split_send_size", 16_384.into()),
            ("read_after_close", true.into()),
        ]),
    );
    root.insert(
        "logging".into(),
        table_value([
            ("mode", "file".into()),
            ("source", "toml".into()),
            (
                "levels",
                toml::Value::Array(vec!["warning".into(), "error".into(), "debug".into()]),
            ),
            ("file", path_value(&state.join("snolc.log"))?),
            ("limit", "8mb".into()),
            ("queue_bytes", 65_536.into()),
            ("max_record_bytes", 2_048.into()),
            ("flush_interval_ms", 1_000.into()),
            ("on_io_error", "event".into()),
        ]),
    );
    root.insert("control".into(), table_value([("mode", "off".into())]));
    let mut tunnel = toml::Table::new();
    tunnel.insert("name".into(), "main".into());
    tunnel.insert("role".into(), "client".into());
    tunnel.insert(
        "adapters".into(),
        toml::Value::Array(
            adapters
                .iter()
                .map(|path| path_value(path))
                .collect::<Result<_, _>>()?,
        ),
    );
    tunnel.insert("protection".into(), path_value(protection)?);
    tunnel.insert("carrier".into(), path_value(carrier)?);
    tunnel.insert("policy".into(), path_value(policy)?);
    root.insert(
        "tunnels".into(),
        toml::Value::Array(vec![toml::Value::Table(tunnel)]),
    );
    toml::to_string(&root).map_err(Into::into)
}

fn table_value<const N: usize>(entries: [(&str, toml::Value); N]) -> toml::Value {
    toml::Value::Table(
        entries
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}

fn path_value(path: &Path) -> Result<toml::Value, ProfileError> {
    path.to_str()
        .map(|path| path.to_owned().into())
        .ok_or(ProfileError::Path)
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
        ) || key.ends_with("_path")
            || key.ends_with("_file")
            || key.ends_with("_directory")
            || match value {
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
    #[error("client path is invalid")]
    Path,
    #[error("generated configuration is invalid: {0}")]
    Generated(String),
    #[error("server_id is already imported")]
    DuplicateServer,
    #[error("profile selection is invalid")]
    Selection,
    #[error("native package requires approval")]
    PackageApproval,
    #[error("bundled native module is unavailable or invalid")]
    BundledModule,
    #[error("credential generation failed")]
    Random,
    #[error("provisioning input is invalid")]
    Provisioning,
    #[error("policy control response is invalid")]
    ControlResponse,
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

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

    fn provision_profile() -> ProvisionProfile {
        let profile = profile();
        ProvisionProfile {
            wire_version: profile.wire_version,
            server_id: profile.server_id.clone(),
            endpoint: profile.endpoint.clone(),
            modules: profile.modules.clone(),
            server_pin: profile.server_pin.clone(),
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
            .insert("server_public_key_file".into(), "/etc/passwd".into());
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
    fn provision_profile_serialization_excludes_the_credential() {
        let profile = profile();
        let metadata = ProvisionProfile::from_profile(&profile);
        let encoded = toml::to_string(&metadata).unwrap();
        assert!(!encoded.contains(profile.credential.expose()));
        assert!(!encoded.contains("credential"));
        assert_eq!(ProvisionProfile::parse_toml(&encoded).unwrap(), metadata);
    }

    #[test]
    fn provisioning_registers_only_the_digest_and_returns_one_profile() {
        let user_id = "00112233445566778899aabbccddeeff";
        let provisioning =
            AccessProvisioning::new(provision_profile(), user_id, "panel", 7).unwrap();
        let request: toml::Value =
            toml::from_str(std::str::from_utf8(provisioning.request()).unwrap()).unwrap();
        assert_eq!(request["method"].as_str(), Some("credential.add"));
        assert_eq!(request["client_id"].as_str(), Some("panel"));
        assert_eq!(request["seq"].as_integer(), Some(7));
        assert_eq!(request["user_id"].as_str(), Some(user_id));
        let digest = request["credential_sha256"].as_str().unwrap().to_owned();
        assert_eq!(digest.len(), 64);

        let access = provisioning
            .finish(format!("status = \"ok\"\nrevision = 2\nuser_id = \"{user_id}\"\n").as_bytes())
            .unwrap();
        let profile = Profile::from_uri(&access.uri).unwrap();
        assert_eq!(access.user_id, user_id);
        assert_eq!(access.revision, 2);
        assert_eq!(profile.credential.expose().len(), 64);
        let (pairs, remainder) = profile.credential.expose().as_bytes().as_chunks::<2>();
        assert!(remainder.is_empty());
        let credential = pairs
            .iter()
            .map(|pair| {
                let pair = std::str::from_utf8(pair).unwrap();
                u8::from_str_radix(pair, 16).unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(encode_hex(&Sha256::digest(credential)), digest);
        assert!(!access.uri.contains(profile.credential.expose()));
    }

    #[test]
    fn provisioning_rejects_mismatched_or_extended_control_responses() {
        let user_id = "00112233445566778899aabbccddeeff";
        let provisioning =
            AccessProvisioning::new(provision_profile(), user_id, "panel", 1).unwrap();
        assert!(matches!(
            provisioning.finish(
                b"status = \"ok\"\nrevision = 2\nuser_id = \"ffeeddccbbaa99887766554433221100\"\n"
            ),
            Err(ProfileError::ControlResponse)
        ));

        let provisioning =
            AccessProvisioning::new(provision_profile(), user_id, "panel", 2).unwrap();
        assert!(matches!(
            provisioning.finish(
                b"status = \"ok\"\nrevision = 2\nuser_id = \"00112233445566778899aabbccddeeff\"\nsecret = \"leak\"\n"
            ),
            Err(ProfileError::ControlResponse)
        ));
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

    #[test]
    fn generated_client_config_passes_runtime_parser_and_keeps_paths_local() {
        let mut profile = profile();
        profile.modules[1].package = "owenewans/protection-noise@0.0.1".into();
        profile.modules[2].package = "owenewans/carrier-tcp@0.0.1".into();
        profile.modules[3].package = "owenewans/policy-local@0.0.1".into();
        let generated = generate_client_config(&profile, Path::new("/tmp/snolcNG-client")).unwrap();
        assert!(!generated.main_toml.contains(profile.credential.expose()));
        assert!(
            generated
                .files
                .iter()
                .any(|file| file.path.ends_with("server-noise-key.hex") && file.secret)
        );
        assert!(generated.files.iter().any(|file| {
            file.path.ends_with("policy.toml")
                && file.secret
                && String::from_utf8_lossy(&file.contents).contains(profile.credential.expose())
        }));
    }

    #[test]
    fn persisted_client_config_is_atomic_and_private() {
        let root = std::env::temp_dir().join(format!(
            "snolcNG-persist-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut profile = profile();
        profile.modules[1].package = "owenewans/protection-noise@0.0.1".into();
        profile.modules[2].package = "owenewans/carrier-tcp@0.0.1".into();
        profile.modules[3].package = "owenewans/policy-local@0.0.1".into();
        let generated = generate_client_config(&profile, &root).unwrap();
        let main = persist_client_config(&generated, &root).unwrap();
        assert_eq!(fs::read_to_string(main).unwrap(), generated.main_toml);
        assert_eq!(
            fs::read_to_string(root.join("secrets/server-noise-key.hex")).unwrap(),
            "server-pin\n"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&root).unwrap().permissions().mode() & 0o777,
                0o700
            );
            for file in generated
                .files
                .iter()
                .map(|file| &file.path)
                .chain(std::iter::once(&generated.main_path))
            {
                assert_eq!(
                    fs::metadata(file).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }
        assert!(!fs::read_dir(root.join("config")).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")
        }));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn bundled_modules_get_content_addressed_locks() {
        let root = std::env::temp_dir().join(format!(
            "snolcNG-bundled-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let native = root.join("native");
        fs::create_dir_all(&native).unwrap();
        let mut profile = profile();
        for (module, name) in profile.modules.iter_mut().zip([
            "adapter-tun",
            "protection-noise",
            "carrier-tcp",
            "policy-local",
        ]) {
            module.package = format!("owenewans/{name}@0.0.1");
            fs::write(
                native.join(bundled_library_name(name).unwrap()),
                format!("module:{name}"),
            )
            .unwrap();
        }
        install_bundled_modules(&profile, &root, &native).unwrap();
        for module in &profile.modules {
            let (identity, version) = module.package.rsplit_once('@').unwrap();
            let (owner, name) = identity.split_once('/').unwrap();
            let lock = root
                .join("packages/locks")
                .join(owner)
                .join(name)
                .join(format!("{version}.toml"));
            let lock: toml::Value = toml::from_str(&fs::read_to_string(lock).unwrap()).unwrap();
            assert_eq!(lock["package"].as_str(), Some(module.package.as_str()));
            assert_eq!(lock["content_sha256"].as_str().unwrap().len(), 64);
            let library = Path::new(lock["library"].as_str().unwrap());
            assert!(library.is_file());
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    fs::metadata(library).unwrap().permissions().mode() & 0o777,
                    0o400
                );
            }
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn app_state_requires_package_approval_and_marks_disconnected_status_stale() {
        let profile = profile();
        let uri = profile.to_uri().unwrap();
        let mut app = AppState::default();
        let trusted = BTreeSet::from([
            "owenewans/tun@0.0.1".into(),
            "owenewans/noise@0.0.1".into(),
            "owenewans/tcp@0.0.1".into(),
        ]);
        app.import_profile(&uri, "clipboard".into(), &trusted)
            .unwrap();
        assert!(matches!(
            app.begin_connect(),
            Err(ProfileError::PackageApproval)
        ));
        app.approve_package("owenewans/policy@0.0.1").unwrap();
        app.begin_connect().unwrap();
        app.connected();
        app.apply_status(ServerStatus {
            used_bytes: 12,
            limit_bytes: Some(100),
            upload_bytes_per_second: Some(10),
            download_bytes_per_second: Some(20),
            expires_at: None,
            revision: 2,
            reason: None,
            stale: true,
        });
        app.apply_status(ServerStatus {
            used_bytes: 1,
            limit_bytes: Some(100),
            upload_bytes_per_second: None,
            download_bytes_per_second: None,
            expires_at: None,
            revision: 1,
            reason: None,
            stale: false,
        });
        assert_eq!(app.status.as_ref().unwrap().used_bytes, 12);
        app.stopped("revoked".into());
        assert!(app.status.as_ref().unwrap().stale);
        assert!(
            matches!(app.connection, ConnectionState::Stopped(ref reason) if reason == "revoked")
        );
        assert!(app.take_repaint_request());
        assert!(!app.take_repaint_request());
    }
}
