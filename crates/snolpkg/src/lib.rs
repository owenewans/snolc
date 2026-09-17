use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::sync::atomic::AtomicBool;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, VerifyingKey};
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tar::Archive;
use thiserror::Error;

pub const MAX_MANIFEST_BYTES: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExtractLimits {
    pub max_files: usize,
    pub max_total_bytes: u64,
    pub max_file_bytes: u64,
}

impl ExtractLimits {
    pub fn validate(self) -> Result<(), PackageError> {
        if self.max_files == 0 || self.max_total_bytes == 0 || self.max_file_bytes == 0 {
            return Err(PackageError::ExtractLimit);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExtractReport {
    pub files: usize,
    pub total_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Publication {
    pub revision: String,
    pub manifest_bytes: Vec<u8>,
    pub signature_bytes: Vec<u8>,
    pub manifest: PublicationManifest,
}

#[derive(Clone, Debug)]
pub struct InstallOptions {
    pub root: PathBuf,
    pub target: String,
    pub limits: ExtractLimits,
    pub offline: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstallResult {
    pub package: String,
    pub store: PathBuf,
    pub lock: PathBuf,
}

#[derive(Serialize)]
struct PackageLock<'a> {
    wire_version: u32,
    package: &'a str,
    target: &'a str,
    content_sha256: String,
    library: &'a Path,
    store: &'a Path,
    dependencies: &'a [Dependency],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredLock {
    wire_version: u32,
    package: String,
    target: String,
    content_sha256: String,
    library: PathBuf,
    store: PathBuf,
    dependencies: Vec<Dependency>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationManifest {
    pub name: String,
    pub authors: Vec<String>,
    pub license: String,
    pub package_version: String,
    pub wire_version: u32,
    pub classes: Vec<String>,
    pub family: String,
    pub entry: PathBuf,
    pub dependencies: Vec<Dependency>,
    pub source: SourceRevision,
    pub toolchain: String,
    pub build: BuildRecipe,
    pub artifacts: Vec<Artifact>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Dependency {
    pub package: String,
    pub version: String,
    pub content_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRevision {
    pub revision: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BuildRecipe {
    pub package: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub target: String,
    pub minimum_isa: String,
    pub minimum_libc: Option<String>,
    pub minimum_android_api: Option<u32>,
    pub url: String,
    pub byte_size: u64,
    pub sha256: String,
    pub build_output: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Sources {
    pub sources: Vec<TrustedSource>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TrustedSource {
    pub id: String,
    pub git: String,
    pub trust: TrustMode,
    pub public_key: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum TrustMode {
    Signed,
    LocalDevelopment,
}

impl PublicationManifest {
    pub fn parse(bytes: &[u8]) -> Result<Self, PackageError> {
        if bytes.is_empty() || bytes.len() > MAX_MANIFEST_BYTES {
            return Err(PackageError::ManifestSize);
        }
        let text = std::str::from_utf8(bytes).map_err(|_| PackageError::ManifestUtf8)?;
        let manifest: Self = toml::from_str(text)?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<(), PackageError> {
        if self.name.is_empty()
            || self.authors.is_empty()
            || self.authors.iter().any(|author| author.is_empty())
            || self.license.is_empty()
            || self.package_version.is_empty()
            || self.family.is_empty()
            || self.toolchain.is_empty()
            || self.build.package.is_empty()
            || self.source.revision.is_empty()
            || self.wire_version != 1
        {
            return Err(PackageError::ManifestValue);
        }
        if self.source.revision.len() != 40
            || self
                .source
                .revision
                .bytes()
                .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(PackageError::ManifestValue);
        }
        validate_package_name(&self.name)?;
        validate_relative_path(&self.entry)?;
        if self.classes.is_empty() || self.artifacts.is_empty() {
            return Err(PackageError::ManifestValue);
        }
        let mut classes = BTreeSet::new();
        for class in &self.classes {
            if !matches!(
                class.as_str(),
                "adapter" | "protection" | "carrier" | "policy"
            ) || !classes.insert(class)
            {
                return Err(PackageError::ManifestValue);
            }
        }
        let mut dependencies = BTreeSet::new();
        for dependency in &self.dependencies {
            validate_package_name(&dependency.package)?;
            validate_sha256(&dependency.content_sha256)?;
            if dependency.version.is_empty() || !dependencies.insert(&dependency.package) {
                return Err(PackageError::ManifestValue);
            }
        }
        let mut targets = BTreeSet::new();
        for artifact in &self.artifacts {
            validate_sha256(&artifact.sha256)?;
            validate_relative_path(&artifact.build_output)?;
            if artifact.target.is_empty()
                || artifact.minimum_isa.is_empty()
                || artifact.byte_size == 0
                || !(artifact.url.starts_with("https://") || artifact.url.starts_with("file:///"))
                || !targets.insert(&artifact.target)
            {
                return Err(PackageError::ManifestValue);
            }
            if artifact.target.contains("android") != artifact.minimum_android_api.is_some() {
                return Err(PackageError::ManifestValue);
            }
        }
        Ok(())
    }
}

impl Sources {
    pub fn parse(input: &str) -> Result<Self, PackageError> {
        let sources: Self = toml::from_str(input)?;
        if sources.sources.is_empty() {
            return Err(PackageError::SourceValue);
        }
        let mut ids = BTreeSet::new();
        for source in &sources.sources {
            if source.id.is_empty() || source.git.is_empty() || !ids.insert(&source.id) {
                return Err(PackageError::SourceValue);
            }
            match source.trust {
                TrustMode::Signed => {
                    let key = source
                        .public_key
                        .as_deref()
                        .ok_or(PackageError::SourceValue)?;
                    let _: [u8; 32] = decode_hex(key)?.try_into().map_err(|_| PackageError::Key)?;
                }
                TrustMode::LocalDevelopment => {
                    if source.public_key.is_some() || !Path::new(&source.git).is_absolute() {
                        return Err(PackageError::SourceValue);
                    }
                }
            }
        }
        Ok(sources)
    }

    pub fn find(&self, git: &str) -> Result<&TrustedSource, PackageError> {
        self.sources
            .iter()
            .find(|source| source.git == git)
            .ok_or(PackageError::UntrustedSource)
    }
}

pub fn verify_manifest(
    manifest_bytes: &[u8],
    signature_bytes: &[u8],
    source: &TrustedSource,
) -> Result<(), PackageError> {
    if source.trust != TrustMode::Signed {
        return Err(PackageError::SignaturePolicy);
    }
    let key: [u8; 32] = decode_hex(
        source
            .public_key
            .as_deref()
            .ok_or(PackageError::SourceValue)?,
    )?
    .try_into()
    .map_err(|_| PackageError::Key)?;
    let signature: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| PackageError::Signature)?;
    let key = VerifyingKey::from_bytes(&key).map_err(|_| PackageError::Key)?;
    key.verify_strict(manifest_bytes, &Signature::from_bytes(&signature))
        .map_err(|_| PackageError::Signature)
}

pub fn validate_relative_path(path: &Path) -> Result<(), PackageError> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(PackageError::Path);
    }
    Ok(())
}

pub fn extract_tar_gz<R: Read>(
    input: R,
    staging: &Path,
    limits: ExtractLimits,
) -> Result<ExtractReport, PackageError> {
    limits.validate()?;
    fs::create_dir_all(staging)?;
    if fs::read_dir(staging)?.next().is_some() {
        return Err(PackageError::StagingNotEmpty);
    }
    let mut archive = Archive::new(GzDecoder::new(input));
    let mut paths = BTreeSet::new();
    let mut files = 0usize;
    let mut total_bytes = 0u64;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        validate_relative_path(&path)?;
        if !paths.insert(path.clone()) {
            return Err(PackageError::DuplicatePath);
        }
        let kind = entry.header().entry_type();
        if kind.is_dir() {
            fs::create_dir_all(staging.join(path))?;
            continue;
        }
        if !kind.is_file() {
            return Err(PackageError::ArchiveType);
        }
        let mode = entry.header().mode()?;
        if mode & 0o6000 != 0 {
            return Err(PackageError::ArchiveMode);
        }
        let size = entry.header().size()?;
        files = files.checked_add(1).ok_or(PackageError::ExtractLimit)?;
        total_bytes = total_bytes
            .checked_add(size)
            .ok_or(PackageError::ExtractLimit)?;
        if files > limits.max_files
            || size > limits.max_file_bytes
            || total_bytes > limits.max_total_bytes
        {
            return Err(PackageError::ExtractLimit);
        }
        let destination = staging.join(path);
        let parent = destination.parent().ok_or(PackageError::Path)?;
        fs::create_dir_all(parent)?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination)?;
        let written = io::copy(&mut entry, &mut output)?;
        if written != size {
            return Err(PackageError::ArchiveSize);
        }
    }
    Ok(ExtractReport { files, total_bytes })
}

pub fn load_publication(
    git: &str,
    module_name: &str,
    clone_directory: &Path,
) -> Result<Publication, PackageError> {
    validate_module_name(module_name)?;
    if git.starts_with("https://") {
        if clone_directory.exists() {
            return Err(PackageError::CloneDirectory);
        }
        let mut prepare = gix::prepare_clone_bare(git, clone_directory)
            .map_err(|error| PackageError::Git(error.to_string()))?;
        let interrupt = AtomicBool::new(false);
        let (repository, _) = prepare
            .fetch_only(gix::progress::Discard, &interrupt)
            .map_err(|error| PackageError::Git(error.to_string()))?;
        read_publication(&repository, module_name)
    } else {
        let path = Path::new(git);
        if !path.is_absolute() {
            return Err(PackageError::GitSource);
        }
        let repository = gix::open(path).map_err(|error| PackageError::Git(error.to_string()))?;
        read_publication(&repository, module_name)
    }
}

pub fn checkout_revision(
    git: &str,
    revision: &str,
    destination: &Path,
) -> Result<String, PackageError> {
    if destination.exists() {
        return Err(PackageError::CloneDirectory);
    }
    if !(git.starts_with("https://") || Path::new(git).is_absolute()) {
        return Err(PackageError::GitSource);
    }
    if revision.len() != 40
        || revision
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(PackageError::ManifestValue);
    }
    let prepare = gix::prepare_clone(git, destination)
        .map_err(|error| PackageError::Git(error.to_string()))?;
    let mut prepare = prepare
        .with_revision(Some(revision))
        .map_err(|error| PackageError::Git(error.to_string()))?;
    let interrupt = AtomicBool::new(false);
    let (mut checkout, _) = prepare
        .fetch_then_checkout(gix::progress::Discard, &interrupt)
        .map_err(|error| PackageError::Git(error.to_string()))?;
    let (repository, _) = checkout
        .main_worktree(gix::progress::Discard, &interrupt)
        .map_err(|error| PackageError::Git(error.to_string()))?;
    let actual = repository
        .head_commit()
        .map_err(|error| PackageError::Git(error.to_string()))?
        .id()
        .to_string();
    if actual != revision {
        return Err(PackageError::Revision);
    }
    Ok(actual)
}

pub fn install_binary(
    git: &str,
    module_name: &str,
    options: &InstallOptions,
) -> Result<InstallResult, PackageError> {
    if !options.root.is_absolute() || options.target.is_empty() {
        return Err(PackageError::InstallOptions);
    }
    options.limits.validate()?;
    fs::create_dir_all(&options.root)?;
    let install_lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(options.root.join(".install.lock"))?;
    install_lock.lock()?;
    let sources = Sources::parse(&fs::read_to_string(options.root.join("sources.toml"))?)?;
    let source = sources.find(git)?;
    let staging = Staging::new(&options.root)?;
    if options.offline && git.starts_with("https://") {
        return Err(PackageError::OfflineNetwork);
    }
    let publication = load_publication(git, module_name, &staging.path.join("repository"))?;
    if source.trust == TrustMode::Signed {
        verify_manifest(
            &publication.manifest_bytes,
            &publication.signature_bytes,
            source,
        )?;
    }
    let package_module = publication
        .manifest
        .name
        .split_once('/')
        .map(|(_, module)| module)
        .ok_or(PackageError::ManifestValue)?;
    if package_module != module_name {
        return Err(PackageError::ManifestValue);
    }
    validate_dependencies(&options.root, &publication.manifest.dependencies)?;
    let artifact = publication
        .manifest
        .artifacts
        .iter()
        .find(|artifact| artifact.target == options.target)
        .ok_or(PackageError::Target)?;
    if options.offline && artifact.url.starts_with("https://") {
        return Err(PackageError::OfflineNetwork);
    }
    let archive_path = staging.path.join("artifact.tar.gz");
    download_artifact(artifact, &archive_path)?;
    let content = staging.path.join("content");
    extract_tar_gz(File::open(&archive_path)?, &content, options.limits)?;
    install_extracted(&publication.manifest, source, artifact, &content, options)
}

pub fn install_source(
    git: &str,
    module_name: &str,
    options: &InstallOptions,
) -> Result<InstallResult, PackageError> {
    if !options.root.is_absolute() || options.target.is_empty() {
        return Err(PackageError::InstallOptions);
    }
    options.limits.validate()?;
    fs::create_dir_all(&options.root)?;
    let install_lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(options.root.join(".install.lock"))?;
    install_lock.lock()?;
    let sources = Sources::parse(&fs::read_to_string(options.root.join("sources.toml"))?)?;
    let source = sources.find(git)?;
    let staging = Staging::new(&options.root)?;
    if options.offline && git.starts_with("https://") {
        return Err(PackageError::OfflineNetwork);
    }
    let publication = load_publication(git, module_name, &staging.path.join("publication"))?;
    if source.trust == TrustMode::Signed {
        verify_manifest(
            &publication.manifest_bytes,
            &publication.signature_bytes,
            source,
        )?;
    }
    let package_module = publication
        .manifest
        .name
        .split_once('/')
        .map(|(_, module)| module)
        .ok_or(PackageError::ManifestValue)?;
    if package_module != module_name {
        return Err(PackageError::ManifestValue);
    }
    validate_dependencies(&options.root, &publication.manifest.dependencies)?;
    let artifact = publication
        .manifest
        .artifacts
        .iter()
        .find(|artifact| artifact.target == options.target)
        .ok_or(PackageError::Target)?;
    let source_tree = staging.path.join("source");
    checkout_revision(git, &publication.manifest.source.revision, &source_tree)?;
    let build_directory = staging.path.join("build");
    let status = Command::new("rustup")
        .arg("run")
        .arg(&publication.manifest.toolchain)
        .arg("cargo")
        .arg("build")
        .arg("--release")
        .arg("--locked")
        .arg("--package")
        .arg(&publication.manifest.build.package)
        .arg("--target")
        .arg(&artifact.target)
        .current_dir(&source_tree)
        .env("CARGO_TARGET_DIR", &build_directory)
        .status()?;
    if !status.success() {
        return Err(PackageError::Build(status.code()));
    }
    let built = build_directory
        .join(&artifact.target)
        .join(&artifact.build_output);
    let metadata = fs::metadata(&built)?;
    if !metadata.is_file() || metadata.len() > options.limits.max_file_bytes {
        return Err(PackageError::Entry);
    }
    let content = staging.path.join("content");
    let entry = content.join(&publication.manifest.entry);
    fs::create_dir_all(entry.parent().ok_or(PackageError::Path)?)?;
    fs::copy(&built, &entry)?;
    copy_notices(&source_tree, &content)?;
    install_extracted(&publication.manifest, source, artifact, &content, options)
}

fn copy_notices(source: &Path, content: &Path) -> Result<(), PackageError> {
    for name in [
        "LICENSE",
        "LICENSE.md",
        "LICENSE.txt",
        "NOTICE",
        "NOTICE.md",
        "NOTICE.txt",
    ] {
        let input = source.join(name);
        if input.is_file() {
            fs::copy(input, content.join(name))?;
        }
    }
    Ok(())
}

fn download_artifact(artifact: &Artifact, output: &Path) -> Result<(), PackageError> {
    let mut input: Box<dyn Read> = if let Some(path) = artifact.url.strip_prefix("file://") {
        let path = Path::new(path);
        if !path.is_absolute() {
            return Err(PackageError::Download("file URL is not absolute".into()));
        }
        Box::new(File::open(path)?)
    } else {
        let client = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .map_err(|error| PackageError::Download(error.to_string()))?;
        let response = client
            .get(&artifact.url)
            .send()
            .and_then(reqwest::blocking::Response::error_for_status)
            .map_err(|error| PackageError::Download(error.to_string()))?;
        if response
            .content_length()
            .is_some_and(|length| length != artifact.byte_size)
        {
            return Err(PackageError::ArtifactSize);
        }
        Box::new(response)
    };
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)?;
    let mut output = BufWriter::new(file);
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0; 16 * 1024];
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or(PackageError::ArtifactSize)?;
        if total > artifact.byte_size {
            return Err(PackageError::ArtifactSize);
        }
        hasher.update(&buffer[..read]);
        output.write_all(&buffer[..read])?;
    }
    output.flush()?;
    output.get_ref().sync_all()?;
    if total != artifact.byte_size || encode_hex(&hasher.finalize()) != artifact.sha256 {
        return Err(PackageError::ArtifactHash);
    }
    Ok(())
}

fn install_extracted(
    manifest: &PublicationManifest,
    source: &TrustedSource,
    artifact: &Artifact,
    content: &Path,
    options: &InstallOptions,
) -> Result<InstallResult, PackageError> {
    let entry = content.join(&manifest.entry);
    if !entry.is_file() {
        return Err(PackageError::Entry);
    }
    let library_hash = hash_file(&entry)?;
    let (owner, name) = manifest
        .name
        .split_once('/')
        .ok_or(PackageError::ManifestValue)?;
    let source_hash = encode_hex(&Sha256::digest(source.git.as_bytes()));
    let store = options
        .root
        .join("store")
        .join(source_hash)
        .join(owner)
        .join(name)
        .join(&manifest.package_version)
        .join(&artifact.target)
        .join(&library_hash);
    fs::create_dir_all(store.parent().ok_or(PackageError::Path)?)?;
    if store.exists() {
        let existing = store.join(&manifest.entry);
        if !existing.is_file() || hash_file(&existing)? != library_hash {
            return Err(PackageError::StoreConflict);
        }
    } else {
        fs::rename(content, &store)?;
        make_readonly(&store)?;
    }
    let library = store.join(&manifest.entry).canonicalize()?;
    let package = format!("{}@{}", manifest.name, manifest.package_version);
    let lock = options
        .root
        .join("locks")
        .join(owner)
        .join(name)
        .join(format!("{}.toml", manifest.package_version));
    let lock_data = toml::to_string(&PackageLock {
        wire_version: manifest.wire_version,
        package: &package,
        target: &artifact.target,
        content_sha256: library_hash,
        library: &library,
        store: &store,
        dependencies: &manifest.dependencies,
    })?;
    atomic_write(&lock, lock_data.as_bytes())?;
    Ok(InstallResult {
        package,
        store,
        lock,
    })
}

pub fn delete_package(root: &Path, package: &str) -> Result<(), PackageError> {
    if !root.is_absolute() {
        return Err(PackageError::InstallOptions);
    }
    let (owner, name, version) = parse_package_identity(package)?;
    let install_lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(root.join(".install.lock"))
        .map_err(|error| PackageError::IoAt("open install lock", error))?;
    install_lock
        .lock()
        .map_err(|error| PackageError::IoAt("lock installer", error))?;
    let lock_path = root
        .join("locks")
        .join(owner)
        .join(name)
        .join(format!("{version}.toml"));
    let target = read_stored_lock(&lock_path)?;
    if target.package != package {
        return Err(PackageError::Lock);
    }
    for candidate in lock_files(&root.join("locks"))? {
        if candidate == lock_path {
            continue;
        }
        let lock = read_stored_lock(&candidate)?;
        if lock.dependencies.iter().any(|dependency| {
            dependency.package == format!("{owner}/{name}") && dependency.version == version
        }) {
            return Err(PackageError::ReverseDependency(lock.package));
        }
    }
    let store_root = root.join("store").canonicalize()?;
    let store = target.store.canonicalize()?;
    let library = target.library.canonicalize()?;
    if !store.starts_with(&store_root) || !library.starts_with(&store) {
        return Err(PackageError::Lock);
    }
    let staging = Staging::new(root)?;
    let trash = staging.path.join("package");
    set_directory_mutable(&store)?;
    if let Err(error) = fs::rename(&store, &trash) {
        let _ = set_directory_readonly(&store);
        return Err(PackageError::IoAt("move package to staging", error));
    }
    if let Err(error) = fs::remove_file(&lock_path) {
        let _ = fs::rename(&trash, &store);
        let _ = set_directory_readonly(&store);
        return Err(error.into());
    }
    make_mutable(&trash).map_err(|error| match error {
        PackageError::Io(error) => PackageError::IoAt("make package mutable", error),
        error => error,
    })?;
    fs::remove_dir_all(&trash).map_err(|error| PackageError::IoAt("remove package", error))?;
    Ok(())
}

pub fn write_template(
    root: &Path,
    package: &str,
    role: &str,
    output: &Path,
) -> Result<(), PackageError> {
    if !root.is_absolute() || output.as_os_str().is_empty() {
        return Err(PackageError::InstallOptions);
    }
    validate_module_name(role)?;
    let (owner, name, version) = parse_package_identity(package)?;
    let install_lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(root.join(".install.lock"))?;
    install_lock.lock()?;
    let lock_path = root
        .join("locks")
        .join(owner)
        .join(name)
        .join(format!("{version}.toml"));
    let lock = read_stored_lock(&lock_path)?;
    if lock.package != package {
        return Err(PackageError::Lock);
    }
    let store_root = root.join("store").canonicalize()?;
    let store = lock.store.canonicalize()?;
    if !store.starts_with(&store_root) {
        return Err(PackageError::Lock);
    }
    let template = store.join("templates").join(format!("{role}.toml"));
    let template = template
        .canonicalize()
        .map_err(|_| PackageError::Template)?;
    if !template.starts_with(&store) || !template.is_file() {
        return Err(PackageError::Template);
    }
    let metadata = fs::metadata(&template)?;
    if metadata.len() > MAX_MANIFEST_BYTES as u64 {
        return Err(PackageError::Template);
    }
    if let Some(parent) = output.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    let mut destination = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)?;
    io::copy(&mut File::open(template)?, &mut destination)?;
    destination.sync_all()?;
    Ok(())
}

fn set_directory_mutable(path: &Path) -> Result<(), PackageError> {
    let mut permissions = fs::metadata(path)?.permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        permissions.set_mode(0o700);
    }
    #[cfg(not(unix))]
    permissions.set_readonly(false);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

fn set_directory_readonly(path: &Path) -> Result<(), PackageError> {
    let mut permissions = fs::metadata(path)?.permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        permissions.set_mode(0o500);
    }
    #[cfg(not(unix))]
    permissions.set_readonly(true);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

fn validate_dependencies(root: &Path, dependencies: &[Dependency]) -> Result<(), PackageError> {
    for dependency in dependencies {
        let (owner, name) = dependency
            .package
            .split_once('/')
            .ok_or(PackageError::Dependency)?;
        let lock_path = root
            .join("locks")
            .join(owner)
            .join(name)
            .join(format!("{}.toml", dependency.version));
        let lock = read_stored_lock(&lock_path).map_err(|_| PackageError::Dependency)?;
        let expected = format!("{}@{}", dependency.package, dependency.version);
        let store_root = root.join("store").canonicalize()?;
        let store = lock.store.canonicalize()?;
        let library = lock.library.canonicalize()?;
        if lock.wire_version != 1
            || lock.package != expected
            || lock.content_sha256 != dependency.content_sha256
            || lock.target.is_empty()
            || !store.starts_with(&store_root)
            || !library.starts_with(&store)
            || hash_file(&library)? != lock.content_sha256
        {
            return Err(PackageError::Dependency);
        }
    }
    Ok(())
}

fn read_stored_lock(path: &Path) -> Result<StoredLock, PackageError> {
    toml::from_str(&fs::read_to_string(path)?).map_err(PackageError::Toml)
}

fn lock_files(root: &Path) -> Result<Vec<PathBuf>, PackageError> {
    let mut output = Vec::new();
    if !root.exists() {
        return Ok(output);
    }
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            output.extend(lock_files(&path)?);
        } else if path
            .extension()
            .is_some_and(|extension| extension == "toml")
        {
            output.push(path);
        }
    }
    Ok(output)
}

fn parse_package_identity(package: &str) -> Result<(&str, &str, &str), PackageError> {
    let (name, version) = package.rsplit_once('@').ok_or(PackageError::Lock)?;
    let (owner, name) = name.split_once('/').ok_or(PackageError::Lock)?;
    validate_package_name(&format!("{owner}/{name}"))?;
    if version.is_empty()
        || !version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'+'))
    {
        return Err(PackageError::Lock);
    }
    Ok((owner, name, version))
}

fn make_mutable(path: &Path) -> Result<(), PackageError> {
    if path.is_dir() {
        for entry in fs::read_dir(path)? {
            make_mutable(&entry?.path())?;
        }
    }
    let mut permissions = fs::metadata(path)?.permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        permissions.set_mode(if path.is_dir() { 0o700 } else { 0o600 });
    }
    #[cfg(not(unix))]
    permissions.set_readonly(false);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

fn hash_file(path: &Path) -> Result<String, PackageError> {
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

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), PackageError> {
    let parent = path.parent().ok_or(PackageError::Path)?;
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .ok_or(PackageError::Path)?,
        std::process::id()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn make_readonly(path: &Path) -> Result<(), PackageError> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let child = entry.path();
        if entry.file_type()?.is_dir() {
            make_readonly(&child)?;
        }
        let mut permissions = fs::metadata(&child)?.permissions();
        permissions.set_readonly(true);
        fs::set_permissions(child, permissions)?;
    }
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_readonly(true);
    fs::set_permissions(path, permissions)?;
    Ok(())
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

struct Staging {
    path: PathBuf,
}

impl Staging {
    fn new(root: &Path) -> Result<Self, PackageError> {
        let staging = root.join("staging");
        fs::create_dir_all(&staging)?;
        for nonce in 0..16u8 {
            let path = staging.join(format!(
                "install-{}-{}-{nonce}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| PackageError::Clock)?
                    .as_nanos()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err(PackageError::StagingCreate)
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn read_publication(
    repository: &gix::Repository,
    module_name: &str,
) -> Result<Publication, PackageError> {
    let commit = repository
        .head_commit()
        .map_err(|error| PackageError::Git(error.to_string()))?;
    let revision = commit.id().to_string();
    let tree = commit
        .tree()
        .map_err(|error| PackageError::Git(error.to_string()))?;
    let manifest_path = PathBuf::from("snolpkg").join(format!("{module_name}.toml"));
    let signature_path = PathBuf::from("snolpkg").join(format!("{module_name}.toml.sig"));
    let manifest_bytes = read_blob(&tree, &manifest_path)?;
    let signature_bytes = read_blob(&tree, &signature_path)?;
    let manifest = PublicationManifest::parse(&manifest_bytes)?;
    Ok(Publication {
        revision,
        manifest_bytes,
        signature_bytes,
        manifest,
    })
}

fn read_blob(tree: &gix::Tree<'_>, path: &Path) -> Result<Vec<u8>, PackageError> {
    let entry = tree
        .lookup_entry_by_path(path)
        .map_err(|error| PackageError::Git(error.to_string()))?
        .ok_or(PackageError::PublicationFile)?;
    let object = entry
        .object()
        .map_err(|error| PackageError::Git(error.to_string()))?;
    if object.kind != gix::object::Kind::Blob || object.data.len() > MAX_MANIFEST_BYTES {
        return Err(PackageError::PublicationFile);
    }
    Ok(object.data.clone())
}

pub fn decode_hex(input: &str) -> Result<Vec<u8>, PackageError> {
    if !input.len().is_multiple_of(2) || !input.is_ascii() {
        return Err(PackageError::Hex);
    }
    input
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let high = hex_digit(pair[0]).ok_or(PackageError::Hex)?;
            let low = hex_digit(pair[1]).ok_or(PackageError::Hex)?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn validate_package_name(name: &str) -> Result<(), PackageError> {
    let mut components = name.split('/');
    let valid = components.by_ref().take(3).collect::<Vec<_>>();
    if valid.len() != 2
        || valid.iter().any(|component| {
            component.is_empty()
                || !component
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
    {
        return Err(PackageError::ManifestValue);
    }
    Ok(())
}

fn validate_module_name(name: &str) -> Result<(), PackageError> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(PackageError::ManifestValue);
    }
    Ok(())
}

fn validate_sha256(input: &str) -> Result<(), PackageError> {
    if input.len() != 64 || decode_hex(input)?.len() != 32 {
        return Err(PackageError::Hash);
    }
    Ok(())
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[derive(Debug, Error)]
pub enum PackageError {
    #[error("manifest size is invalid")]
    ManifestSize,
    #[error("manifest is not UTF-8")]
    ManifestUtf8,
    #[error("manifest TOML is invalid: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("manifest value is invalid")]
    ManifestValue,
    #[error("trusted source is invalid")]
    SourceValue,
    #[error("source is not trusted")]
    UntrustedSource,
    #[error("signature policy does not allow verification")]
    SignaturePolicy,
    #[error("public key is invalid")]
    Key,
    #[error("signature is invalid")]
    Signature,
    #[error("SHA-256 is invalid")]
    Hash,
    #[error("hex value is invalid")]
    Hex,
    #[error("relative path is invalid")]
    Path,
    #[error("extraction limit is invalid or exhausted")]
    ExtractLimit,
    #[error("staging directory is not empty")]
    StagingNotEmpty,
    #[error("archive path is duplicated")]
    DuplicatePath,
    #[error("archive entry type is forbidden")]
    ArchiveType,
    #[error("archive entry mode is forbidden")]
    ArchiveMode,
    #[error("archive entry size is inconsistent")]
    ArchiveSize,
    #[error("I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("I/O failed during {0}: {1}")]
    IoAt(&'static str, io::Error),
    #[error("Git operation failed: {0}")]
    Git(String),
    #[error("Git source must be HTTPS or an absolute local path")]
    GitSource,
    #[error("clone directory already exists")]
    CloneDirectory,
    #[error("publication file is missing or invalid")]
    PublicationFile,
    #[error("checked out revision does not match manifest")]
    Revision,
    #[error("install options are invalid")]
    InstallOptions,
    #[error("target artifact is unavailable")]
    Target,
    #[error("offline mode forbids a network request")]
    OfflineNetwork,
    #[error("artifact download failed: {0}")]
    Download(String),
    #[error("artifact byte size does not match manifest")]
    ArtifactSize,
    #[error("artifact hash does not match manifest")]
    ArtifactHash,
    #[error("source build failed with exit code {0:?}")]
    Build(Option<i32>),
    #[error("package dependency is missing or conflicts")]
    Dependency,
    #[error("package lock is invalid")]
    Lock,
    #[error("package is required by {0}")]
    ReverseDependency(String),
    #[error("package template is unavailable")]
    Template,
    #[error("module entry is missing")]
    Entry,
    #[error("immutable store content conflicts")]
    StoreConflict,
    #[error("system clock is before the Unix epoch")]
    Clock,
    #[error("staging directory cannot be allocated")]
    StagingCreate,
    #[error("TOML serialization failed: {0}")]
    TomlSerialize(#[from] toml::ser::Error),
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Cursor;
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    use ed25519_dalek::{Signer, SigningKey};
    use flate2::{Compression, write::GzEncoder};
    use tar::{Builder, EntryType, Header};

    use super::*;

    const MANIFEST: &str = r#"
name = "owenewans/carrier-tcp"
authors = ["Owen Ewans"]
license = "Unlicense"
package_version = "0.0.1"
wire_version = 1
classes = ["carrier"]
family = "tcp"
entry = "lib/libsnolc_carrier_tcp.so"
toolchain = "1.98.1"
dependencies = []

[source]
revision = "0123456789abcdef0123456789abcdef01234567"

[build]
package = "snolc-carrier-tcp"

[[artifacts]]
target = "x86_64-unknown-linux-gnu"
minimum_isa = "x86-64"
minimum_libc = "2.28"
url = "https://example.invalid/carrier.tar.gz"
byte_size = 1024
sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
build_output = "release/libsnolc_carrier_tcp.so"
"#;

    #[test]
    fn parses_strict_complete_manifest() {
        let manifest = PublicationManifest::parse(MANIFEST.as_bytes()).unwrap();
        assert_eq!(manifest.name, "owenewans/carrier-tcp");
        assert!(
            PublicationManifest::parse(
                MANIFEST
                    .replace("wire_version = 1", "wire_version = 1\nextra = 1")
                    .as_bytes()
            )
            .is_err()
        );
    }

    #[test]
    fn verifies_signature_over_original_manifest_bytes() {
        let signing = SigningKey::from_bytes(&[7; 32]);
        let key = signing.verifying_key().to_bytes();
        let source = TrustedSource {
            id: "official".into(),
            git: "https://example.invalid/modules.git".into(),
            trust: TrustMode::Signed,
            public_key: Some(key.iter().map(|byte| format!("{byte:02x}")).collect()),
        };
        let signature = signing.sign(MANIFEST.as_bytes()).to_bytes();
        verify_manifest(MANIFEST.as_bytes(), &signature, &source).unwrap();
        assert!(verify_manifest(b"changed", &signature, &source).is_err());
    }

    #[test]
    fn rejects_escaping_paths_and_unsigned_remote_sources() {
        assert!(validate_relative_path(Path::new("../module.so")).is_err());
        let sources = r#"
[[sources]]
id = "local"
git = "/tmp/modules"
trust = "local-development"
"#;
        assert!(Sources::parse(sources).is_ok());
        let invalid = sources.replace("/tmp/modules", "https://example.invalid/modules");
        assert!(Sources::parse(&invalid).is_err());
    }

    #[test]
    fn extracts_regular_files_with_bounded_accounting() {
        let archive = archive_with(|builder| {
            append_file(builder, "lib/module.so", b"module", 0o755);
            append_file(builder, "NOTICE", b"license", 0o644);
        });
        let staging = temporary_directory("extract-ok");
        let report = extract_tar_gz(
            Cursor::new(archive),
            &staging,
            ExtractLimits {
                max_files: 2,
                max_total_bytes: 13,
                max_file_bytes: 7,
            },
        )
        .unwrap();
        assert_eq!(report.files, 2);
        assert_eq!(report.total_bytes, 13);
        assert_eq!(fs::read(staging.join("lib/module.so")).unwrap(), b"module");
        fs::remove_dir_all(staging).unwrap();
    }

    #[test]
    fn rejects_links_duplicates_modes_and_size_limits() {
        let duplicate = archive_with(|builder| {
            append_file(builder, "same", b"one", 0o644);
            append_file(builder, "same", b"two", 0o644);
        });
        let staging = temporary_directory("extract-duplicate");
        assert!(matches!(
            extract_tar_gz(Cursor::new(duplicate), &staging, limits()),
            Err(PackageError::DuplicatePath)
        ));
        fs::remove_dir_all(staging).unwrap();

        let link = archive_with(|builder| {
            let mut header = Header::new_gnu();
            header.set_entry_type(EntryType::Symlink);
            header.set_size(0);
            header.set_mode(0o777);
            header.set_cksum();
            builder.append_link(&mut header, "link", "target").unwrap();
        });
        let staging = temporary_directory("extract-link");
        assert!(matches!(
            extract_tar_gz(Cursor::new(link), &staging, limits()),
            Err(PackageError::ArchiveType)
        ));
        fs::remove_dir_all(staging).unwrap();

        let setuid = archive_with(|builder| append_file(builder, "file", b"x", 0o4755));
        let staging = temporary_directory("extract-mode");
        assert!(matches!(
            extract_tar_gz(Cursor::new(setuid), &staging, limits()),
            Err(PackageError::ArchiveMode)
        ));
        fs::remove_dir_all(staging).unwrap();

        let oversized = archive_with(|builder| append_file(builder, "file", b"12345", 0o644));
        let staging = temporary_directory("extract-limit");
        let mut limits = limits();
        limits.max_file_bytes = 4;
        assert!(matches!(
            extract_tar_gz(Cursor::new(oversized), &staging, limits),
            Err(PackageError::ExtractLimit)
        ));
        fs::remove_dir_all(staging).unwrap();
    }

    #[test]
    fn reads_publication_from_pinned_git_objects_without_checkout() {
        let root = temporary_directory("git-publication");
        run_git(&root, &["init", "-q"]);
        fs::create_dir(root.join("snolpkg")).unwrap();
        fs::write(root.join("snolpkg/test.toml"), MANIFEST).unwrap();
        fs::write(root.join("snolpkg/test.toml.sig"), [9; 64]).unwrap();
        run_git(
            &root,
            &["add", "snolpkg/test.toml", "snolpkg/test.toml.sig"],
        );
        run_git(
            &root,
            &[
                "-c",
                "user.name=snolpkg test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "-q",
                "-m",
                "publication",
            ],
        );
        let clone = root.join("unused-clone");
        let publication = load_publication(root.to_str().unwrap(), "test", &clone).unwrap();
        assert_eq!(publication.signature_bytes, [9; 64]);
        assert_eq!(publication.manifest.name, "owenewans/carrier-tcp");
        assert_eq!(publication.revision.len(), 40);
        assert!(!clone.exists());
        remove_readonly_tree(&root);
    }

    #[test]
    fn checks_out_exact_commit_without_shell_git_in_product_path() {
        let root = temporary_directory("git-checkout");
        let repository = root.join("repository");
        fs::create_dir(&repository).unwrap();
        run_git(&repository, &["init", "-q"]);
        fs::write(repository.join("value"), b"first").unwrap();
        run_git(&repository, &["add", "value"]);
        run_git(
            &repository,
            &[
                "-c",
                "user.name=snolpkg test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "-q",
                "-m",
                "first",
            ],
        );
        let first = git_output(&repository, &["rev-parse", "HEAD"]);
        fs::write(repository.join("value"), b"second").unwrap();
        run_git(&repository, &["add", "value"]);
        run_git(
            &repository,
            &[
                "-c",
                "user.name=snolpkg test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "-q",
                "-m",
                "second",
            ],
        );
        let checkout = root.join("checkout");
        assert_eq!(
            checkout_revision(repository.to_str().unwrap(), &first, &checkout).unwrap(),
            first
        );
        assert_eq!(fs::read(checkout.join("value")).unwrap(), b"first");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn moves_verified_content_into_immutable_store_and_writes_lock() {
        let root = temporary_directory("install-store");
        let content = root.join("content");
        fs::create_dir_all(content.join("lib")).unwrap();
        fs::write(content.join("lib/libsnolc_carrier_tcp.so"), b"library").unwrap();
        fs::create_dir(content.join("templates")).unwrap();
        fs::write(content.join("templates/server.toml"), "wire_version = 1\n").unwrap();
        let manifest = PublicationManifest::parse(MANIFEST.as_bytes()).unwrap();
        let source = TrustedSource {
            id: "official".into(),
            git: "https://example.invalid/modules.git".into(),
            trust: TrustMode::Signed,
            public_key: Some("11".repeat(32)),
        };
        let artifact = &manifest.artifacts[0];
        let result = install_extracted(
            &manifest,
            &source,
            artifact,
            &content,
            &InstallOptions {
                root: root.clone(),
                target: artifact.target.clone(),
                limits: limits(),
                offline: false,
            },
        )
        .unwrap();
        let installed_store = result.store.clone();
        let installed_lock = result.lock.clone();
        assert_eq!(result.package, "owenewans/carrier-tcp@0.0.1");
        assert!(result.store.join(&manifest.entry).is_file());
        let lock = fs::read_to_string(result.lock).unwrap();
        let lock: toml::Value = toml::from_str(&lock).unwrap();
        assert_eq!(lock["wire_version"].as_integer(), Some(1));
        assert_eq!(
            lock["content_sha256"].as_str(),
            Some("b718f1354f7247312eca086d9a024afe5fa717ddea5adeddd6f12bcf945b2e8c")
        );
        let output = root.join("generated/server.toml");
        write_template(&root, "owenewans/carrier-tcp@0.0.1", "server", &output).unwrap();
        assert_eq!(fs::read_to_string(output).unwrap(), "wire_version = 1\n");
        assert!(
            write_template(
                &root,
                "owenewans/carrier-tcp@0.0.1",
                "server",
                &root.join("generated/server.toml"),
            )
            .is_err()
        );
        delete_package(&root, "owenewans/carrier-tcp@0.0.1").unwrap();
        assert!(!installed_store.exists());
        assert!(!installed_lock.exists());
        remove_readonly_tree(&root);
    }

    #[test]
    fn refuses_to_delete_reverse_dependency() {
        let root = temporary_directory("delete-dependency");
        let source = TrustedSource {
            id: "official".into(),
            git: "https://example.invalid/modules.git".into(),
            trust: TrustMode::Signed,
            public_key: Some("11".repeat(32)),
        };
        let options = InstallOptions {
            root: root.clone(),
            target: "x86_64-unknown-linux-gnu".into(),
            limits: limits(),
            offline: false,
        };
        let base = PublicationManifest::parse(MANIFEST.as_bytes()).unwrap();
        let base_content = root.join("base-content");
        fs::create_dir_all(base_content.join("lib")).unwrap();
        fs::write(base_content.join("lib/libsnolc_carrier_tcp.so"), b"base").unwrap();
        let base_result =
            install_extracted(&base, &source, &base.artifacts[0], &base_content, &options).unwrap();
        let base_lock = read_stored_lock(&base_result.lock).unwrap();

        let mut dependent = base.clone();
        dependent.name = "owenewans/dependent".into();
        dependent.entry = "lib/dependent.so".into();
        dependent.dependencies.push(Dependency {
            package: "owenewans/carrier-tcp".into(),
            version: "0.0.1".into(),
            content_sha256: base_lock.content_sha256,
        });
        let dependent_content = root.join("dependent-content");
        fs::create_dir_all(dependent_content.join("lib")).unwrap();
        fs::write(dependent_content.join("lib/dependent.so"), b"dependent").unwrap();
        install_extracted(
            &dependent,
            &source,
            &dependent.artifacts[0],
            &dependent_content,
            &options,
        )
        .unwrap();
        assert!(matches!(
            delete_package(&root, "owenewans/carrier-tcp@0.0.1"),
            Err(PackageError::ReverseDependency(package)) if package == "owenewans/dependent@0.0.1"
        ));
        delete_package(&root, "owenewans/dependent@0.0.1").unwrap();
        delete_package(&root, "owenewans/carrier-tcp@0.0.1").unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn installs_binary_from_local_git_and_file_artifact() {
        let root = temporary_directory("install-e2e");
        let repository = root.join("repository");
        fs::create_dir(&repository).unwrap();
        run_git(&repository, &["init", "-q"]);
        let archive =
            archive_with(|builder| append_file(builder, "lib/module.so", b"native module", 0o644));
        let artifact_path = root.join("artifact.tar.gz");
        fs::write(&artifact_path, &archive).unwrap();
        let artifact_hash = encode_hex(&Sha256::digest(&archive));
        let manifest = format!(
            r#"name = "owenewans/test"
authors = ["Owen Ewans"]
license = "Unlicense"
package_version = "0.0.1"
wire_version = 1
classes = ["carrier"]
family = "test"
entry = "lib/module.so"
toolchain = "1.98.1"
dependencies = []

[source]
revision = "0123456789abcdef0123456789abcdef01234567"

[build]
package = "snolc-test"

[[artifacts]]
target = "{}"
minimum_isa = "test"
minimum_libc = "2.28"
url = "file://{}"
byte_size = {}
sha256 = "{}"
build_output = "release/libtest.so"
"#,
            env!("SNOLPKG_TARGET"),
            artifact_path.display(),
            archive.len(),
            artifact_hash
        );
        fs::create_dir(repository.join("snolpkg")).unwrap();
        fs::write(repository.join("snolpkg/test.toml"), manifest).unwrap();
        fs::write(repository.join("snolpkg/test.toml.sig"), [0; 64]).unwrap();
        run_git(
            &repository,
            &["add", "snolpkg/test.toml", "snolpkg/test.toml.sig"],
        );
        run_git(
            &repository,
            &[
                "-c",
                "user.name=snolpkg test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "-q",
                "-m",
                "publication",
            ],
        );
        let packages = root.join("packages");
        fs::create_dir(&packages).unwrap();
        fs::write(
            packages.join("sources.toml"),
            format!(
                "[[sources]]\nid = \"local\"\ngit = \"{}\"\ntrust = \"local-development\"\n",
                repository.display()
            ),
        )
        .unwrap();
        let result = install_binary(
            repository.to_str().unwrap(),
            "test",
            &InstallOptions {
                root: packages,
                target: env!("SNOLPKG_TARGET").into(),
                limits: limits(),
                offline: true,
            },
        )
        .unwrap();
        assert_eq!(result.package, "owenewans/test@0.0.1");
        assert_eq!(
            fs::read(result.store.join("lib/module.so")).unwrap(),
            b"native module"
        );
        remove_readonly_tree(&root);
    }

    #[test]
    fn builds_pinned_source_with_locked_cargo_and_keeps_license() {
        let root = temporary_directory("source-e2e");
        let repository = root.join("repository");
        fs::create_dir(&repository).unwrap();
        run_git(&repository, &["init", "-q"]);
        fs::create_dir(repository.join("src")).unwrap();
        fs::write(
            repository.join("Cargo.toml"),
            r#"[package]
name = "source-test"
version = "0.0.1"
edition = "2024"

[lib]
crate-type = ["cdylib"]
"#,
        )
        .unwrap();
        fs::write(
            repository.join("Cargo.lock"),
            r#"# This file is automatically @generated by Cargo.
# It is not intended for manual editing.
version = 4

[[package]]
name = "source-test"
version = "0.0.1"
"#,
        )
        .unwrap();
        fs::write(
            repository.join("src/lib.rs"),
            "pub fn value() -> u8 { 1 }\n",
        )
        .unwrap();
        fs::write(repository.join("LICENSE"), "license text\n").unwrap();
        run_git(&repository, &["add", "."]);
        run_git(
            &repository,
            &[
                "-c",
                "user.name=snolpkg test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "-q",
                "-m",
                "source",
            ],
        );
        let source_revision = git_output(&repository, &["rev-parse", "HEAD"]);
        let manifest = format!(
            r#"name = "owenewans/source-test"
authors = ["Owen Ewans"]
license = "Unlicense"
package_version = "0.0.1"
wire_version = 1
classes = ["carrier"]
family = "test"
entry = "lib/module.so"
toolchain = "1.98.1"
dependencies = []

[source]
revision = "{}"

[build]
package = "source-test"

[[artifacts]]
target = "{}"
minimum_isa = "test"
minimum_libc = "2.28"
url = "file:///missing-source-artifact"
byte_size = 1
sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
build_output = "release/libsource_test.so"
"#,
            source_revision,
            env!("SNOLPKG_TARGET")
        );
        fs::create_dir(repository.join("snolpkg")).unwrap();
        fs::write(repository.join("snolpkg/source-test.toml"), manifest).unwrap();
        fs::write(repository.join("snolpkg/source-test.toml.sig"), [0; 64]).unwrap();
        run_git(&repository, &["add", "snolpkg"]);
        run_git(
            &repository,
            &[
                "-c",
                "user.name=snolpkg test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "-q",
                "-m",
                "publication",
            ],
        );
        let packages = root.join("packages");
        fs::create_dir(&packages).unwrap();
        fs::write(
            packages.join("sources.toml"),
            format!(
                "[[sources]]\nid = \"local\"\ngit = \"{}\"\ntrust = \"local-development\"\n",
                repository.display()
            ),
        )
        .unwrap();
        let result = install_source(
            repository.to_str().unwrap(),
            "source-test",
            &InstallOptions {
                root: packages,
                target: env!("SNOLPKG_TARGET").into(),
                limits: ExtractLimits {
                    max_files: 16,
                    max_total_bytes: 16 * 1024 * 1024,
                    max_file_bytes: 16 * 1024 * 1024,
                },
                offline: true,
            },
        )
        .unwrap();
        assert!(result.store.join("lib/module.so").is_file());
        assert_eq!(
            fs::read_to_string(result.store.join("LICENSE")).unwrap(),
            "license text\n"
        );
        remove_readonly_tree(&root);
    }

    fn archive_with(build: impl FnOnce(&mut Builder<GzEncoder<Vec<u8>>>)) -> Vec<u8> {
        let encoder = GzEncoder::new(Vec::new(), Compression::fast());
        let mut builder = Builder::new(encoder);
        build(&mut builder);
        builder.into_inner().unwrap().finish().unwrap()
    }

    fn append_file<W: io::Write>(builder: &mut Builder<W>, path: &str, bytes: &[u8], mode: u32) {
        let mut header = Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(mode);
        header.set_cksum();
        builder.append_data(&mut header, path, bytes).unwrap();
    }

    fn limits() -> ExtractLimits {
        ExtractLimits {
            max_files: 8,
            max_total_bytes: 1024,
            max_file_bytes: 1024,
        }
    }

    fn temporary_directory(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "snolpkg-{name}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    fn run_git(directory: &Path, arguments: &[&str]) {
        let status = Command::new("git")
            .args(arguments)
            .current_dir(directory)
            .status()
            .unwrap();
        assert!(status.success());
    }

    fn git_output(directory: &Path, arguments: &[&str]) -> String {
        let output = Command::new("git")
            .args(arguments)
            .current_dir(directory)
            .output()
            .unwrap();
        assert!(output.status.success());
        String::from_utf8(output.stdout).unwrap().trim().into()
    }

    fn remove_readonly_tree(path: &Path) {
        make_writable_tree(path);
        fs::remove_dir_all(path).unwrap();
    }

    fn make_writable_tree(path: &Path) {
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                make_writable_tree(&entry.path());
            }
        }
        let mut permissions = fs::metadata(path).unwrap().permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            permissions.set_mode(0o700);
        }
        #[cfg(not(unix))]
        permissions.set_readonly(false);
        fs::set_permissions(path, permissions).unwrap();
    }
}
