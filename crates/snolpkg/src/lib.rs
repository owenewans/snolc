use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MAX_MANIFEST_BYTES: usize = 1_048_576;

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
            if artifact.target.is_empty()
                || artifact.minimum_isa.is_empty()
                || artifact.byte_size == 0
                || !artifact.url.starts_with("https://")
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
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

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
revision = "0123456789abcdef"

[build]
package = "snolc-carrier-tcp"

[[artifacts]]
target = "x86_64-unknown-linux-gnu"
minimum_isa = "x86-64"
minimum_libc = "2.28"
url = "https://example.invalid/carrier.tar.gz"
byte_size = 1024
sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
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
}
