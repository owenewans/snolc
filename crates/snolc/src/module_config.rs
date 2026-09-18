use std::path::{Path, PathBuf};

use serde::Deserialize;
use thiserror::Error;

use crate::config::Role;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleConfig {
    pub wire_version: u32,
    pub instance: String,
    pub package: PackageIdentity,
    pub role: Role,
    pub options: toml::Table,
    #[serde(skip)]
    pub base_directory: PathBuf,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PackageIdentity {
    pub owner: String,
    pub name: String,
    pub version: String,
}

impl ModuleConfig {
    pub fn parse(input: &str, path: &Path) -> Result<Self, ModuleConfigError> {
        let mut config: Self = toml::from_str(input)?;
        let parent = path.parent().ok_or(ModuleConfigError::Path)?;
        config.base_directory = if parent.is_absolute() {
            parent.to_path_buf()
        } else {
            std::env::current_dir()?.join(parent)
        };
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ModuleConfigError> {
        if self.wire_version != snolc_abi::WIRE_VERSION {
            return Err(ModuleConfigError::WireVersion(self.wire_version));
        }
        if self.instance.is_empty()
            || self.instance.len() > 64
            || !self
                .instance
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(ModuleConfigError::Instance);
        }
        Ok(())
    }

    pub fn options_toml(&self) -> Result<Vec<u8>, ModuleConfigError> {
        Ok(toml::to_string(&self.options)?.into_bytes())
    }
}

impl<'de> Deserialize<'de> for PackageIdentity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

impl std::str::FromStr for PackageIdentity {
    type Err = ModuleConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (path, version) = value.rsplit_once('@').ok_or(ModuleConfigError::Package)?;
        let (owner, name) = path.split_once('/').ok_or(ModuleConfigError::Package)?;
        if owner.is_empty()
            || name.is_empty()
            || name.contains('/')
            || version.is_empty()
            || !owner.bytes().all(package_character)
            || !name.bytes().all(package_character)
            || !version.bytes().all(version_character)
        {
            return Err(ModuleConfigError::Package);
        }
        Ok(Self {
            owner: owner.into(),
            name: name.into(),
            version: version.into(),
        })
    }
}

impl std::fmt::Display for PackageIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}/{}@{}", self.owner, self.name, self.version)
    }
}

fn package_character(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
}

fn version_character(byte: u8) -> bool {
    package_character(byte) || byte == b'+'
}

#[derive(Debug, Error)]
pub enum ModuleConfigError {
    #[error("module TOML is invalid: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("module options cannot be serialized: {0}")]
    Serialize(#[from] toml::ser::Error),
    #[error("module config path has no parent")]
    Path,
    #[error("module config directory cannot be resolved: {0}")]
    Io(#[from] std::io::Error),
    #[error("module wire version {0} is unsupported")]
    WireVersion(u32),
    #[error("module instance name is invalid")]
    Instance,
    #[error("package identity is invalid")]
    Package,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_config_is_valid() {
        let config = ModuleConfig::parse(
            "wire_version = 1\ninstance = \"policy-main\"\npackage = \"owenewans/policy-local@0.0.2\"\nrole = \"server\"\n[options]\nnode_id = \"node-1\"\n",
            Path::new("/tmp/modules/policy.toml"),
        )
        .unwrap();
        assert_eq!(config.package.to_string(), "owenewans/policy-local@0.0.2");
        assert!(
            String::from_utf8(config.options_toml().unwrap())
                .unwrap()
                .contains("node-1")
        );
    }

    #[test]
    fn package_identity_is_exact() {
        let package: PackageIdentity = "owenewans/carrier-tcp@0.0.2".parse().unwrap();
        assert_eq!(package.name, "carrier-tcp");
        assert!("carrier-tcp".parse::<PackageIdentity>().is_err());
    }
}
