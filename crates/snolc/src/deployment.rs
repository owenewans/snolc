use std::collections::BTreeMap;
use std::env;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::config::{Config, ConfigError};
use crate::loader::{LoadError, LoadedModule};
use crate::module_config::{ModuleConfig, ModuleConfigError, PackageIdentity};

pub struct Deployment {
    config: Config,
    modules: Vec<LoadedModule>,
}

impl Deployment {
    pub fn load(path: &Path) -> Result<Self, DeploymentError> {
        let path = absolute(path)?;
        let directory = path.parent().ok_or(DeploymentError::ConfigPath)?;
        let input = fs::read_to_string(&path)?;
        let config = Config::parse(&input, directory)?;
        let expected = module_paths(&config)?;
        let mut instances = BTreeMap::new();
        for (module_path, class) in expected {
            let input = fs::read_to_string(&module_path)?;
            let module_config = ModuleConfig::parse(&input, &module_path)?;
            if instances.contains_key(&module_config.instance) {
                return Err(DeploymentError::DuplicateInstance(module_config.instance));
            }
            let library = resolve_library(&config.paths.packages, &module_config.package)?;
            let options = module_config.options_toml()?;
            let loaded = LoadedModule::load(
                module_config.instance.clone(),
                &library,
                options,
                &module_config.base_directory,
                &module_path,
            )?;
            if loaded.class_mask() & class == 0 {
                return Err(DeploymentError::Class {
                    instance: module_config.instance,
                    class,
                });
            }
            instances.insert(module_config.instance, loaded);
        }
        Ok(Self {
            config,
            modules: instances.into_values().collect(),
        })
    }

    pub fn into_parts(self) -> (Config, Vec<LoadedModule>) {
        (self.config, self.modules)
    }
}

fn module_paths(config: &Config) -> Result<BTreeMap<PathBuf, u32>, DeploymentError> {
    let mut paths = BTreeMap::new();
    for tunnel in &config.tunnels {
        for adapter in &tunnel.adapters {
            merge_class(&mut paths, adapter, crate::CLASS_ADAPTER)?;
        }
        merge_class(&mut paths, &tunnel.protection, crate::CLASS_PROTECTION)?;
        merge_class(&mut paths, &tunnel.carrier, crate::CLASS_CARRIER)?;
        merge_class(&mut paths, &tunnel.policy, crate::CLASS_POLICY)?;
    }
    Ok(paths)
}

fn merge_class(
    paths: &mut BTreeMap<PathBuf, u32>,
    path: &Path,
    class: u32,
) -> Result<(), DeploymentError> {
    match paths.get(path) {
        Some(existing) if *existing != class => {
            Err(DeploymentError::ConflictingClass(path.to_path_buf()))
        }
        Some(_) => Ok(()),
        None => {
            paths.insert(path.to_path_buf(), class);
            Ok(())
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageLock {
    wire_version: u32,
    package: PackageIdentity,
    target: String,
    content_sha256: String,
    library: PathBuf,
    store: PathBuf,
    dependencies: Vec<LockedDependency>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LockedDependency {
    package: String,
    version: String,
    content_sha256: String,
}

fn resolve_library(packages: &Path, package: &PackageIdentity) -> Result<PathBuf, DeploymentError> {
    let root = packages.canonicalize()?;
    let lock_path = root
        .join("locks")
        .join(&package.owner)
        .join(&package.name)
        .join(format!("{}.toml", package.version));
    let lock: PackageLock = toml::from_str(&fs::read_to_string(&lock_path)?)?;
    if lock.wire_version != crate::WIRE_VERSION
        || lock.package != *package
        || lock.target.is_empty()
        || lock.store.as_os_str().is_empty()
        || lock.content_sha256.len() != 64
        || lock.dependencies.iter().any(|dependency| {
            dependency.package.is_empty()
                || dependency.version.is_empty()
                || dependency.content_sha256.len() != 64
        })
    {
        return Err(DeploymentError::PackageLock(lock_path));
    }
    let lock_directory = lock_path.parent().ok_or(DeploymentError::PackageLockPath)?;
    let library = lock_directory.join(lock.library).canonicalize()?;
    let store = lock_directory.join(lock.store).canonicalize()?;
    if !library.starts_with(&root) || !store.starts_with(&root) || !library.starts_with(&store) {
        return Err(DeploymentError::PackageEscape);
    }
    if hash_file(&library)? != lock.content_sha256.to_ascii_lowercase() {
        return Err(DeploymentError::PackageHash(library));
    }
    Ok(library)
}

fn hash_file(path: &Path) -> Result<String, io::Error> {
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
    Ok(hex(&hasher.finalize()))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[usize::from(byte >> 4)] as char);
        output.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    output
}

fn absolute(path: &Path) -> Result<PathBuf, io::Error> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        env::current_dir().map(|directory| directory.join(path))
    }
}

#[derive(Debug, Error)]
pub enum DeploymentError {
    #[error("deployment I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("main configuration is invalid: {0}")]
    Config(#[from] ConfigError),
    #[error("module configuration is invalid: {0}")]
    ModuleConfig(#[from] ModuleConfigError),
    #[error("native module failed to load: {0}")]
    Load(#[from] LoadError),
    #[error("package lock TOML is invalid: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("main configuration path has no parent")]
    ConfigPath,
    #[error("package lock path has no parent")]
    PackageLockPath,
    #[error("duplicate module instance {0}")]
    DuplicateInstance(String),
    #[error("module {instance} does not provide class {class:#x}")]
    Class { instance: String, class: u32 },
    #[error("module configuration {} is used for two classes", .0.display())]
    ConflictingClass(PathBuf),
    #[error("package lock {} is incompatible", .0.display())]
    PackageLock(PathBuf),
    #[error("package path escapes package directory")]
    PackageEscape,
    #[error("package library hash mismatch: {}", .0.display())]
    PackageHash(PathBuf),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_has_fixed_width() {
        assert_eq!(hex(&[0, 255]), "00ff");
    }

    #[test]
    fn conflicting_module_classes_are_rejected() {
        let path = PathBuf::from("module.toml");
        let mut paths = BTreeMap::new();
        merge_class(&mut paths, &path, crate::CLASS_ADAPTER).unwrap();
        assert!(matches!(
            merge_class(&mut paths, &path, crate::CLASS_POLICY),
            Err(DeploymentError::ConflictingClass(found)) if found == path
        ));
    }
}
