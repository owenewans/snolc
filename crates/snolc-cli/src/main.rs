use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256};
use snolc::config::Config;
use snolc::loader::LoadedModule;
use snolc::module_config::{ModuleConfig, PackageIdentity};
use snolc::{Engine, Event, Host};

fn main() {
    if let Err(error) = run(env::args().skip(1).collect()) {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run(arguments: Vec<String>) -> Result<(), String> {
    match arguments.as_slice() {
        [command] if command == "version" || command == "--version" => {
            println!(
                "snolc {} wire {}",
                env!("CARGO_PKG_VERSION"),
                snolc::WIRE_VERSION
            );
            Ok(())
        }
        [command, path] if command == "validate" => {
            let (config, modules) = load(Path::new(path))?;
            Engine::validate(config, modules).map_err(|error| error.to_string())?;
            println!("valid");
            Ok(())
        }
        [command, path] if command == "run" => run_engine(Path::new(path)),
        _ => Err("usage: snolc version | validate <snolc.toml> | run <snolc.toml>".into()),
    }
}

fn run_engine(path: &Path) -> Result<(), String> {
    let (config, modules) = load(path)?;
    let validated = Engine::validate(config, modules).map_err(|error| error.to_string())?;
    let (engine, handle) = Engine::build(validated, CliHost).map_err(|error| error.to_string())?;
    let shutdown = handle.clone();
    ctrlc::set_handler(move || {
        let _ = shutdown.shutdown();
    })
    .map_err(|error| error.to_string())?;
    engine.run().map_err(|error| error.to_string())
}

fn load(path: &Path) -> Result<(Config, Vec<LoadedModule>), String> {
    let path = absolute(path)?;
    let directory = path.parent().ok_or("config path has no parent")?;
    let input = fs::read_to_string(&path).map_err(|error| error.to_string())?;
    let config = Config::parse(&input, directory).map_err(|error| error.to_string())?;
    let expected = module_paths(&config)?;
    let mut instances = BTreeMap::new();
    for (module_path, class) in expected {
        let input = fs::read_to_string(&module_path).map_err(|error| error.to_string())?;
        let module_config =
            ModuleConfig::parse(&input, &module_path).map_err(|error| error.to_string())?;
        if instances.contains_key(&module_config.instance) {
            return Err(format!(
                "duplicate module instance {}",
                module_config.instance
            ));
        }
        let library = resolve_library(&config.paths.packages, &module_config.package)?;
        let options = module_config
            .options_toml()
            .map_err(|error| error.to_string())?;
        let loaded = LoadedModule::load(
            module_config.instance.clone(),
            &library,
            options,
            &module_config.base_directory,
        )
        .map_err(|error| error.to_string())?;
        if loaded.class_mask() & class == 0 {
            return Err(format!(
                "module {} does not provide class {class:#x}",
                module_config.instance
            ));
        }
        instances.insert(module_config.instance, loaded);
    }
    Ok((config, instances.into_values().collect()))
}

fn module_paths(config: &Config) -> Result<BTreeMap<PathBuf, u32>, String> {
    let mut paths = BTreeMap::new();
    for tunnel in &config.tunnels {
        for adapter in &tunnel.adapters {
            merge_class(&mut paths, adapter, snolc::CLASS_ADAPTER)?;
        }
        merge_class(&mut paths, &tunnel.protection, snolc::CLASS_PROTECTION)?;
        merge_class(&mut paths, &tunnel.carrier, snolc::CLASS_CARRIER)?;
        merge_class(&mut paths, &tunnel.policy, snolc::CLASS_POLICY)?;
    }
    Ok(paths)
}

fn merge_class(paths: &mut BTreeMap<PathBuf, u32>, path: &Path, class: u32) -> Result<(), String> {
    match paths.get(path) {
        Some(existing) if *existing != class => Err(format!(
            "module config {} is used for two classes",
            path.display()
        )),
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
}

fn resolve_library(packages: &Path, package: &PackageIdentity) -> Result<PathBuf, String> {
    let root = packages.canonicalize().map_err(|error| error.to_string())?;
    let lock_path = root
        .join("locks")
        .join(&package.owner)
        .join(&package.name)
        .join(format!("{}.toml", package.version));
    let lock_text = fs::read_to_string(&lock_path).map_err(|error| error.to_string())?;
    let lock: PackageLock = toml::from_str(&lock_text).map_err(|error| error.to_string())?;
    if lock.wire_version != snolc::WIRE_VERSION
        || lock.package != *package
        || lock.target.is_empty()
    {
        return Err(format!(
            "package lock {} is incompatible",
            lock_path.display()
        ));
    }
    let lock_directory = lock_path.parent().ok_or("package lock has no parent")?;
    let library = lock_directory
        .join(lock.library)
        .canonicalize()
        .map_err(|error| error.to_string())?;
    if !library.starts_with(&root) {
        return Err("package library escapes package directory".into());
    }
    let bytes = fs::read(&library).map_err(|error| error.to_string())?;
    let digest = hex(&Sha256::digest(bytes));
    if digest != lock.content_sha256.to_ascii_lowercase() {
        return Err(format!(
            "package library hash mismatch: {}",
            library.display()
        ));
    }
    Ok(library)
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

fn absolute(path: &Path) -> Result<PathBuf, String> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        env::current_dir()
            .map(|directory| directory.join(path))
            .map_err(|error| error.to_string())
    }
}

struct CliHost;

impl Host for CliHost {
    fn engine_event(&self, event: &Event) {
        eprintln!("{event:?}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_and_usage_are_stable() {
        assert!(run(vec!["version".into()]).is_ok());
        assert!(run(Vec::new()).unwrap_err().starts_with("usage:"));
    }

    #[test]
    fn sha256_hex_has_fixed_width() {
        assert_eq!(hex(&[0, 255]), "00ff");
    }
}
