use std::env;
use std::fs;
use std::path::PathBuf;

use serde::Deserialize;
use snolpkg::{ExtractLimits, InstallOptions, install_binary, install_source};

fn main() {
    if let Err(error) = run(env::args().skip(1).collect()) {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run(arguments: Vec<String>) -> Result<(), String> {
    if arguments.as_slice() == ["version"] || arguments.as_slice() == ["--version"] {
        println!("snolpkg {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    match arguments.as_slice() {
        [command, mode, git, module] if command == "add" && mode == "-b" => {
            let root = package_root()?;
            let config: InstallerConfig = toml::from_str(
                &fs::read_to_string(root.join("snolpkg.toml"))
                    .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
            let result = install_binary(
                git,
                module,
                &InstallOptions {
                    root,
                    target: env!("SNOLPKG_TARGET").into(),
                    limits: config.limits(),
                    offline: config.offline,
                },
            )
            .map_err(|error| error.to_string())?;
            println!("{}", result.package);
            Ok(())
        }
        [command, mode, git, module] if command == "add" && mode == "-s" => {
            let root = package_root()?;
            let config: InstallerConfig = toml::from_str(
                &fs::read_to_string(root.join("snolpkg.toml"))
                    .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
            let result = install_source(
                git,
                module,
                &InstallOptions {
                    root,
                    target: env!("SNOLPKG_TARGET").into(),
                    limits: config.limits(),
                    offline: config.offline,
                },
            )
            .map_err(|error| error.to_string())?;
            println!("{}", result.package);
            Ok(())
        }
        _ => Err(usage().into()),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallerConfig {
    offline: bool,
    max_archive_files: usize,
    max_archive_bytes: u64,
    max_file_bytes: u64,
}

impl InstallerConfig {
    fn limits(&self) -> ExtractLimits {
        ExtractLimits {
            max_files: self.max_archive_files,
            max_total_bytes: self.max_archive_bytes,
            max_file_bytes: self.max_file_bytes,
        }
    }
}

fn package_root() -> Result<PathBuf, String> {
    let root = PathBuf::from(env::var_os("SNOLPKG_ROOT").ok_or("SNOLPKG_ROOT is required")?);
    if root.is_absolute() {
        Ok(root)
    } else {
        Err("SNOLPKG_ROOT must be absolute".into())
    }
}

fn usage() -> &'static str {
    "usage: snolpkg add -b|-s <git-url> <module-name> | del <installed-package> | template <installed-package> --role <role> --output <path>"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_requires_all_archive_limits() {
        let config: InstallerConfig = toml::from_str(
            "offline = false\nmax_archive_files = 64\nmax_archive_bytes = 1048576\nmax_file_bytes = 262144\n",
        )
        .unwrap();
        assert_eq!(config.limits().max_files, 64);
        assert!(toml::from_str::<InstallerConfig>("max_archive_files = 1").is_err());
    }

    #[test]
    fn unknown_command_returns_usage() {
        assert_eq!(run(Vec::new()).unwrap_err(), usage());
    }
}
