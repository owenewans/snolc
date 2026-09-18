use std::env;
use std::fs;
use std::io::Write;
use std::path::Path;

use snolc::{Deployment, Engine, Event, Host};

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
            let (config, modules) = load(Path::new(path))?.into_parts();
            Engine::validate(config, modules).map_err(|error| error.to_string())?;
            println!("valid");
            Ok(())
        }
        [command, path] if command == "run" => run_engine(Path::new(path)),
        [command, socket, instance, request] if command == "control" => {
            let request = fs::read(request).map_err(|error| error.to_string())?;
            if request.len() > 65_536 {
                return Err("control request exceeds 65536 bytes".into());
            }
            let response = snolc::control::request(
                Path::new(socket),
                instance,
                &request,
                65_536,
            )
            .map_err(|error| error.to_string())?;
            std::io::stdout()
                .write_all(&response)
                .map_err(|error| error.to_string())
        }
        _ => Err(
            "usage: snolc version | validate <snolc.toml> | run <snolc.toml> | control <socket> <instance> <request.toml>"
                .into(),
        ),
    }
}

fn run_engine(path: &Path) -> Result<(), String> {
    let (config, modules) = load(path)?.into_parts();
    let validated = Engine::validate(config, modules).map_err(|error| error.to_string())?;
    let (engine, handle) = Engine::build(validated, CliHost).map_err(|error| error.to_string())?;
    let shutdown = handle.clone();
    ctrlc::set_handler(move || {
        let _ = shutdown.shutdown();
    })
    .map_err(|error| error.to_string())?;
    engine.run().map_err(|error| error.to_string())
}

fn load(path: &Path) -> Result<Deployment, String> {
    Deployment::load(path).map_err(|error| error.to_string())
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
}
