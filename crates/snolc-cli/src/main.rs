use std::env;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;

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
    let workers = load(path)?.into_parts().0.engine.worker_threads;
    if workers == 1 {
        return run_single_engine(path);
    }

    let path = path.to_path_buf();
    let (ready_tx, ready_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let cancelled = Arc::new(AtomicBool::new(false));
    let mut threads = Vec::with_capacity(workers);
    for index in 0..workers {
        let path = path.clone();
        let ready_tx = ready_tx.clone();
        let done_tx = done_tx.clone();
        let cancelled_worker = Arc::clone(&cancelled);
        match thread::Builder::new()
            .name(format!("snolc-{index}"))
            .spawn(move || {
                let result = build_engine(&path);
                match result {
                    Ok((mut engine, handle)) => {
                        engine.set_idle_wait(index != 0);
                        let _ = ready_tx.send(Ok(handle.clone()));
                        if cancelled_worker.load(Ordering::Acquire) {
                            let _ = handle.shutdown();
                        }
                        let _ = done_tx.send(engine.run().map_err(|error| error.to_string()));
                    }
                    Err(error) => {
                        cancelled_worker.store(true, Ordering::Release);
                        let _ = ready_tx.send(Err(error));
                    }
                }
            }) {
            Ok(thread) => threads.push(thread),
            Err(error) => {
                cancelled.store(true, Ordering::Release);
                let mut handles = Vec::new();
                for _ in 0..threads.len() {
                    if let Ok(Ok(handle)) = ready_rx.recv() {
                        handles.push(handle);
                    }
                }
                for handle in &handles {
                    let _ = handle.shutdown();
                }
                for thread in threads {
                    let _ = thread.join();
                }
                return Err(error.to_string());
            }
        }
    }
    drop(ready_tx);
    drop(done_tx);

    let mut handles = Vec::with_capacity(workers);
    let mut startup_error = None;
    for _ in 0..workers {
        match ready_rx.recv().map_err(|error| error.to_string())? {
            Ok(handle) => handles.push(handle),
            Err(error) => {
                cancelled.store(true, Ordering::Release);
                startup_error.get_or_insert(error);
            }
        }
    }
    if let Some(error) = startup_error {
        for handle in &handles {
            let _ = handle.shutdown();
        }
        for thread in threads {
            let _ = thread.join();
        }
        return Err(error);
    }
    let shutdown = Arc::new(handles);
    let signal_handles = Arc::clone(&shutdown);
    ctrlc::set_handler(move || {
        for handle in signal_handles.iter() {
            let _ = handle.shutdown();
        }
    })
    .map_err(|error| error.to_string())?;

    let first = done_rx.recv().map_err(|error| error.to_string())?;
    for handle in shutdown.iter() {
        let _ = handle.shutdown();
    }
    let mut result = first;
    for thread in threads {
        if thread.join().is_err() && result.is_ok() {
            result = Err("engine worker panicked".into());
        }
    }
    result
}

fn run_single_engine(path: &Path) -> Result<(), String> {
    let (engine, handle) = build_engine(path)?;
    let shutdown = handle.clone();
    ctrlc::set_handler(move || {
        let _ = shutdown.shutdown();
    })
    .map_err(|error| error.to_string())?;
    engine.run().map_err(|error| error.to_string())
}

fn build_engine(path: &Path) -> Result<(Engine, snolc::EngineHandle), String> {
    let (config, modules) = load(path)?.into_parts();
    let validated = Engine::validate(config, modules).map_err(|error| error.to_string())?;
    Engine::build(validated, CliHost).map_err(|error| error.to_string())
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
