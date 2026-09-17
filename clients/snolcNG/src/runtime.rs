use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};
use std::thread::JoinHandle;

use snolc::{Deployment, Engine, EngineHandle, Event, Host, Snapshot};
use thiserror::Error;

const EVENT_CAPACITY: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClientEvent {
    Starting,
    Engine(Event),
    Failed(String),
    Stopped,
}

enum RuntimeEvent {
    Starting,
    Ready(EngineHandle),
    Engine(Event),
    Failed(String),
    Stopped,
}

struct ClientHost {
    events: SyncSender<RuntimeEvent>,
    wake: Arc<dyn Fn() + Send + Sync>,
}

impl ClientHost {
    fn send(&self, event: RuntimeEvent) {
        let _ = self.events.try_send(event);
        (self.wake)();
    }
}

impl Host for ClientHost {
    fn engine_event(&self, event: &Event) {
        self.send(RuntimeEvent::Engine(event.clone()));
    }
}

pub struct EngineRuntime {
    sender: SyncSender<RuntimeEvent>,
    receiver: Receiver<RuntimeEvent>,
    wake: Arc<dyn Fn() + Send + Sync>,
    handle: Option<EngineHandle>,
    thread: Option<JoinHandle<()>>,
    active: bool,
    shutdown_pending: bool,
}

impl EngineRuntime {
    pub fn new(wake: impl Fn() + Send + Sync + 'static) -> Self {
        let (sender, receiver) = mpsc::sync_channel(EVENT_CAPACITY);
        Self {
            sender,
            receiver,
            wake: Arc::new(wake),
            handle: None,
            thread: None,
            active: false,
            shutdown_pending: false,
        }
    }

    pub fn start(&mut self, config: &Path) -> Result<(), RuntimeError> {
        self.reap();
        if self.active {
            return Err(RuntimeError::Running);
        }
        let config = absolute(config)?;
        let events = self.sender.clone();
        let wake = Arc::clone(&self.wake);
        self.active = true;
        self.thread = Some(
            std::thread::Builder::new()
                .name("snolc-engine".into())
                .spawn(move || run_engine(config, events, wake))?,
        );
        Ok(())
    }

    pub fn request_shutdown(&mut self) -> Result<(), RuntimeError> {
        if let Some(handle) = &self.handle {
            handle.request_shutdown()?;
        } else if self.active {
            self.shutdown_pending = true;
        }
        Ok(())
    }

    pub fn drain(&mut self) -> Vec<ClientEvent> {
        let mut output = Vec::new();
        loop {
            match self.receiver.try_recv() {
                Ok(RuntimeEvent::Starting) => output.push(ClientEvent::Starting),
                Ok(RuntimeEvent::Ready(handle)) => {
                    self.handle = Some(handle);
                    if self.shutdown_pending {
                        self.shutdown_pending = false;
                        if let Some(handle) = &self.handle {
                            let _ = handle.request_shutdown();
                        }
                    }
                }
                Ok(RuntimeEvent::Engine(event)) => output.push(ClientEvent::Engine(event)),
                Ok(RuntimeEvent::Failed(error)) => {
                    self.handle = None;
                    self.active = false;
                    output.push(ClientEvent::Failed(error));
                }
                Ok(RuntimeEvent::Stopped) => {
                    self.handle = None;
                    self.active = false;
                    output.push(ClientEvent::Stopped);
                }
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
            }
        }
        self.reap();
        output
    }

    pub fn snapshot(&self) -> Option<Snapshot> {
        self.handle.as_ref().map(EngineHandle::snapshot)
    }

    pub fn is_active(&self) -> bool {
        self.active
    }

    fn reap(&mut self) {
        if self.thread.as_ref().is_some_and(JoinHandle::is_finished)
            && let Some(thread) = self.thread.take()
        {
            let _ = thread.join();
        }
    }
}

impl Drop for EngineRuntime {
    fn drop(&mut self) {
        if let Some(handle) = &self.handle {
            let _ = handle.request_shutdown();
        }
    }
}

fn run_engine(
    config: PathBuf,
    events: SyncSender<RuntimeEvent>,
    wake: Arc<dyn Fn() + Send + Sync>,
) {
    send(&events, &wake, RuntimeEvent::Starting);
    let result: Result<(), String> = (|| {
        let (config, modules) = Deployment::load(&config)
            .map_err(|error| error.to_string())?
            .into_parts();
        let validated = Engine::validate(config, modules).map_err(|error| error.to_string())?;
        let host = ClientHost {
            events: events.clone(),
            wake: Arc::clone(&wake),
        };
        let (engine, handle) = Engine::build(validated, host).map_err(|error| error.to_string())?;
        send(&events, &wake, RuntimeEvent::Ready(handle));
        engine.run().map_err(|error| error.to_string())
    })();
    match result {
        Ok(()) => send(&events, &wake, RuntimeEvent::Stopped),
        Err(error) => send(&events, &wake, RuntimeEvent::Failed(error)),
    }
}

fn send(
    events: &SyncSender<RuntimeEvent>,
    wake: &Arc<dyn Fn() + Send + Sync>,
    event: RuntimeEvent,
) {
    let _ = events.try_send(event);
    wake();
}

fn absolute(path: &Path) -> Result<PathBuf, std::io::Error> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        std::env::current_dir().map(|directory| directory.join(path))
    }
}

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("engine is already running")]
    Running,
    #[error("engine runtime I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("engine command failed: {0}")]
    Engine(#[from] snolc::EngineError),
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    use super::*;

    #[test]
    fn deployment_failure_returns_asynchronous_client_event() {
        let wakes = Arc::new(AtomicUsize::new(0));
        let wake_count = Arc::clone(&wakes);
        let mut runtime = EngineRuntime::new(move || {
            wake_count.fetch_add(1, Ordering::Relaxed);
        });
        runtime
            .start(Path::new("/missing/snolcNG-test-config.toml"))
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut events = Vec::new();
        while Instant::now() < deadline {
            events.extend(runtime.drain());
            if events
                .iter()
                .any(|event| matches!(event, ClientEvent::Failed(_)))
            {
                break;
            }
            std::thread::yield_now();
        }
        assert!(events.contains(&ClientEvent::Starting));
        assert!(
            events
                .iter()
                .any(|event| matches!(event, ClientEvent::Failed(error) if error.contains("I/O")))
        );
        assert!(!runtime.is_active());
        assert!(wakes.load(Ordering::Relaxed) >= 2);
    }
}
