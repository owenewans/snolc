#![deny(unsafe_op_in_unsafe_fn)]

pub mod config;
pub mod control;
mod core_io;
pub mod deployment;
mod engine;
pub mod events;
pub mod loader;
pub mod logging;
pub mod module_config;
pub mod mux;
pub mod stack;
pub mod wire;

pub use deployment::{Deployment, DeploymentError};
pub use engine::{Engine, EngineError, EngineHandle, Host, ResponseFuture, ValidatedConfig};
pub use events::{Event, EventReceiver, Lifecycle, PlatformEvent, Snapshot};
pub use snolc_abi::{CLASS_ADAPTER, CLASS_CARRIER, CLASS_POLICY, CLASS_PROTECTION, WIRE_VERSION};
