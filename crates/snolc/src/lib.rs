#![deny(unsafe_op_in_unsafe_fn)]

pub mod config;
mod engine;
pub mod events;
pub mod loader;
pub mod logging;
pub mod module_config;
pub mod mux;
pub mod stack;
pub mod wire;

pub use engine::{Engine, EngineError, EngineHandle, Host, ResponseFuture, ValidatedConfig};
pub use events::{Event, EventReceiver, Lifecycle, Snapshot};
pub use snolc_abi::{CLASS_ADAPTER, CLASS_CARRIER, CLASS_POLICY, CLASS_PROTECTION, WIRE_VERSION};
