pub mod acme;
pub mod carrier;
pub mod cli;
pub mod config;
pub mod error;
pub mod fragment;
pub mod frame;
pub mod handshake;
pub mod identity;
pub mod impersonate;
pub mod inbound;
pub mod logging;
pub mod mirror;
pub mod mux;
pub mod outbound;
pub mod protection;
pub mod routing;
pub mod runtime;
pub mod ssh;
pub mod steal;
pub mod tun;
pub mod tunnel;
pub mod vpn;
pub mod webrtc;
pub mod wire_io;

pub const COMMIT_VERSION: &str = env!("SNOLC_COMMIT");
/// Bumped whenever a change makes this build's config or wire behavior
/// incompatible with a previous release; a client and server built with
/// different values are expected not to interoperate correctly.
pub const WIRE_VERSION: u32 = 2;
