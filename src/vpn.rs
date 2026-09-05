//! Hooks supplied by an embedding VPN application.
//!
//! Android's `VpnService` must exempt the proxy's own carrier and direct
//! sockets from the VPN before they connect, otherwise those connections are
//! captured by the TUN device again. The Java/Kotlin bridge installs a
//! process-wide callback here and forwards each descriptor to
//! `VpnService.protect(int)`.

use std::io;
use std::os::fd::RawFd;
use std::sync::{Arc, RwLock};

use crate::error::{Error, Result};

/// Callback invoked for each externally routed socket before it is used.
///
/// It may be called concurrently from arbitrary runtime threads. The
/// descriptor is borrowed only for the duration of the call and must not be
/// retained or closed by the callback.
pub type SocketProtector = Arc<dyn Fn(RawFd) -> io::Result<()> + Send + Sync + 'static>;

static SOCKET_PROTECTOR: RwLock<Option<SocketProtector>> = RwLock::new(None);

/// Replaces the process-wide socket protector and returns the previous one.
///
/// An Android embedding should install this before calling
/// [`crate::runtime::run`]. Passing `None` restores the default no-op behavior.
pub fn set_socket_protector(protector: Option<SocketProtector>) -> Option<SocketProtector> {
    let mut current = SOCKET_PROTECTOR
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    std::mem::replace(&mut *current, protector)
}

pub(crate) fn protect_socket(descriptor: RawFd) -> Result<()> {
    let protector = SOCKET_PROTECTOR
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    invoke_socket_protector(protector.as_ref(), descriptor)
}

fn invoke_socket_protector(protector: Option<&SocketProtector>, descriptor: RawFd) -> Result<()> {
    let Some(protector) = protector else {
        return Ok(());
    };
    protector(descriptor).map_err(|error| {
        Error::Permission(format!(
            "socket protector rejected descriptor {descriptor}: {error}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_protector_is_a_no_op() {
        invoke_socket_protector(None, 7).unwrap();
    }

    #[test]
    fn protector_failure_is_reported_as_a_permission_error() {
        let protector: SocketProtector =
            Arc::new(|_| Err(io::Error::other("VpnService.protect returned false")));
        let error = invoke_socket_protector(Some(&protector), 7).unwrap_err();
        assert!(matches!(
            error,
            Error::Permission(message)
                if message.contains("descriptor 7") && message.contains("returned false")
        ));
    }
}
