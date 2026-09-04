//! "Self" TLS mode: a real, publicly trusted certificate obtained
//! autonomously from Let's Encrypt via TLS-ALPN-01, using `rustls-acme`.
//!
//! TLS-ALPN-01 validates by connecting to port 443 of the domain's resolved
//! address -- this is fixed by the ACME protocol, not a choice this crate
//! makes. [`crate::config::Config::validate`] enforces that `bind`/`remote`
//! use port 443 whenever this mode is selected.

use std::path::PathBuf;
use std::sync::Arc;

use rustls_acme::caches::DirCache;
use rustls_acme::{AcmeConfig, is_tls_alpn_challenge};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_rustls::LazyConfigAcceptor;
use tokio_stream::StreamExt;

use crate::carrier::BoxedStream;
use crate::error::{Error, Result};
use crate::logging::{Level, Logger};

pub struct AcmeAcceptor {
    challenge: Arc<rustls::ServerConfig>,
    default: Arc<rustls::ServerConfig>,
}

impl AcmeAcceptor {
    /// Starts autonomous certificate acquisition/renewal for `domain` in the
    /// background (spawns a task that drives issuance/renewal for the
    /// lifetime of the process) and returns an acceptor immediately;
    /// individual connections may arrive before the first certificate has
    /// been issued, in which case the TLS handshake with real clients will
    /// simply fail until issuance completes.
    pub fn start(domain: String, cache_dir: PathBuf, logger: Logger) -> Self {
        let mut state = AcmeConfig::new([domain])
            .cache(DirCache::new(cache_dir))
            .directory_lets_encrypt(true)
            .state();
        let challenge = state.challenge_rustls_config();
        let default = state.default_rustls_config();

        tokio::spawn(async move {
            loop {
                match state.next().await {
                    Some(Ok(event)) => {
                        logger.record(Level::Debug, &format!("acme: {event:?}"));
                    }
                    Some(Err(error)) => {
                        logger.record(Level::Warning, &format!("acme error: {error:?}"));
                    }
                    None => break,
                }
            }
        });

        Self { challenge, default }
    }

    /// Completes a TLS handshake on `stream`. TLS-ALPN-01 challenge
    /// connections from the CA are answered and then closed; the caller
    /// should treat [`None`] as "nothing more to do with this connection".
    pub async fn accept(&self, stream: TcpStream) -> Result<Option<BoxedStream>> {
        let start = LazyConfigAcceptor::new(Default::default(), stream)
            .await
            .map_err(|error| Error::Carrier(format!("TLS handshake failed: {error}")))?;

        if is_tls_alpn_challenge(&start.client_hello()) {
            let mut tls = start
                .into_stream(self.challenge.clone())
                .await
                .map_err(|error| {
                    Error::Carrier(format!("acme challenge handshake failed: {error}"))
                })?;
            let _ = tls.shutdown().await;
            return Ok(None);
        }

        let tls = start
            .into_stream(self.default.clone())
            .await
            .map_err(|error| Error::Carrier(format!("TLS handshake failed: {error}")))?;
        Ok(Some(Box::new(tls)))
    }
}

/// Connects to `remote` as a TLS client and verifies its certificate
/// against the public Web PKI root store -- appropriate here because, in
/// "self" mode, the server presents a real, publicly trusted certificate.
pub async fn connect(stream: TcpStream, domain: &str) -> Result<BoxedStream> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let server_name = rustls::pki_types::ServerName::try_from(domain.to_owned())
        .map_err(|_| Error::Carrier("invalid acme domain name".to_owned()))?;
    let tls = connector
        .connect(server_name, stream)
        .await
        .map_err(|error| Error::Carrier(format!("TLS handshake with {domain} failed: {error}")))?;
    Ok(Box::new(tls))
}
