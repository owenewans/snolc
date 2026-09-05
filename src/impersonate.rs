//! Real, per-browser TLS `ClientHello` shapes for `steal` mode, built with
//! the same library (`boring`, Cloudflare's BoringSSL bindings) that real
//! Chrome releases are built on -- rather than the hand-shaped minimal hello
//! in [`crate::steal`], which uses a small, plausible but not
//! browser-accurate cipher/extension set.
//!
//! No real TLS session is ever completed here. `steal` mode's client side
//! is not a real TLS client: it sends one `ClientHello` record carrying a
//! tag in `session_id` and then immediately speaks the snolc protocol on
//! the same raw bytes -- there is no `ServerHello` to wait for when talking
//! to a real snolc server. So to get the exact bytes real BoringSSL would
//! put on the wire for a given fingerprint, this drives a real (and
//! intentionally never-finishing) handshake against a throwaway local
//! loopback listener and captures whatever the client wrote before it
//! blocked waiting for a response that will never come.
//!
//! `session_id` sits at a fixed byte offset (44..76) in every TLS 1.2/1.3
//! `ClientHello`, before any of the variable-length fields the fingerprint
//! actually varies (cipher suites, extensions, ALPN, curves...), so
//! [`crate::steal::patch_session_id_tag`] can overwrite it after the fact
//! regardless of which generator produced the rest of the record.

use boring::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};

use crate::config::Fingerprint;
use crate::error::{Error, Result};

/// Largest `ClientHello` this module will ever capture; real browser
/// hellos (with session tickets/GREASE/ALPN) are well under this.
const MAX_CAPTURED_HELLO: usize = 8192;

/// Builds the exact `ClientHello` bytes BoringSSL produces for `fingerprint`
/// with `sni` as the server name, or `Ok(None)` for [`Fingerprint::None`]
/// (the caller should use [`crate::steal::client_hello`]'s hand-built hello
/// instead).
pub async fn client_hello_bytes(fingerprint: Fingerprint, sni: &str) -> Result<Option<Vec<u8>>> {
    let profile = match fingerprint {
        Fingerprint::None => return Ok(None),
        Fingerprint::Chrome131 => Profile::chrome131(),
        Fingerprint::Firefox133 => Profile::firefox133(),
    };

    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let local = listener.local_addr()?;
    let capture = tokio::spawn(async move {
        let (mut accepted, _) = listener.accept().await?;
        let mut buffer = vec![0_u8; MAX_CAPTURED_HELLO];
        let length = accepted.read(&mut buffer).await?;
        buffer.truncate(length);
        std::io::Result::Ok(buffer)
    });

    let mut builder = SslConnector::builder(SslMethod::tls())
        .map_err(|error| Error::Protocol(format!("boring context: {error}")))?;
    profile.configure(&mut builder)?;
    builder.set_verify(SslVerifyMode::NONE);
    let connector = builder.build();
    let config = connector
        .configure()
        .map_err(|error| Error::Protocol(format!("boring connect configuration: {error}")))?;

    let stream = TcpStream::connect(local).await?;
    // The local peer never answers, so this handshake can never succeed;
    // we only care about the bytes written before it blocks on a read.
    let _ = tokio_boring::connect(config, sni, stream).await;

    let captured = capture
        .await
        .map_err(|error| Error::Protocol(format!("hello capture task failed: {error}")))??;
    if captured.is_empty() {
        return Err(Error::Protocol(
            "boring did not produce a ClientHello".to_owned(),
        ));
    }
    Ok(Some(captured))
}

/// One browser's real cipher/curve/signature-algorithm/ALPN shape, plus
/// whether it randomizes its own extension order (Chrome does, since
/// around version 110 -- matching that randomization, rather than a fixed
/// order, is itself part of a correct modern Chrome fingerprint, which is
/// exactly why JA4 hashes extensions unordered where JA3 did not).
struct Profile {
    ciphers: &'static str,
    curves: &'static str,
    sigalgs: &'static str,
    alpn: &'static [u8],
    permute_extensions: bool,
}

impl Profile {
    fn chrome131() -> Self {
        Self {
            ciphers: "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:\
                      ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
                      ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:\
                      ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:\
                      ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:\
                      AES256-GCM-SHA384:AES128-SHA:AES256-SHA",
            curves: "X25519:P-256:P-384",
            sigalgs: "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:\
                      ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:\
                      rsa_pss_rsae_sha512:rsa_pkcs1_sha512",
            alpn: b"\x02h2\x08http/1.1",
            permute_extensions: true,
        }
    }

    fn firefox133() -> Self {
        Self {
            ciphers: "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:\
                      ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
                      ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:\
                      ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:\
                      ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:\
                      AES256-GCM-SHA384:AES128-SHA:AES256-SHA",
            curves: "X25519:P-256:P-384:P-521",
            sigalgs: "ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512:\
                      rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:rsa_pss_rsae_sha512:\
                      rsa_pkcs1_sha256:rsa_pkcs1_sha384:rsa_pkcs1_sha512",
            alpn: b"\x02h2\x08http/1.1",
            // Firefox keeps a fixed extension order; randomizing it here
            // would be a Chrome-specific detail bleeding into the wrong
            // profile.
            permute_extensions: false,
        }
    }

    fn configure(&self, builder: &mut boring::ssl::SslConnectorBuilder) -> Result<()> {
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_2))
            .map_err(|error| Error::Protocol(format!("boring min version: {error}")))?;
        builder
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|error| Error::Protocol(format!("boring max version: {error}")))?;
        builder
            .set_cipher_list(self.ciphers)
            .map_err(|error| Error::Protocol(format!("boring ciphers: {error}")))?;
        builder
            .set_curves_list(self.curves)
            .map_err(|error| Error::Protocol(format!("boring curves: {error}")))?;
        builder
            .set_sigalgs_list(self.sigalgs)
            .map_err(|error| Error::Protocol(format!("boring sigalgs: {error}")))?;
        builder
            .set_alpn_protos(self.alpn)
            .map_err(|error| Error::Protocol(format!("boring alpn: {error}")))?;
        builder.set_grease_enabled(true);
        builder.set_permute_extensions(self.permute_extensions);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn none_fingerprint_defers_to_the_hand_built_hello() {
        assert!(
            client_hello_bytes(Fingerprint::None, "example.com")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn chrome_and_firefox_produce_a_real_tls_client_hello_record() {
        for fingerprint in [Fingerprint::Chrome131, Fingerprint::Firefox133] {
            let hello = client_hello_bytes(fingerprint, "donor.example")
                .await
                .unwrap()
                .expect("a real fingerprint always produces bytes");
            // TLS record header: handshake (0x16), legacy record version
            // 0x03 0x0X, then a 2-byte length.
            assert_eq!(hello[0], 0x16, "{fingerprint:?}: not a handshake record");
            assert_eq!(
                hello[1], 0x03,
                "{fingerprint:?}: unexpected record major version"
            );
            // Handshake header: ClientHello (0x01).
            assert_eq!(hello[5], 0x01, "{fingerprint:?}: not a ClientHello");
            // session_id length at byte 43 is always 32 for a fresh hello
            // (see steal::HELLO_PREFIX_LEN's derivation).
            assert_eq!(
                hello[43], 32,
                "{fingerprint:?}: unexpected session_id length"
            );
            assert!(hello.len() > 76, "{fingerprint:?}: hello too short");
        }
    }
}
