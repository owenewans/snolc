//! REALITY-style TLS camouflage.
//!
//! The client sends a syntactically valid TLS 1.3 `ClientHello` for
//! `donor`'s SNI. Its `session_id` field (32 bytes, which real TLS 1.3
//! clients commonly fill with random bytes for middlebox compatibility
//! anyway) carries `HMAC-SHA256(secret, "snolc/steal/v1" || donor ||
//! time_bucket)`.
//!
//! The server reads only the first 76 bytes of the connection -- exactly
//! enough to reach the end of the fixed-position `session_id` field -- and
//! checks the tag. On a match it discards the remainder of the declared TLS
//! record (so the byte stream is left aligned right before whatever comes
//! next) and switches straight to the snolc wire protocol: no TLS
//! handshake is ever completed with the real client. On a mismatch -- a
//! real browser, a scanner, or a censor actively probing the server -- the
//! bytes already read are handed back as a prefix and the caller splices
//! the connection to `donor` (see [`crate::mirror`]), so the far end gets
//! `donor`'s genuine TLS session, byte for byte.
//!
//! This is *not* a byte-perfect JA3/JA4 clone of any specific browser: the
//! cipher suite and extension list are a small, plausible, hand-picked set,
//! not an emulation of Chrome/Firefox's exact fingerprint. A DPI system
//! fingerprinting at that level of detail could still flag it. Matching a
//! specific browser fingerprint would require a uTLS-style stack such as
//! `wreq`/`boring`, which is not wired into the carrier layer yet.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::error::{Error, Result};

type HmacSha256 = Hmac<Sha256>;

const CONTEXT: &[u8] = b"snolc/steal/v1";
const TIME_WINDOW_SECS: u64 = 30;
/// Bytes needed to reach the end of the fixed-position `session_id` field:
/// 5 (record header) + 1 (handshake type) + 3 (handshake length) +
/// 2 (legacy_version) + 32 (random) + 1 (session_id length) + 32 (session_id).
const HELLO_PREFIX_LEN: usize = 76;
const MAX_RECORD_BODY: usize = 4096;

const CIPHER_SUITES: [u16; 3] = [0x1301, 0x1302, 0x1303];
const SIGNATURE_ALGORITHMS: [u16; 3] = [0x0403, 0x0804, 0x0807];
const SUPPORTED_GROUP_X25519: u16 = 0x001d;

pub enum Accept {
    /// The session_id tag matched: the TLS record has been fully consumed
    /// and the caller should proceed directly with the snolc handshake.
    Authenticated,
    /// No match. `prefix` is every byte already read from the connection.
    /// When `complete` is true, `prefix` holds the *entire* declared TLS
    /// record (a real, self-contained `ClientHello`); it is safe to treat
    /// as one complete request for response caching. When false (the input
    /// was not TLS-shaped, or the record was rejected as unreasonably
    /// large), `prefix` is only a partial read and the caller must fall
    /// back to a live, uncached splice.
    Unauthenticated { prefix: Vec<u8>, complete: bool },
}

/// Builds a complete, correctly length-prefixed TLS 1.3 `ClientHello` for
/// `donor`, with the auth tag embedded in `session_id`.
pub fn client_hello(donor: &str, secret: &[u8; 32]) -> Result<Vec<u8>> {
    if donor.is_empty() || donor.len() > 255 {
        return Err(Error::Protocol("invalid steal donor".to_owned()));
    }
    let session_id = tag(secret, donor, current_bucket());

    let mut random = [0_u8; 32];
    getrandom::fill(&mut random).map_err(|error| Error::Protocol(error.to_string()))?;

    let mut body = Vec::with_capacity(200);
    body.extend_from_slice(&[0x03, 0x03]); // legacy_version
    body.extend_from_slice(&random);
    body.push(32);
    body.extend_from_slice(&session_id);

    body.extend_from_slice(&u16_prefixed(
        &CIPHER_SUITES
            .iter()
            .flat_map(|s| s.to_be_bytes())
            .collect::<Vec<_>>(),
    ));
    body.push(1);
    body.push(0x00); // compression methods: [null]

    let mut extensions = Vec::with_capacity(120);
    extensions.extend_from_slice(&extension(0x0000, &server_name(donor)));
    extensions.extend_from_slice(&extension(0x002b, &u8_prefixed(&[0x03, 0x04])));
    extensions.extend_from_slice(&extension(
        0x000a,
        &u16_prefixed(&SUPPORTED_GROUP_X25519.to_be_bytes()),
    ));
    let mut key = [0_u8; 32];
    getrandom::fill(&mut key).map_err(|error| Error::Protocol(error.to_string()))?;
    let mut key_share_entry = SUPPORTED_GROUP_X25519.to_be_bytes().to_vec();
    key_share_entry.extend_from_slice(&u16_prefixed(&key));
    extensions.extend_from_slice(&extension(0x0033, &u16_prefixed(&key_share_entry)));
    extensions.extend_from_slice(&extension(
        0x000d,
        &u16_prefixed(
            &SIGNATURE_ALGORITHMS
                .iter()
                .flat_map(|a| a.to_be_bytes())
                .collect::<Vec<_>>(),
        ),
    ));
    extensions.extend_from_slice(&extension(0x0010, &alpn(&["h2", "http/1.1"])));
    body.extend_from_slice(&u16_prefixed(&extensions));

    let mut handshake = vec![0x01]; // ClientHello
    handshake.extend_from_slice(&u24(body.len()));
    handshake.extend_from_slice(&body);

    let mut record = vec![0x16, 0x03, 0x01]; // handshake, legacy record version
    record.extend_from_slice(
        &u16::try_from(handshake.len())
            .map_err(|_| Error::Protocol("steal ClientHello is too large".to_owned()))?
            .to_be_bytes(),
    );
    record.extend_from_slice(&handshake);
    Ok(record)
}

/// Overwrites the `session_id` field (always at the fixed byte range
/// 44..76 of a real TLS 1.2/1.3 `ClientHello`, regardless of which
/// generator produced the rest of the record -- see
/// [`crate::impersonate`]) with the auth tag for `donor`/`secret`.
///
/// Used for both the hand-built hello above (where it's redundant with the
/// tag already written directly into `body`, but exercised the same way
/// for a single code path) and for a real browser-shaped hello produced by
/// [`crate::impersonate::client_hello_bytes`].
pub fn patch_session_id_tag(record: &mut [u8], donor: &str, secret: &[u8; 32]) -> Result<()> {
    if record.len() < HELLO_PREFIX_LEN || record[0] != 0x16 || record[5] != 0x01 || record[43] != 32
    {
        return Err(Error::Protocol(
            "not a well-formed ClientHello record".to_owned(),
        ));
    }
    record[44..76].copy_from_slice(&tag(secret, donor, current_bucket()));
    Ok(())
}

/// Reads the fixed-position prefix of an incoming connection and decides
/// whether it carries a valid auth tag for `secret`/`donor`. On success, any
/// remaining bytes of the declared TLS record are also consumed so the
/// stream is left aligned for the snolc handshake that follows.
pub async fn accept<S>(stream: &mut S, secret: &[u8; 32], donor: &str) -> Result<Accept>
where
    S: AsyncRead + Unpin,
{
    let mut prefix = Vec::with_capacity(HELLO_PREFIX_LEN);
    while prefix.len() < HELLO_PREFIX_LEN {
        let mut chunk = [0_u8; HELLO_PREFIX_LEN];
        let want = HELLO_PREFIX_LEN - prefix.len();
        match stream.read(&mut chunk[..want]).await {
            Ok(0) => break,
            Ok(read) => prefix.extend_from_slice(&chunk[..read]),
            Err(error) => return Err(error.into()),
        }
    }

    if prefix.len() != HELLO_PREFIX_LEN
        || prefix[0] != 0x16
        || prefix[5] != 0x01
        || prefix[43] != 32
    {
        // Not TLS-shaped (or too short to tell): only a partial read is
        // available, so the caller must fall back to a live splice.
        return Ok(Accept::Unauthenticated {
            prefix,
            complete: false,
        });
    }

    // Consumed so far, past the 5-byte record header: handshake header (4) +
    // legacy_version (2) + random (32) + session_id_len (1) + session_id (32).
    let consumed_from_body = 71;
    let record_body_len = u16::from_be_bytes([prefix[3], prefix[4]]) as usize;
    let remaining = match record_body_len.checked_sub(consumed_from_body) {
        Some(remaining) if remaining <= MAX_RECORD_BODY => remaining,
        // A malformed or unreasonably large declared length: still
        // TLS-shaped enough to be worth mirroring, but we cannot safely
        // read "the rest of the record" for it, so only relay live.
        _ => {
            return Ok(Accept::Unauthenticated {
                prefix,
                complete: false,
            });
        }
    };

    let session_id: [u8; 32] = prefix[44..76].try_into().expect("checked prefix length");
    let expected_current = tag(secret, donor, current_bucket());
    let expected_previous = tag(secret, donor, current_bucket().saturating_sub(1));
    let matches = bool::from(session_id.ct_eq(&expected_current))
        | bool::from(session_id.ct_eq(&expected_previous));

    if matches {
        let mut discard = vec![0_u8; remaining];
        stream.read_exact(&mut discard).await?;
        return Ok(Accept::Authenticated);
    }

    // A real ClientHello for someone else: read the rest of the declared
    // record too, so `prefix` is the complete, self-contained request and
    // the caller can safely relay it (and cache the response) as one unit.
    let mut rest = vec![0_u8; remaining];
    match stream.read_exact(&mut rest).await {
        Ok(_) => {
            prefix.extend_from_slice(&rest);
            Ok(Accept::Unauthenticated {
                prefix,
                complete: true,
            })
        }
        Err(_) => Ok(Accept::Unauthenticated {
            prefix,
            complete: false,
        }),
    }
}

fn tag(secret: &[u8; 32], donor: &str, bucket: u64) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(CONTEXT);
    mac.update(donor.as_bytes());
    mac.update(&bucket.to_be_bytes());
    mac.finalize().into_bytes().into()
}

fn current_bucket() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time precedes the Unix epoch")
        .as_secs()
        / TIME_WINDOW_SECS
}

fn server_name(donor: &str) -> Vec<u8> {
    let mut entry = vec![0x00]; // name_type: host_name
    entry.extend_from_slice(&u16_prefixed(donor.as_bytes()));
    u16_prefixed(&entry)
}

fn alpn(protocols: &[&str]) -> Vec<u8> {
    let mut list = Vec::new();
    for protocol in protocols {
        list.extend_from_slice(&u8_prefixed(protocol.as_bytes()));
    }
    u16_prefixed(&list)
}

fn extension(kind: u16, body: &[u8]) -> Vec<u8> {
    let mut out = kind.to_be_bytes().to_vec();
    out.extend_from_slice(&u16_prefixed(body));
    out
}

fn u8_prefixed(body: &[u8]) -> Vec<u8> {
    let mut out = vec![body.len() as u8];
    out.extend_from_slice(body);
    out
}

fn u16_prefixed(body: &[u8]) -> Vec<u8> {
    let mut out = (body.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(body);
    out
}

fn u24(value: usize) -> [u8; 3] {
    let bytes = (value as u32).to_be_bytes();
    [bytes[1], bytes[2], bytes[3]]
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncWriteExt;

    use super::*;

    /// Feeds `bytes` through a duplex pipe (the same style used elsewhere in
    /// this crate) so `accept` sees a real `AsyncRead`, then drops the write
    /// half so subsequent reads observe EOF once `bytes` is exhausted.
    async fn reader_for(bytes: Vec<u8>) -> tokio::io::DuplexStream {
        let (mut writer, reader) = tokio::io::duplex(bytes.len().max(1) + 64);
        writer.write_all(&bytes).await.unwrap();
        drop(writer);
        reader
    }

    #[tokio::test]
    async fn matching_secret_authenticates_and_leaves_the_stream_aligned() {
        let secret = [7_u8; 32];
        let mut hello = client_hello("petrovich.ru", &secret).unwrap();
        hello.extend_from_slice(b"SNLC-FOLLOWS");
        let mut stream = reader_for(hello).await;

        let outcome = accept(&mut stream, &secret, "petrovich.ru").await.unwrap();
        assert!(matches!(outcome, Accept::Authenticated));

        let mut rest = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut rest)
            .await
            .unwrap();
        assert_eq!(rest, b"SNLC-FOLLOWS");
    }

    #[tokio::test]
    async fn wrong_secret_falls_back_to_the_complete_donor_hello() {
        let full_hello = client_hello("petrovich.ru", &[1_u8; 32]).unwrap();
        let mut stream = reader_for(full_hello.clone()).await;

        let outcome = accept(&mut stream, &[2_u8; 32], "petrovich.ru")
            .await
            .unwrap();
        let Accept::Unauthenticated { prefix, complete } = outcome else {
            panic!("expected an unauthenticated outcome for the wrong secret");
        };
        // The whole ClientHello record must be captured (not just the first
        // 76 bytes), so the caller can hand a complete request to the donor
        // and safely cache its response.
        assert!(complete);
        assert_eq!(prefix, full_hello);
    }

    #[tokio::test]
    async fn wrong_donor_in_the_tag_is_rejected_even_with_the_right_secret() {
        let secret = [9_u8; 32];
        let hello = client_hello("petrovich.ru", &secret).unwrap();
        let mut stream = reader_for(hello).await;

        let outcome = accept(&mut stream, &secret, "different.example")
            .await
            .unwrap();
        assert!(matches!(outcome, Accept::Unauthenticated { .. }));
    }

    #[tokio::test]
    async fn a_short_or_non_tls_connection_returns_whatever_was_read() {
        let mut stream = reader_for(b"GET / HTTP/1.1\r\n".to_vec()).await;
        let outcome = accept(&mut stream, &[3_u8; 32], "petrovich.ru")
            .await
            .unwrap();
        let Accept::Unauthenticated { prefix, complete } = outcome else {
            panic!("expected an unauthenticated outcome for non-TLS input");
        };
        assert!(!complete);
        assert_eq!(prefix, b"GET / HTTP/1.1\r\n");
    }

    #[tokio::test]
    async fn a_real_browser_shaped_hello_authenticates_the_same_way() {
        use crate::config::Fingerprint;
        use crate::impersonate::client_hello_bytes;

        let secret = [11_u8; 32];
        for fingerprint in [Fingerprint::Chrome131, Fingerprint::Firefox133] {
            let mut hello = client_hello_bytes(fingerprint, "petrovich.ru")
                .await
                .unwrap()
                .expect("a real fingerprint always produces bytes");
            patch_session_id_tag(&mut hello, "petrovich.ru", &secret).unwrap();
            hello.extend_from_slice(b"SNLC-FOLLOWS");
            let mut stream = reader_for(hello).await;

            let outcome = accept(&mut stream, &secret, "petrovich.ru").await.unwrap();
            assert!(
                matches!(outcome, Accept::Authenticated),
                "{fingerprint:?} hello was not authenticated"
            );

            let mut rest = Vec::new();
            tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut rest)
                .await
                .unwrap();
            assert_eq!(rest, b"SNLC-FOLLOWS");
        }
    }

    #[test]
    #[ignore = "manual: dumps bytes for a live real-TLS-server sanity check"]
    fn dump_client_hello_for_manual_inspection() {
        let bytes = client_hello("petrovich.ru", &[5_u8; 32]).unwrap();
        std::fs::write("/tmp/opencode/steal-client-hello.bin", &bytes).unwrap();
        println!("wrote {} bytes", bytes.len());
    }

    #[test]
    fn the_previous_time_bucket_is_still_accepted_for_clock_skew() {
        let secret = [4_u8; 32];
        let previous = tag(&secret, "petrovich.ru", current_bucket().saturating_sub(1));
        let current = tag(&secret, "petrovich.ru", current_bucket());
        assert_ne!(previous, current);
    }
}
