//! Generic 1:1 mirroring of a real target: point at any address (a third
//! party's site, or `127.0.0.1`) and relay raw bytes to it unmodified, so
//! whoever is on the inbound side gets exactly what that target would have
//! sent them directly. Optionally caches the first response bytes per
//! request fingerprint so repeat requests are answered from memory without
//! touching the target again. The cache is in-memory only and never
//! persisted to disk.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::Result;

const MAX_CACHE_ENTRIES: usize = 256;
const MAX_CACHED_RESPONSE: usize = 256 * 1024;

type Fingerprint = [u8; 32];
type Entry = (Instant, Vec<u8>);

pub struct Cache {
    ttl: Duration,
    entries: Mutex<HashMap<Fingerprint, Entry>>,
}

impl Cache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn fingerprint(prefix: &[u8]) -> [u8; 32] {
        Sha256::digest(prefix).into()
    }

    fn get(&self, prefix: &[u8]) -> Option<Vec<u8>> {
        let key = Self::fingerprint(prefix);
        let mut entries = self.entries.lock().expect("mirror cache lock");
        match entries.get(&key) {
            Some((stored, response)) if stored.elapsed() < self.ttl => Some(response.clone()),
            Some(_) => {
                entries.remove(&key);
                None
            }
            None => None,
        }
    }

    fn put(&self, prefix: &[u8], response: Vec<u8>) {
        if response.is_empty() || response.len() > MAX_CACHED_RESPONSE {
            return;
        }
        let key = Self::fingerprint(prefix);
        let mut entries = self.entries.lock().expect("mirror cache lock");
        if entries.len() >= MAX_CACHE_ENTRIES && !entries.contains_key(&key) {
            // Simplicity over strict LRU ordering: drop one arbitrary entry
            // to keep the cache bounded.
            if let Some(evict) = entries.keys().next().copied() {
                entries.remove(&evict);
            }
        }
        entries.insert(key, (Instant::now(), response));
    }
}

/// Connects to `target`, forwards `prefix` (bytes already consumed from the
/// inbound connection) followed by a live bidirectional copy. No caching.
pub async fn splice(
    mut inbound: impl AsyncRead + AsyncWrite + Unpin,
    target: &str,
    prefix: &[u8],
) -> Result<()> {
    let mut outbound = TcpStream::connect(target).await?;
    outbound.set_nodelay(true)?;
    if !prefix.is_empty() {
        outbound.write_all(prefix).await?;
    }
    tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await?;
    Ok(())
}

/// Same as [`splice`], but replays a cached response for a `prefix` seen
/// before (within `cache`'s TTL) instead of recontacting `target`, and
/// captures new responses into the cache as they are relayed live.
///
/// Both directions are relayed concurrently for the lifetime of the
/// connection (not just an initial "request" burst): protocols like TLS and
/// HTTP/2 require the client to keep sending after the target's first
/// reply (a TLS `Finished` message, a stream request, ...), so the target
/// only ever gets a complete conversation if we forward continuously in
/// both directions from the start, not in two separate phases.
pub async fn serve(
    inbound: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    target: &str,
    prefix: &[u8],
    cache: Option<&Cache>,
) -> Result<()> {
    let Some(cache) = cache else {
        return splice(inbound, target, prefix).await;
    };
    if let Some(cached) = cache.get(prefix) {
        let mut inbound = inbound;
        inbound.write_all(&cached).await?;
        return Ok(());
    }

    let mut outbound = TcpStream::connect(target).await?;
    outbound.set_nodelay(true)?;
    if !prefix.is_empty() {
        outbound.write_all(prefix).await?;
    }

    let (mut inbound_reader, mut inbound_writer) = tokio::io::split(inbound);
    let (mut outbound_reader, mut outbound_writer) = outbound.into_split();

    let client_to_target = async move {
        let result = tokio::io::copy(&mut inbound_reader, &mut outbound_writer).await;
        let _ = outbound_writer.shutdown().await;
        result
    };
    let target_to_client = async move {
        let mut buffer = [0_u8; 4096];
        let mut captured = Vec::new();
        loop {
            let length = outbound_reader.read(&mut buffer).await?;
            if length == 0 {
                break;
            }
            inbound_writer.write_all(&buffer[..length]).await?;
            if captured.len() < MAX_CACHED_RESPONSE {
                captured.extend_from_slice(&buffer[..length]);
            }
        }
        let _ = inbound_writer.shutdown().await;
        Ok::<Vec<u8>, std::io::Error>(captured)
    };

    let (sent, received) = tokio::join!(client_to_target, target_to_client);
    sent?;
    let captured = received?;
    if !captured.is_empty() {
        cache.put(prefix, captured);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use tokio::net::TcpListener;

    use super::*;

    async fn echo_once_server() -> (TcpListener, std::net::SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        (listener, address)
    }

    #[tokio::test]
    async fn splice_forwards_the_prefix_and_relays_the_real_response() {
        let (listener, address) = echo_once_server().await;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 5];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"hello");
            stream.write_all(b"world").await.unwrap();
        });

        let (mut client, inbound_side) = tokio::io::duplex(64);
        let target = address.to_string();
        let relay = tokio::spawn(async move { splice(inbound_side, &target, b"hello").await });
        let mut response = [0_u8; 5];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"world");
        drop(client);
        relay.await.unwrap().unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn cached_response_is_replayed_without_recontacting_the_target() {
        let (listener, address) = echo_once_server().await;
        let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let hits_clone = hits.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            hits_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut request = [0_u8; 3];
            stream.read_exact(&mut request).await.unwrap();
            stream.write_all(b"cached-response").await.unwrap();
        });

        let cache = Cache::new(Duration::from_secs(60));
        let target = address.to_string();
        let (mut first_client, first_inbound) = tokio::io::duplex(64);
        let first_relay = tokio::spawn(async move {
            serve(first_inbound, &target, b"req", Some(&cache)).await?;
            Ok::<_, crate::error::Error>(cache)
        });
        let mut first_response = vec![0_u8; 15];
        first_client.read_exact(&mut first_response).await.unwrap();
        assert_eq!(&first_response, b"cached-response");
        // Signals "done sending" so the relay's client-to-target copy can
        // observe EOF and the whole `serve` call can complete.
        drop(first_client);
        let cache = first_relay.await.unwrap().unwrap();
        server.await.unwrap();
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);

        // Second call with the same prefix must not touch the (now closed)
        // listener at all; it can only succeed if it is served from cache.
        let (mut second_client, second_inbound) = tokio::io::duplex(64);
        serve(second_inbound, &address.to_string(), b"req", Some(&cache))
            .await
            .unwrap();
        let mut second_response = vec![0_u8; 15];
        second_client
            .read_exact(&mut second_response)
            .await
            .unwrap();
        assert_eq!(&second_response, b"cached-response");
    }

    #[tokio::test]
    async fn different_prefixes_are_not_confused_in_the_cache() {
        let cache = Cache::new(Duration::from_secs(60));
        assert!(cache.get(b"a").is_none());
        cache.put(b"a", b"response-a".to_vec());
        assert_eq!(cache.get(b"a").unwrap(), b"response-a");
        assert!(cache.get(b"b").is_none());
    }

    #[tokio::test]
    async fn expired_entries_are_not_replayed() {
        let cache = Cache::new(Duration::from_millis(1));
        cache.put(b"a", b"response".to_vec());
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert!(cache.get(b"a").is_none());
    }
}
