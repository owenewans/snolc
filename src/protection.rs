use aes_gcm::aead::{AeadInOut, KeyInit};
use aes_gcm::{Aes256Gcm, Tag as AesTag};
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20poly1305::{ChaCha20Poly1305, Tag as ChaChaTag};
use hkdf::Hkdf;
use serde::Deserialize;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::frame::{Frame, FrameType};

pub const SESSION_KEY_LEN: usize = 32;
pub const AUTH_TAG_LEN: usize = 16;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
pub enum ProtectionMode {
    #[serde(rename = "chacha poly")]
    ChaChaPoly,
    #[serde(rename = "chacha")]
    ChaCha,
    #[serde(rename = "AES-GCM")]
    AesGcm,
    #[serde(rename = "no")]
    None,
}

impl ProtectionMode {
    pub const fn id(self) -> u8 {
        match self {
            Self::ChaChaPoly => 1,
            Self::ChaCha => 2,
            Self::AesGcm => 3,
            Self::None => 4,
        }
    }

    pub const fn tag_len(self) -> usize {
        match self {
            Self::ChaChaPoly | Self::AesGcm => AUTH_TAG_LEN,
            Self::ChaCha | Self::None => 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Side {
    Client,
    Server,
}

pub struct StreamProtector {
    mode: ProtectionMode,
    tx_key: Zeroizing<[u8; SESSION_KEY_LEN]>,
    rx_key: Zeroizing<[u8; SESSION_KEY_LEN]>,
    next_tx: Option<u64>,
    next_rx: Option<u64>,
}

impl StreamProtector {
    pub fn new(
        master: &[u8; SESSION_KEY_LEN],
        stream: u64,
        side: Side,
        mode: ProtectionMode,
    ) -> Result<Self> {
        let mut material = Zeroizing::new([0_u8; SESSION_KEY_LEN * 2]);
        let mut info = Vec::with_capacity(25);
        info.extend_from_slice(b"snolc/stream/v1");
        info.extend_from_slice(&stream.to_be_bytes());
        info.push(mode.id());
        Hkdf::<Sha256>::new(None, master)
            .expand(&info, material.as_mut())
            .map_err(|_| Error::Protocol("cannot derive stream keys".to_owned()))?;
        let c2s: [u8; SESSION_KEY_LEN] = material[..SESSION_KEY_LEN]
            .try_into()
            .map_err(|_| Error::Protocol("invalid client stream key".to_owned()))?;
        let s2c: [u8; SESSION_KEY_LEN] = material[SESSION_KEY_LEN..]
            .try_into()
            .map_err(|_| Error::Protocol("invalid server stream key".to_owned()))?;
        let (tx_key, rx_key) = match side {
            Side::Client => (c2s, s2c),
            Side::Server => (s2c, c2s),
        };
        Ok(Self {
            mode,
            tx_key: Zeroizing::new(tx_key),
            rx_key: Zeroizing::new(rx_key),
            next_tx: Some(0),
            next_rx: Some(0),
        })
    }

    pub fn seal(&mut self, kind: FrameType, flags: u8, plaintext: &[u8]) -> Result<Frame> {
        let sequence = self
            .next_tx
            .ok_or_else(|| Error::Protocol("send nonce is exhausted".to_owned()))?;
        let mut frame = Frame {
            kind,
            flags,
            sequence,
            payload: plaintext.to_vec(),
            tag: Vec::new(),
        };
        let aad = frame.header()?;
        frame.tag = seal_payload(self.mode, &self.tx_key, sequence, &aad, &mut frame.payload)?;
        self.next_tx = sequence.checked_add(1);
        Ok(frame)
    }

    pub const fn tag_len(&self) -> usize {
        self.mode.tag_len()
    }

    pub fn open(&mut self, mut frame: Frame) -> Result<Vec<u8>> {
        let expected = self
            .next_rx
            .ok_or_else(|| Error::Protocol("receive nonce is exhausted".to_owned()))?;
        if frame.sequence != expected {
            return Err(Error::Protocol("stream nonce mismatch".to_owned()));
        }
        if frame.tag.len() != self.mode.tag_len() {
            return Err(Error::Protocol(
                "invalid authentication tag length".to_owned(),
            ));
        }
        let aad = frame.header()?;
        open_payload(
            self.mode,
            &self.rx_key,
            frame.sequence,
            &aad,
            &mut frame.payload,
            &frame.tag,
        )?;
        self.next_rx = expected.checked_add(1);
        Ok(frame.payload)
    }
}

fn nonce(sequence: u64) -> [u8; 12] {
    let mut nonce = [0_u8; 12];
    nonce[4..].copy_from_slice(&sequence.to_be_bytes());
    nonce
}

fn seal_payload(
    mode: ProtectionMode,
    key: &[u8; SESSION_KEY_LEN],
    sequence: u64,
    aad: &[u8],
    payload: &mut [u8],
) -> Result<Vec<u8>> {
    let nonce = nonce(sequence);
    match mode {
        ProtectionMode::ChaChaPoly => {
            let cipher = ChaCha20Poly1305::new_from_slice(key)
                .map_err(|_| Error::Protocol("invalid ChaCha key".to_owned()))?;
            cipher
                .encrypt_inout_detached(&nonce.into(), aad, payload.into())
                .map(|tag| tag.to_vec())
                .map_err(|_| Error::Protocol("ChaCha encryption failed".to_owned()))
        }
        ProtectionMode::AesGcm => {
            let cipher = Aes256Gcm::new_from_slice(key)
                .map_err(|_| Error::Protocol("invalid AES key".to_owned()))?;
            cipher
                .encrypt_inout_detached(&nonce.into(), aad, payload.into())
                .map(|tag| tag.to_vec())
                .map_err(|_| Error::Protocol("AES encryption failed".to_owned()))
        }
        ProtectionMode::ChaCha => {
            let mut cipher = ChaCha20::new(key.into(), (&nonce).into());
            cipher.apply_keystream(payload);
            Ok(Vec::new())
        }
        ProtectionMode::None => Ok(Vec::new()),
    }
}

fn open_payload(
    mode: ProtectionMode,
    key: &[u8; SESSION_KEY_LEN],
    sequence: u64,
    aad: &[u8],
    payload: &mut [u8],
    tag: &[u8],
) -> Result<()> {
    let nonce = nonce(sequence);
    match mode {
        ProtectionMode::ChaChaPoly => {
            let cipher = ChaCha20Poly1305::new_from_slice(key)
                .map_err(|_| Error::Protocol("invalid ChaCha key".to_owned()))?;
            let tag: &ChaChaTag = tag
                .try_into()
                .map_err(|_| Error::Protocol("invalid ChaCha tag length".to_owned()))?;
            cipher
                .decrypt_inout_detached(&nonce.into(), aad, payload.into(), tag)
                .map_err(|_| Error::Authentication("invalid ChaCha tag".to_owned()))
        }
        ProtectionMode::AesGcm => {
            let cipher = Aes256Gcm::new_from_slice(key)
                .map_err(|_| Error::Protocol("invalid AES key".to_owned()))?;
            let tag: &AesTag = tag
                .try_into()
                .map_err(|_| Error::Protocol("invalid AES tag length".to_owned()))?;
            cipher
                .decrypt_inout_detached(&nonce.into(), aad, payload.into(), tag)
                .map_err(|_| Error::Authentication("invalid AES tag".to_owned()))
        }
        ProtectionMode::ChaCha => {
            let mut cipher = ChaCha20::new(key.into(), (&nonce).into());
            cipher.apply_keystream(payload);
            Ok(())
        }
        ProtectionMode::None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn modes() -> [ProtectionMode; 4] {
        [
            ProtectionMode::ChaChaPoly,
            ProtectionMode::ChaCha,
            ProtectionMode::AesGcm,
            ProtectionMode::None,
        ]
    }

    #[test]
    fn all_modes_round_trip_in_both_directions() {
        for mode in modes() {
            let master = [9_u8; SESSION_KEY_LEN];
            let mut client = StreamProtector::new(&master, 12, Side::Client, mode).unwrap();
            let mut server = StreamProtector::new(&master, 12, Side::Server, mode).unwrap();

            let request = client.seal(FrameType::Data, 0, b"request").unwrap();
            assert_eq!(server.open(request).unwrap(), b"request");
            let response = server.seal(FrameType::Data, 0, b"response").unwrap();
            assert_eq!(client.open(response).unwrap(), b"response");
        }
    }

    #[test]
    fn authenticated_modes_reject_tampering_without_advancing_nonce() {
        let master = [4_u8; SESSION_KEY_LEN];
        let mut client =
            StreamProtector::new(&master, 1, Side::Client, ProtectionMode::ChaChaPoly).unwrap();
        let mut server =
            StreamProtector::new(&master, 1, Side::Server, ProtectionMode::ChaChaPoly).unwrap();
        let frame = client.seal(FrameType::Data, 0, b"data").unwrap();
        let mut damaged = frame.clone();
        damaged.payload[0] ^= 1;
        assert!(server.open(damaged).is_err());
        assert_eq!(server.open(frame).unwrap(), b"data");
    }

    #[test]
    fn sequence_mismatch_is_fatal_for_the_frame() {
        let master = [1_u8; SESSION_KEY_LEN];
        let mut client =
            StreamProtector::new(&master, 3, Side::Client, ProtectionMode::None).unwrap();
        let mut server =
            StreamProtector::new(&master, 3, Side::Server, ProtectionMode::None).unwrap();
        let _first = client.seal(FrameType::Data, 0, b"first").unwrap();
        let second = client.seal(FrameType::Data, 0, b"second").unwrap();
        assert!(server.open(second).is_err());
    }
}
