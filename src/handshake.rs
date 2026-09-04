use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroizing;

use crate::WIRE_VERSION;
use crate::error::{Error, Result};
use crate::identity::{IDENTITY_KEY_LEN, Identity, SIGNATURE_LEN, verify};
use crate::protection::{ProtectionMode, SESSION_KEY_LEN};

const RANDOM_LEN: usize = 32;
const EPHEMERAL_LEN: usize = 32;
const CLIENT_HELLO_LEN: usize = 1 + IDENTITY_KEY_LEN + EPHEMERAL_LEN + RANDOM_LEN + SIGNATURE_LEN;
const SERVER_HELLO_LEN: usize = EPHEMERAL_LEN + RANDOM_LEN + 32;
const FINISH_LEN: usize = 32;
const CLIENT_CONTEXT: &[u8] = b"snolc/client-hello/v1";

type HmacSha256 = Hmac<Sha256>;

pub struct ClientHandshake {
    identity_public: [u8; IDENTITY_KEY_LEN],
    ephemeral: EphemeralSecret,
    ephemeral_public: [u8; EPHEMERAL_LEN],
    random: [u8; RANDOM_LEN],
    mode: ProtectionMode,
}

pub struct ServerPending {
    identity: [u8; IDENTITY_KEY_LEN],
    master: Zeroizing<[u8; SESSION_KEY_LEN]>,
    finish_key: Zeroizing<[u8; SESSION_KEY_LEN]>,
    transcript: Vec<u8>,
}

pub struct ClientEstablished {
    pub master: Zeroizing<[u8; SESSION_KEY_LEN]>,
    pub finish: [u8; FINISH_LEN],
}

/// Reads the client identity out of a `ClientHello` payload without verifying
/// its signature. Used by the server to decide, before running the full
/// handshake, whether the identity is on the allowed list.
pub fn peek_client_identity(hello: &[u8]) -> Result<[u8; IDENTITY_KEY_LEN]> {
    if hello.len() != CLIENT_HELLO_LEN {
        return Err(Error::Protocol("invalid client hello length".to_owned()));
    }
    hello[1..33]
        .try_into()
        .map_err(|_| Error::Protocol("invalid identity key".to_owned()))
}

impl ClientHandshake {
    pub fn start(identity: &Identity, mode: ProtectionMode) -> Result<(Self, Vec<u8>)> {
        let ephemeral = EphemeralSecret::random();
        let ephemeral_public = PublicKey::from(&ephemeral).to_bytes();
        let mut random = [0_u8; RANDOM_LEN];
        getrandom::fill(&mut random).map_err(|error| Error::Authentication(error.to_string()))?;
        let identity_public = identity.public();
        let signed = client_signed_message(mode, &identity_public, &ephemeral_public, &random);
        let signature = identity.sign(&signed);

        let mut hello = Vec::with_capacity(CLIENT_HELLO_LEN);
        hello.push(mode.id());
        hello.extend_from_slice(&identity_public);
        hello.extend_from_slice(&ephemeral_public);
        hello.extend_from_slice(&random);
        hello.extend_from_slice(&signature);
        Ok((
            Self {
                identity_public,
                ephemeral,
                ephemeral_public,
                random,
                mode,
            },
            hello,
        ))
    }

    pub fn complete(self, server_hello: &[u8]) -> Result<ClientEstablished> {
        if server_hello.len() != SERVER_HELLO_LEN {
            return Err(Error::Protocol("invalid server hello length".to_owned()));
        }
        let server_public: [u8; EPHEMERAL_LEN] = server_hello[..EPHEMERAL_LEN]
            .try_into()
            .map_err(|_| Error::Protocol("invalid server ephemeral key".to_owned()))?;
        let server_random: [u8; RANDOM_LEN] = server_hello
            [EPHEMERAL_LEN..EPHEMERAL_LEN + RANDOM_LEN]
            .try_into()
            .map_err(|_| Error::Protocol("invalid server random".to_owned()))?;
        let shared = self
            .ephemeral
            .diffie_hellman(&PublicKey::from(server_public));
        if !shared.was_contributory() {
            return Err(Error::Authentication(
                "non-contributory server key".to_owned(),
            ));
        }
        let transcript = transcript(
            self.mode,
            &self.identity_public,
            &self.ephemeral_public,
            &self.random,
            &server_public,
            &server_random,
        );
        let secrets = derive_secrets(shared.as_bytes(), &transcript)?;
        verify_mac(
            &secrets.server_key[..],
            b"server",
            &transcript,
            &server_hello[EPHEMERAL_LEN + RANDOM_LEN..],
        )?;
        let finish = calculate_mac(&secrets.finish_key[..], b"client", &transcript)?;
        Ok(ClientEstablished {
            master: secrets.master,
            finish,
        })
    }
}

pub fn accept_client(
    hello: &[u8],
    expected_mode: ProtectionMode,
    allowed: &[[u8; IDENTITY_KEY_LEN]],
) -> Result<(Vec<u8>, ServerPending)> {
    if hello.len() != CLIENT_HELLO_LEN {
        return Err(Error::Protocol("invalid client hello length".to_owned()));
    }
    if hello[0] != expected_mode.id() {
        return Err(Error::Protocol("protection mode mismatch".to_owned()));
    }
    let identity_public: [u8; IDENTITY_KEY_LEN] = hello[1..33]
        .try_into()
        .map_err(|_| Error::Protocol("invalid identity key".to_owned()))?;
    if !allowed.iter().any(|key| key == &identity_public) {
        return Err(Error::Authentication("unknown client key".to_owned()));
    }
    let client_public: [u8; EPHEMERAL_LEN] = hello[33..65]
        .try_into()
        .map_err(|_| Error::Protocol("invalid client ephemeral key".to_owned()))?;
    let client_random: [u8; RANDOM_LEN] = hello[65..97]
        .try_into()
        .map_err(|_| Error::Protocol("invalid client random".to_owned()))?;
    let signature: [u8; SIGNATURE_LEN] = hello[97..]
        .try_into()
        .map_err(|_| Error::Protocol("invalid client signature".to_owned()))?;
    let signed = client_signed_message(
        expected_mode,
        &identity_public,
        &client_public,
        &client_random,
    );
    verify(&identity_public, &signed, &signature)?;

    let ephemeral = EphemeralSecret::random();
    let server_public = PublicKey::from(&ephemeral).to_bytes();
    let mut server_random = [0_u8; RANDOM_LEN];
    getrandom::fill(&mut server_random)
        .map_err(|error| Error::Authentication(error.to_string()))?;
    let shared = ephemeral.diffie_hellman(&PublicKey::from(client_public));
    if !shared.was_contributory() {
        return Err(Error::Authentication(
            "non-contributory client key".to_owned(),
        ));
    }
    let transcript = transcript(
        expected_mode,
        &identity_public,
        &client_public,
        &client_random,
        &server_public,
        &server_random,
    );
    let secrets = derive_secrets(shared.as_bytes(), &transcript)?;
    let server_mac = calculate_mac(&secrets.server_key[..], b"server", &transcript)?;
    let mut response = Vec::with_capacity(SERVER_HELLO_LEN);
    response.extend_from_slice(&server_public);
    response.extend_from_slice(&server_random);
    response.extend_from_slice(&server_mac);
    Ok((
        response,
        ServerPending {
            identity: identity_public,
            master: secrets.master,
            finish_key: secrets.finish_key,
            transcript,
        },
    ))
}

impl ServerPending {
    pub const fn identity(&self) -> [u8; IDENTITY_KEY_LEN] {
        self.identity
    }

    pub fn finish(self, finish: &[u8]) -> Result<Zeroizing<[u8; SESSION_KEY_LEN]>> {
        if finish.len() != FINISH_LEN {
            return Err(Error::Protocol("invalid client finish length".to_owned()));
        }
        verify_mac(&self.finish_key[..], b"client", &self.transcript, finish)?;
        Ok(self.master)
    }
}

struct HandshakeSecrets {
    master: Zeroizing<[u8; SESSION_KEY_LEN]>,
    server_key: Zeroizing<[u8; SESSION_KEY_LEN]>,
    finish_key: Zeroizing<[u8; SESSION_KEY_LEN]>,
}

fn derive_secrets(shared: &[u8; 32], transcript: &[u8]) -> Result<HandshakeSecrets> {
    let mut output = Zeroizing::new([0_u8; SESSION_KEY_LEN * 3]);
    Hkdf::<Sha256>::new(Some(transcript), shared)
        .expand(b"snolc/handshake/secrets/v1", output.as_mut())
        .map_err(|_| Error::Protocol("cannot derive handshake secrets".to_owned()))?;
    Ok(HandshakeSecrets {
        master: Zeroizing::new(output[..32].try_into().expect("fixed-size master key")),
        server_key: Zeroizing::new(output[32..64].try_into().expect("fixed-size server key")),
        finish_key: Zeroizing::new(output[64..].try_into().expect("fixed-size finish key")),
    })
}

fn client_signed_message(
    mode: ProtectionMode,
    identity: &[u8; 32],
    ephemeral: &[u8; 32],
    random: &[u8; 32],
) -> Vec<u8> {
    let mut message = Vec::with_capacity(CLIENT_CONTEXT.len() + 3 + 1 + 96);
    message.extend_from_slice(CLIENT_CONTEXT);
    message.extend_from_slice(&wire_bytes());
    message.push(mode.id());
    message.extend_from_slice(identity);
    message.extend_from_slice(ephemeral);
    message.extend_from_slice(random);
    message
}

fn transcript(
    mode: ProtectionMode,
    identity: &[u8; 32],
    client_ephemeral: &[u8; 32],
    client_random: &[u8; 32],
    server_ephemeral: &[u8; 32],
    server_random: &[u8; 32],
) -> Vec<u8> {
    let mut value = client_signed_message(mode, identity, client_ephemeral, client_random);
    value.extend_from_slice(server_ephemeral);
    value.extend_from_slice(server_random);
    value
}

fn calculate_mac(key: &[u8], label: &[u8], transcript: &[u8]) -> Result<[u8; 32]> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| Error::Protocol("invalid handshake MAC key".to_owned()))?;
    mac.update(label);
    mac.update(transcript);
    Ok(mac.finalize().into_bytes().into())
}

fn verify_mac(key: &[u8], label: &[u8], transcript: &[u8], expected: &[u8]) -> Result<()> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| Error::Protocol("invalid handshake MAC key".to_owned()))?;
    mac.update(label);
    mac.update(transcript);
    mac.verify_slice(expected)
        .map_err(|_| Error::Authentication("invalid handshake MAC".to_owned()))
}

fn wire_bytes() -> [u8; 3] {
    let bytes = WIRE_VERSION.to_be_bytes();
    [bytes[1], bytes[2], bytes[3]]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authenticated_ephemeral_handshake_derives_the_same_master() {
        let identity = Identity::generate().unwrap();
        let (client, hello) =
            ClientHandshake::start(&identity, ProtectionMode::ChaChaPoly).unwrap();
        let (response, server) =
            accept_client(&hello, ProtectionMode::ChaChaPoly, &[identity.public()]).unwrap();
        let client = client.complete(&response).unwrap();
        let server_master = server.finish(&client.finish).unwrap();
        assert_eq!(&*client.master, &*server_master);
    }

    #[test]
    fn unknown_identity_is_rejected_before_session_creation() {
        let identity = Identity::generate().unwrap();
        let (_, hello) = ClientHandshake::start(&identity, ProtectionMode::AesGcm).unwrap();
        assert!(accept_client(&hello, ProtectionMode::AesGcm, &[[3_u8; 32]]).is_err());
    }

    #[test]
    fn tampered_client_hello_is_rejected() {
        let identity = Identity::generate().unwrap();
        let (_, mut hello) = ClientHandshake::start(&identity, ProtectionMode::AesGcm).unwrap();
        hello[40] ^= 1;
        assert!(accept_client(&hello, ProtectionMode::AesGcm, &[identity.public()]).is_err());
    }
}
