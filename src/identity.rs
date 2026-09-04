use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

pub const IDENTITY_KEY_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;

pub struct Identity {
    signing: SigningKey,
}

impl Identity {
    pub fn generate() -> std::result::Result<Self, getrandom::Error> {
        let mut seed = [0_u8; IDENTITY_KEY_LEN];
        getrandom::fill(&mut seed)?;
        Ok(Self {
            signing: SigningKey::from_bytes(&seed),
        })
    }

    pub fn from_base64(value: &str) -> Result<Self> {
        let decoded = Zeroizing::new(
            STANDARD
                .decode(value)
                .map_err(|_| Error::Authentication("private key is not base64".to_owned()))?,
        );
        let seed: [u8; IDENTITY_KEY_LEN] = decoded
            .as_slice()
            .try_into()
            .map_err(|_| Error::Authentication("private key must contain 32 bytes".to_owned()))?;
        Ok(Self {
            signing: SigningKey::from_bytes(&seed),
        })
    }

    pub fn public(&self) -> [u8; IDENTITY_KEY_LEN] {
        self.signing.verifying_key().to_bytes()
    }

    pub fn public_base64(&self) -> String {
        STANDARD.encode(self.public())
    }

    pub fn private_base64(&self) -> Zeroizing<String> {
        Zeroizing::new(STANDARD.encode(self.signing.to_bytes()))
    }

    pub fn yaml(&self) -> String {
        format!(
            "private: {}\npublic: {}\n",
            self.private_base64().as_str(),
            self.public_base64()
        )
    }

    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.signing.sign(message).to_bytes()
    }
}

pub fn verify(public: &[u8; IDENTITY_KEY_LEN], message: &[u8], signature: &[u8; 64]) -> Result<()> {
    let key = VerifyingKey::from_bytes(public)
        .map_err(|_| Error::Authentication("invalid public key".to_owned()))?;
    let signature = Signature::from_bytes(signature);
    key.verify(message, &signature)
        .map_err(|_| Error::Authentication("invalid client signature".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exported_identity_round_trips() {
        let identity = Identity::generate().unwrap();
        let restored = Identity::from_base64(&identity.private_base64()).unwrap();
        assert_eq!(restored.public(), identity.public());
        let signature = restored.sign(b"message");
        verify(&restored.public(), b"message", &signature).unwrap();
        assert!(verify(&restored.public(), b"other", &signature).is_err());
    }
}
