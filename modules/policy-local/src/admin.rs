use std::collections::HashMap;

use getrandom::fill;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Clone, Copy, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct UserId([u8; 16]);

impl UserId {
    pub fn generate() -> Result<Self, AdminError> {
        let mut bytes = [0; 16];
        fill(&mut bytes).map_err(|_| AdminError::Random)?;
        Ok(Self(bytes))
    }

    pub fn hex(self) -> String {
        encode_hex(&self.0)
    }
}

pub struct Credential([u8; 32]);

impl Credential {
    pub fn generate() -> Result<Self, AdminError> {
        let mut bytes = [0; 32];
        fill(&mut bytes).map_err(|_| AdminError::Random)?;
        Ok(Self(bytes))
    }

    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.0).into()
    }

    pub fn expose_once(mut self) -> [u8; 32] {
        let output = self.0;
        self.0.fill(0);
        output
    }
}

impl Drop for Credential {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[derive(Clone, Deserialize, Serialize)]
struct Receipt {
    seq: u64,
    request_hash: [u8; 32],
    response: Vec<u8>,
}

pub struct AdminSequencer {
    max_clients: usize,
    clients: HashMap<String, Receipt>,
}

pub enum AdminDecision {
    Execute { request_hash: [u8; 32] },
    Replay(Vec<u8>),
}

impl AdminSequencer {
    pub fn new(max_clients: usize) -> Result<Self, AdminError> {
        if max_clients == 0 {
            return Err(AdminError::Invalid);
        }
        Ok(Self {
            max_clients,
            clients: HashMap::new(),
        })
    }

    pub fn check(
        &self,
        client_id: &str,
        seq: u64,
        request: &[u8],
    ) -> Result<AdminDecision, AdminError> {
        validate_client_id(client_id)?;
        let request_hash: [u8; 32] = Sha256::digest(request).into();
        match self.clients.get(client_id) {
            None if self.clients.len() >= self.max_clients => Err(AdminError::ClientLimit),
            None if seq == 1 => Ok(AdminDecision::Execute { request_hash }),
            None => Err(AdminError::Sequence),
            Some(receipt) if seq == receipt.seq && request_hash == receipt.request_hash => {
                Ok(AdminDecision::Replay(receipt.response.clone()))
            }
            Some(receipt) if seq == receipt.seq + 1 => Ok(AdminDecision::Execute { request_hash }),
            Some(_) => Err(AdminError::Sequence),
        }
    }

    pub fn commit(
        &mut self,
        client_id: String,
        seq: u64,
        request_hash: [u8; 32],
        response: Vec<u8>,
    ) -> Result<Vec<u8>, AdminError> {
        validate_client_id(&client_id)?;
        match self.clients.get(&client_id) {
            None if self.clients.len() >= self.max_clients => {
                return Err(AdminError::ClientLimit);
            }
            None if seq == 1 => {}
            Some(receipt) if seq == receipt.seq + 1 => {}
            _ => return Err(AdminError::State),
        }
        let receipt = Receipt {
            seq,
            request_hash,
            response,
        };
        let encoded = postcard::to_allocvec(&receipt).map_err(|_| AdminError::Encode)?;
        self.clients.insert(client_id, receipt);
        Ok(encoded)
    }

    pub fn restore(&mut self, client_id: String, encoded: &[u8]) -> Result<(), AdminError> {
        validate_client_id(&client_id)?;
        if !self.clients.contains_key(&client_id) && self.clients.len() >= self.max_clients {
            return Err(AdminError::ClientLimit);
        }
        let receipt = postcard::from_bytes(encoded).map_err(|_| AdminError::Encode)?;
        self.clients.insert(client_id, receipt);
        Ok(())
    }
}

fn validate_client_id(client_id: &str) -> Result<(), AdminError> {
    if client_id.is_empty()
        || client_id.len() > 64
        || !client_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(AdminError::Invalid);
    }
    Ok(())
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[usize::from(byte >> 4)] as char);
        output.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    output
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum AdminError {
    #[error("administrative client is invalid")]
    Invalid,
    #[error("administrative client limit is exhausted")]
    ClientLimit,
    #[error("administrative sequence is invalid")]
    Sequence,
    #[error("administrative state transition is invalid")]
    State,
    #[error("system random source failed")]
    Random,
    #[error("administrative record encoding failed")]
    Encode,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeats_last_response_without_reapplying() {
        let mut sequencer = AdminSequencer::new(2).unwrap();
        let request = b"quota.add";
        let hash = match sequencer.check("panel", 1, request).unwrap() {
            AdminDecision::Execute { request_hash } => request_hash,
            AdminDecision::Replay(_) => panic!("new request replayed"),
        };
        sequencer
            .commit("panel".into(), 1, hash, b"revision=2".to_vec())
            .unwrap();
        assert!(matches!(
            sequencer.check("panel", 1, request).unwrap(),
            AdminDecision::Replay(response) if response == b"revision=2"
        ));
        assert!(matches!(
            sequencer.check("panel", 1, b"different"),
            Err(AdminError::Sequence)
        ));
        assert!(matches!(
            sequencer.check("panel", 3, b"skip"),
            Err(AdminError::Sequence)
        ));
    }

    #[test]
    fn credentials_hash_and_clear_secret() {
        let credential = Credential::generate().unwrap();
        let digest = credential.digest();
        let secret = credential.expose_once();
        assert_eq!(digest.as_slice(), Sha256::digest(secret).as_slice());
        assert_eq!(UserId::generate().unwrap().hex().len(), 32);
    }
}
