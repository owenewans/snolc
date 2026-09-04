use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::error::{Error, Result};

pub const FRAGMENT_HEADER_LEN: usize = 16;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Fragment {
    pub message: u64,
    pub index: u16,
    pub count: u16,
    pub total: u32,
    pub payload: Vec<u8>,
}

pub fn split(
    message: u64,
    payload: &[u8],
    mtu: usize,
    outer_overhead: usize,
) -> Result<Vec<Fragment>> {
    let capacity = mtu
        .checked_sub(outer_overhead)
        .and_then(|space| space.checked_sub(FRAGMENT_HEADER_LEN))
        .ok_or_else(|| Error::Protocol("carrier MTU cannot hold a fragment".to_owned()))?;
    if capacity == 0 {
        return Err(Error::Protocol(
            "fragment payload capacity is zero".to_owned(),
        ));
    }
    let count = payload.len().max(1).div_ceil(capacity);
    let count = u16::try_from(count)
        .map_err(|_| Error::Protocol("packet requires too many fragments".to_owned()))?;
    let total = u32::try_from(payload.len())
        .map_err(|_| Error::Protocol("packet is too large".to_owned()))?;

    if payload.is_empty() {
        return Ok(vec![Fragment {
            message,
            index: 0,
            count,
            total,
            payload: Vec::new(),
        }]);
    }
    Ok(payload
        .chunks(capacity)
        .enumerate()
        .map(|(index, chunk)| Fragment {
            message,
            index: index as u16,
            count,
            total,
            payload: chunk.to_vec(),
        })
        .collect())
}

impl Fragment {
    pub fn encode(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(FRAGMENT_HEADER_LEN + self.payload.len());
        output.extend_from_slice(&self.message.to_be_bytes());
        output.extend_from_slice(&self.index.to_be_bytes());
        output.extend_from_slice(&self.count.to_be_bytes());
        output.extend_from_slice(&self.total.to_be_bytes());
        output.extend_from_slice(&self.payload);
        output
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() < FRAGMENT_HEADER_LEN {
            return Err(Error::Protocol("truncated fragment".to_owned()));
        }
        let fragment = Self {
            message: u64::from_be_bytes(input[..8].try_into().expect("checked fragment message")),
            index: u16::from_be_bytes(input[8..10].try_into().expect("checked fragment index")),
            count: u16::from_be_bytes(input[10..12].try_into().expect("checked fragment count")),
            total: u32::from_be_bytes(input[12..16].try_into().expect("checked fragment total")),
            payload: input[16..].to_vec(),
        };
        fragment.validate()?;
        Ok(fragment)
    }

    fn validate(&self) -> Result<()> {
        if self.count == 0 || self.index >= self.count {
            return Err(Error::Protocol("invalid fragment position".to_owned()));
        }
        if self.payload.len() > self.total as usize {
            return Err(Error::Protocol(
                "fragment exceeds total packet length".to_owned(),
            ));
        }
        Ok(())
    }
}

pub struct Reassembler {
    entries: HashMap<u64, Assembly>,
    bytes: usize,
    max_entries: usize,
    max_bytes: usize,
    timeout: Duration,
}

struct Assembly {
    created: Instant,
    count: u16,
    total: u32,
    received: usize,
    parts: Vec<Option<Vec<u8>>>,
}

impl Reassembler {
    pub fn new(max_entries: usize, max_bytes: usize, timeout: Duration) -> Result<Self> {
        if max_entries == 0 || max_bytes == 0 || timeout.is_zero() {
            return Err(Error::Config(
                "reassembly limits must be non-zero".to_owned(),
            ));
        }
        Ok(Self {
            entries: HashMap::new(),
            bytes: 0,
            max_entries,
            max_bytes,
            timeout,
        })
    }

    pub fn insert(&mut self, fragment: Fragment, now: Instant) -> Result<Option<Vec<u8>>> {
        fragment.validate()?;
        self.expire(now);

        if !self.entries.contains_key(&fragment.message) {
            if self.entries.len() >= self.max_entries {
                return Err(Error::Protocol(
                    "fragment assembly limit reached".to_owned(),
                ));
            }
            if fragment.total as usize > self.max_bytes.saturating_sub(self.bytes) {
                return Err(Error::Protocol("fragment memory limit reached".to_owned()));
            }
            self.bytes += fragment.total as usize;
            self.entries.insert(
                fragment.message,
                Assembly {
                    created: now,
                    count: fragment.count,
                    total: fragment.total,
                    received: 0,
                    parts: vec![None; fragment.count as usize],
                },
            );
        }

        let assembly = self
            .entries
            .get_mut(&fragment.message)
            .expect("assembly inserted");
        if assembly.count != fragment.count || assembly.total != fragment.total {
            return Err(Error::Protocol("inconsistent fragment metadata".to_owned()));
        }
        let slot = &mut assembly.parts[fragment.index as usize];
        if let Some(existing) = slot {
            if existing != &fragment.payload {
                return Err(Error::Protocol("conflicting duplicate fragment".to_owned()));
            }
            return Ok(None);
        }
        assembly.received = assembly
            .received
            .checked_add(fragment.payload.len())
            .ok_or_else(|| Error::Protocol("fragment length overflow".to_owned()))?;
        if assembly.received > assembly.total as usize {
            return Err(Error::Protocol(
                "assembled packet exceeds declared length".to_owned(),
            ));
        }
        *slot = Some(fragment.payload);

        if assembly.parts.iter().all(Option::is_some) {
            let assembly = self
                .entries
                .remove(&fragment.message)
                .expect("complete assembly");
            self.bytes -= assembly.total as usize;
            if assembly.received != assembly.total as usize {
                return Err(Error::Protocol(
                    "assembled packet length mismatch".to_owned(),
                ));
            }
            let mut packet = Vec::with_capacity(assembly.total as usize);
            for part in assembly.parts {
                packet.extend_from_slice(part.as_deref().expect("complete fragment"));
            }
            return Ok(Some(packet));
        }
        Ok(None)
    }

    pub fn expire(&mut self, now: Instant) {
        let timeout = self.timeout;
        let mut removed = 0;
        self.entries.retain(|_, assembly| {
            let keep = now.saturating_duration_since(assembly.created) < timeout;
            if !keep {
                removed += assembly.total as usize;
            }
            keep
        });
        self.bytes -= removed;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragments_fit_the_mtu_and_reassemble_out_of_order() {
        let payload: Vec<u8> = (0..=255).cycle().take(4000).collect();
        let fragments = split(7, &payload, 512, 37).unwrap();
        assert!(fragments.len() > 1);
        assert!(
            fragments
                .iter()
                .all(|fragment| fragment.encode().len() + 37 <= 512)
        );

        let now = Instant::now();
        let mut reassembler = Reassembler::new(10, 16 * 1024, Duration::from_secs(5)).unwrap();
        let mut result = None;
        for fragment in fragments.into_iter().rev() {
            result = reassembler.insert(fragment, now).unwrap().or(result);
        }
        assert_eq!(result.unwrap(), payload);
    }

    #[test]
    fn conflicting_duplicate_is_rejected() {
        let now = Instant::now();
        let mut reassembler = Reassembler::new(1, 1024, Duration::from_secs(1)).unwrap();
        let first = Fragment {
            message: 1,
            index: 0,
            count: 2,
            total: 2,
            payload: vec![1],
        };
        reassembler.insert(first.clone(), now).unwrap();
        let mut conflicting = first;
        conflicting.payload[0] = 2;
        assert!(reassembler.insert(conflicting, now).is_err());
    }

    #[test]
    fn stale_assemblies_release_the_memory_budget() {
        let now = Instant::now();
        let mut reassembler = Reassembler::new(1, 10, Duration::from_millis(1)).unwrap();
        let incomplete = Fragment {
            message: 1,
            index: 0,
            count: 2,
            total: 10,
            payload: vec![1],
        };
        reassembler.insert(incomplete, now).unwrap();
        reassembler.expire(now + Duration::from_millis(2));
        let replacement = Fragment {
            message: 2,
            index: 0,
            count: 1,
            total: 1,
            payload: vec![2],
        };
        assert_eq!(
            reassembler
                .insert(replacement, now + Duration::from_millis(2))
                .unwrap(),
            Some(vec![2])
        );
    }
}
