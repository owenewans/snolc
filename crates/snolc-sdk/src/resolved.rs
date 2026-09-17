use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use thiserror::Error;

pub const MAX_RESOLVED_ADDRESSES: usize = 64;

#[derive(Debug, Error)]
pub enum ResolvedAddressError {
    #[error("resolved address count is invalid")]
    Count,
    #[error("resolved address buffer is too small")]
    Buffer,
    #[error("resolved address encoding is invalid")]
    Encoding,
}

pub fn resolved_addresses_size(addresses: &[IpAddr]) -> Result<usize, ResolvedAddressError> {
    if addresses.is_empty() || addresses.len() > MAX_RESOLVED_ADDRESSES {
        return Err(ResolvedAddressError::Count);
    }
    addresses.iter().try_fold(2_usize, |length, address| {
        length
            .checked_add(match address {
                IpAddr::V4(_) => 5,
                IpAddr::V6(_) => 17,
            })
            .ok_or(ResolvedAddressError::Encoding)
    })
}

pub fn encode_resolved_addresses(
    addresses: &[IpAddr],
    output: &mut [u8],
) -> Result<usize, ResolvedAddressError> {
    let required = resolved_addresses_size(addresses)?;
    if output.len() < required {
        return Err(ResolvedAddressError::Buffer);
    }
    output[..2].copy_from_slice(&(addresses.len() as u16).to_be_bytes());
    let mut offset = 2;
    for address in addresses {
        match address {
            IpAddr::V4(address) => {
                output[offset] = 1;
                output[offset + 1..offset + 5].copy_from_slice(&address.octets());
                offset += 5;
            }
            IpAddr::V6(address) => {
                output[offset] = 2;
                output[offset + 1..offset + 17].copy_from_slice(&address.octets());
                offset += 17;
            }
        }
    }
    Ok(required)
}

pub fn decode_resolved_addresses(input: &[u8]) -> Result<Vec<IpAddr>, ResolvedAddressError> {
    let count = input
        .get(..2)
        .and_then(|count| <[u8; 2]>::try_from(count).ok())
        .map(u16::from_be_bytes)
        .map(usize::from)
        .ok_or(ResolvedAddressError::Encoding)?;
    if count == 0 || count > MAX_RESOLVED_ADDRESSES {
        return Err(ResolvedAddressError::Count);
    }
    let mut offset = 2;
    let mut addresses = Vec::with_capacity(count);
    for _ in 0..count {
        let tag = *input.get(offset).ok_or(ResolvedAddressError::Encoding)?;
        offset += 1;
        let address = match tag {
            1 => {
                let bytes = input
                    .get(offset..offset + 4)
                    .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
                    .ok_or(ResolvedAddressError::Encoding)?;
                offset += 4;
                IpAddr::V4(Ipv4Addr::from(bytes))
            }
            2 => {
                let bytes = input
                    .get(offset..offset + 16)
                    .and_then(|bytes| <[u8; 16]>::try_from(bytes).ok())
                    .ok_or(ResolvedAddressError::Encoding)?;
                offset += 16;
                IpAddr::V6(Ipv6Addr::from(bytes))
            }
            _ => return Err(ResolvedAddressError::Encoding),
        };
        addresses.push(address);
    }
    if offset != input.len() {
        return Err(ResolvedAddressError::Encoding);
    }
    Ok(addresses)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolved_addresses_round_trip_without_trailing_bytes() {
        let addresses = [
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ];
        let mut encoded = [0; 24];
        let length = encode_resolved_addresses(&addresses, &mut encoded).unwrap();
        assert_eq!(length, encoded.len());
        assert_eq!(decode_resolved_addresses(&encoded).unwrap(), addresses);

        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert!(matches!(
            decode_resolved_addresses(&trailing),
            Err(ResolvedAddressError::Encoding)
        ));
    }

    #[test]
    fn resolved_addresses_enforce_count_and_output_bounds() {
        assert!(matches!(
            resolved_addresses_size(&[]),
            Err(ResolvedAddressError::Count)
        ));
        let addresses = vec![IpAddr::V4(Ipv4Addr::UNSPECIFIED); MAX_RESOLVED_ADDRESSES + 1];
        assert!(matches!(
            resolved_addresses_size(&addresses),
            Err(ResolvedAddressError::Count)
        ));
        assert!(matches!(
            encode_resolved_addresses(&[IpAddr::V4(Ipv4Addr::LOCALHOST)], &mut [0; 6]),
            Err(ResolvedAddressError::Buffer)
        ));
    }
}
