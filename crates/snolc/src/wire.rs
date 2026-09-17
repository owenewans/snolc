use std::net::{Ipv4Addr, Ipv6Addr};

use thiserror::Error;

pub const MAGIC: [u8; 4] = *b"SNOL";
pub const HEADER_LENGTH: usize = 12;
pub const MAX_POLICY_FAMILY: usize = 64;
pub const MAX_OPEN_BODY: usize = 4096;
pub const MAX_METADATA: usize = 1024;
pub const MAX_REASON: usize = 256;
pub const MAX_UDP_PAYLOAD: usize = 65_507;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum StreamKind {
    Policy = 1,
    Tcp = 2,
    Udp = 3,
}

impl TryFrom<u8> for StreamKind {
    type Error = WireError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Policy),
            2 => Ok(Self::Tcp),
            3 => Ok(Self::Udp),
            value => Err(WireError::UnknownKind(value)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum OpenStatus {
    Ok = 0,
    Denied = 1,
    ConnectFailed = 2,
    Unsupported = 3,
    ResourceLimit = 4,
    ProtocolError = 5,
    InternalError = 6,
}

impl TryFrom<u8> for OpenStatus {
    type Error = WireError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Ok),
            1 => Ok(Self::Denied),
            2 => Ok(Self::ConnectFailed),
            3 => Ok(Self::Unsupported),
            4 => Ok(Self::ResourceLimit),
            5 => Ok(Self::ProtocolError),
            6 => Ok(Self::InternalError),
            value => Err(WireError::UnknownStatus(value)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Destination {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Domain(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenRequest {
    pub kind: StreamKind,
    pub destination: Destination,
    pub port: u16,
    pub metadata: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenResponse {
    pub status: OpenStatus,
    pub reason: String,
}

pub fn encode_header(kind: StreamKind, output: &mut Vec<u8>) {
    output.extend_from_slice(&MAGIC);
    output.extend_from_slice(&snolc_abi::WIRE_VERSION.to_be_bytes());
    output.push(kind as u8);
    output.extend_from_slice(&[0; 3]);
}

pub fn parse_header(input: &[u8]) -> Result<StreamKind, WireError> {
    let header = input.get(..HEADER_LENGTH).ok_or(WireError::Incomplete)?;
    if header[..4] != MAGIC {
        return Err(WireError::InvalidMagic);
    }
    let version = u32::from_be_bytes(header[4..8].try_into().expect("header length checked"));
    if version != snolc_abi::WIRE_VERSION {
        return Err(WireError::Version(version));
    }
    if header[9..12] != [0; 3] {
        return Err(WireError::Reserved);
    }
    StreamKind::try_from(header[8])
}

pub fn encode_policy(family: &str) -> Result<Vec<u8>, WireError> {
    validate_family(family)?;
    let mut output = Vec::with_capacity(HEADER_LENGTH + 2 + family.len());
    encode_header(StreamKind::Policy, &mut output);
    output.extend_from_slice(&(family.len() as u16).to_be_bytes());
    output.extend_from_slice(family.as_bytes());
    Ok(output)
}

pub fn parse_policy(input: &[u8]) -> Result<String, WireError> {
    if parse_header(input)? != StreamKind::Policy {
        return Err(WireError::InvalidKind);
    }
    let mut cursor = Cursor::new(input, HEADER_LENGTH);
    let length = cursor.u16()? as usize;
    if !(1..=MAX_POLICY_FAMILY).contains(&length) {
        return Err(WireError::Length);
    }
    let family = std::str::from_utf8(cursor.bytes(length)?).map_err(|_| WireError::Utf8)?;
    if cursor.remaining() != 0 {
        return Err(WireError::TrailingBytes);
    }
    validate_family(family)?;
    Ok(family.to_owned())
}

pub fn encode_open(request: &OpenRequest) -> Result<Vec<u8>, WireError> {
    if !matches!(request.kind, StreamKind::Tcp | StreamKind::Udp) {
        return Err(WireError::InvalidKind);
    }
    if request.port == 0 {
        return Err(WireError::Port);
    }
    if request.metadata.len() > MAX_METADATA {
        return Err(WireError::Length);
    }

    let mut body = Vec::new();
    match &request.destination {
        Destination::Ipv4(address) => {
            body.push(1);
            body.extend_from_slice(&address.octets());
        }
        Destination::Ipv6(address) => {
            body.push(2);
            body.extend_from_slice(&address.octets());
        }
        Destination::Domain(domain) => {
            validate_domain(domain)?;
            body.push(3);
            body.extend_from_slice(&(domain.len() as u16).to_be_bytes());
            body.extend_from_slice(domain.as_bytes());
        }
    }
    body.extend_from_slice(&request.port.to_be_bytes());
    body.extend_from_slice(&(request.metadata.len() as u16).to_be_bytes());
    body.extend_from_slice(&request.metadata);
    if body.len() > MAX_OPEN_BODY {
        return Err(WireError::Length);
    }

    let mut output = Vec::with_capacity(HEADER_LENGTH + 2 + body.len());
    encode_header(request.kind, &mut output);
    output.extend_from_slice(&(body.len() as u16).to_be_bytes());
    output.extend_from_slice(&body);
    Ok(output)
}

pub fn parse_open(input: &[u8]) -> Result<OpenRequest, WireError> {
    let kind = parse_header(input)?;
    if !matches!(kind, StreamKind::Tcp | StreamKind::Udp) {
        return Err(WireError::InvalidKind);
    }
    let mut cursor = Cursor::new(input, HEADER_LENGTH);
    let body_length = cursor.u16()? as usize;
    if body_length > MAX_OPEN_BODY {
        return Err(WireError::Length);
    }
    if cursor.remaining() < body_length {
        return Err(WireError::Incomplete);
    }
    if cursor.remaining() > body_length {
        return Err(WireError::TrailingBytes);
    }
    let body_end = cursor.position + body_length;
    let destination = match cursor.u8()? {
        1 => Destination::Ipv4(Ipv4Addr::from(cursor.array::<4>()?)),
        2 => Destination::Ipv6(Ipv6Addr::from(cursor.array::<16>()?)),
        3 => {
            let length = cursor.u16()? as usize;
            let domain = std::str::from_utf8(cursor.bytes(length)?).map_err(|_| WireError::Utf8)?;
            validate_domain(domain)?;
            Destination::Domain(domain.to_owned())
        }
        value => return Err(WireError::AddressType(value)),
    };
    let port = cursor.u16()?;
    if port == 0 {
        return Err(WireError::Port);
    }
    let metadata_length = cursor.u16()? as usize;
    if metadata_length > MAX_METADATA {
        return Err(WireError::Length);
    }
    let metadata = cursor.bytes(metadata_length)?.to_vec();
    if cursor.position != body_end {
        return Err(WireError::TrailingBytes);
    }
    Ok(OpenRequest {
        kind,
        destination,
        port,
        metadata,
    })
}

pub fn encode_open_response(response: &OpenResponse) -> Result<Vec<u8>, WireError> {
    if response.reason.len() > MAX_REASON {
        return Err(WireError::Length);
    }
    let mut output = Vec::with_capacity(3 + response.reason.len());
    output.push(response.status as u8);
    output.extend_from_slice(&(response.reason.len() as u16).to_be_bytes());
    output.extend_from_slice(response.reason.as_bytes());
    Ok(output)
}

pub fn parse_open_response(input: &[u8]) -> Result<OpenResponse, WireError> {
    let mut cursor = Cursor::new(input, 0);
    let status = OpenStatus::try_from(cursor.u8()?)?;
    let length = cursor.u16()? as usize;
    if length > MAX_REASON {
        return Err(WireError::Length);
    }
    let reason = std::str::from_utf8(cursor.bytes(length)?).map_err(|_| WireError::Utf8)?;
    if cursor.remaining() != 0 {
        return Err(WireError::TrailingBytes);
    }
    Ok(OpenResponse {
        status,
        reason: reason.to_owned(),
    })
}

pub fn encode_udp(payload: &[u8]) -> Result<Vec<u8>, WireError> {
    if payload.len() > MAX_UDP_PAYLOAD {
        return Err(WireError::Length);
    }
    let mut output = Vec::with_capacity(2 + payload.len());
    output.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    output.extend_from_slice(payload);
    Ok(output)
}

pub fn parse_udp(input: &[u8]) -> Result<&[u8], WireError> {
    let mut cursor = Cursor::new(input, 0);
    let length = cursor.u16()? as usize;
    if length > MAX_UDP_PAYLOAD {
        return Err(WireError::Length);
    }
    let payload = cursor.bytes(length)?;
    if cursor.remaining() != 0 {
        return Err(WireError::TrailingBytes);
    }
    Ok(payload)
}

fn validate_family(family: &str) -> Result<(), WireError> {
    if family.is_empty()
        || family.len() > MAX_POLICY_FAMILY
        || !family
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(WireError::PolicyFamily);
    }
    Ok(())
}

fn validate_domain(domain: &str) -> Result<(), WireError> {
    if domain.is_empty() || domain.len() > 253 || !domain.is_ascii() {
        return Err(WireError::Domain);
    }
    for label in domain.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(WireError::Domain);
        }
    }
    Ok(())
}

struct Cursor<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(input: &'a [u8], position: usize) -> Self {
        Self { input, position }
    }

    fn remaining(&self) -> usize {
        self.input.len().saturating_sub(self.position)
    }

    fn bytes(&mut self, length: usize) -> Result<&'a [u8], WireError> {
        let end = self.position.checked_add(length).ok_or(WireError::Length)?;
        let bytes = self
            .input
            .get(self.position..end)
            .ok_or(WireError::Incomplete)?;
        self.position = end;
        Ok(bytes)
    }

    fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.bytes(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, WireError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        self.bytes(N)?.try_into().map_err(|_| WireError::Incomplete)
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum WireError {
    #[error("frame is incomplete")]
    Incomplete,
    #[error("wire magic is invalid")]
    InvalidMagic,
    #[error("wire version {0} is unsupported")]
    Version(u32),
    #[error("stream kind {0} is unknown")]
    UnknownKind(u8),
    #[error("stream kind is invalid for this frame")]
    InvalidKind,
    #[error("reserved header bytes are nonzero")]
    Reserved,
    #[error("frame has trailing bytes")]
    TrailingBytes,
    #[error("field length exceeds its limit")]
    Length,
    #[error("address type {0} is unknown")]
    AddressType(u8),
    #[error("domain is invalid")]
    Domain,
    #[error("policy family is invalid")]
    PolicyFamily,
    #[error("port zero is invalid")]
    Port,
    #[error("UTF-8 field is invalid")]
    Utf8,
    #[error("open status {0} is unknown")]
    UnknownStatus(u8),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(destination: Destination) -> OpenRequest {
        OpenRequest {
            kind: StreamKind::Tcp,
            destination,
            port: 443,
            metadata: vec![1, 2, 3],
        }
    }

    #[test]
    fn tcp_header_matches_contract() {
        let encoded = encode_open(&request(Destination::Ipv4(Ipv4Addr::LOCALHOST))).unwrap();
        assert_eq!(
            &encoded[..HEADER_LENGTH],
            &[0x53, 0x4e, 0x4f, 0x4c, 0, 0, 0, 1, 2, 0, 0, 0]
        );
    }

    #[test]
    fn open_round_trips_all_addresses() {
        for destination in [
            Destination::Ipv4(Ipv4Addr::new(192, 0, 2, 1)),
            Destination::Ipv6(Ipv6Addr::LOCALHOST),
            Destination::Domain("example.com".into()),
        ] {
            let request = request(destination);
            assert_eq!(
                parse_open(&encode_open(&request).unwrap()).unwrap(),
                request
            );
        }
    }

    #[test]
    fn every_open_prefix_is_incomplete() {
        let encoded = encode_open(&request(Destination::Domain("example.com".into()))).unwrap();
        for length in 0..encoded.len() {
            assert_eq!(parse_open(&encoded[..length]), Err(WireError::Incomplete));
        }
    }

    #[test]
    fn policy_and_response_round_trip() {
        assert_eq!(
            parse_policy(&encode_policy("policy-local").unwrap()).unwrap(),
            "policy-local"
        );
        let response = OpenResponse {
            status: OpenStatus::Denied,
            reason: "blocked".into(),
        };
        assert_eq!(
            parse_open_response(&encode_open_response(&response).unwrap()).unwrap(),
            response
        );
    }

    #[test]
    fn udp_preserves_boundaries() {
        for payload in [Vec::new(), vec![1], vec![7; MAX_UDP_PAYLOAD]] {
            assert_eq!(parse_udp(&encode_udp(&payload).unwrap()).unwrap(), payload);
        }
    }

    #[test]
    fn rejects_trailing_reserved_and_unknown_fields() {
        let mut encoded = encode_open(&request(Destination::Ipv6(Ipv6Addr::LOCALHOST))).unwrap();
        encoded.push(0);
        assert_eq!(parse_open(&encoded), Err(WireError::TrailingBytes));
        encoded.pop();
        encoded[11] = 1;
        assert_eq!(parse_open(&encoded), Err(WireError::Reserved));
        encoded[11] = 0;
        encoded[8] = 99;
        assert_eq!(parse_open(&encoded), Err(WireError::UnknownKind(99)));
    }

    #[test]
    fn arbitrary_bytes_do_not_panic() {
        for length in 0..8192 {
            let input = vec![(length % 251) as u8; length];
            let _ = parse_open(&input);
            let _ = parse_open_response(&input);
            let _ = parse_policy(&input);
            let _ = parse_udp(&input);
        }
    }
}
