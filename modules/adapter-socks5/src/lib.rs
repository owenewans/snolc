#![deny(unsafe_op_in_unsafe_fn)]

use std::net::{Ipv4Addr, Ipv6Addr};

use serde::Deserialize;
use snolc_sdk::abi::{self, SnolAdapterApiV1, SnolWakeHandle};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Command {
    Connect,
    UdpAssociate,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Address {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Domain(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Request {
    pub command: Command,
    pub address: Address,
    pub port: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpPacket<'a> {
    pub address: Address,
    pub port: u16,
    pub payload: &'a [u8],
}

pub fn parse_request(input: &[u8]) -> Result<Request, ParseError> {
    if input.len() < 4 || input[0] != 5 || input[2] != 0 {
        return Err(ParseError::Protocol);
    }
    let command = match input[1] {
        1 => Command::Connect,
        2 => return Err(ParseError::BindUnsupported),
        3 => Command::UdpAssociate,
        _ => return Err(ParseError::Command),
    };
    let (address, port, consumed) = parse_address(&input[3..])?;
    if consumed + 3 != input.len() {
        return Err(ParseError::TrailingBytes);
    }
    Ok(Request {
        command,
        address,
        port,
    })
}

pub fn parse_udp(input: &[u8]) -> Result<UdpPacket<'_>, ParseError> {
    if input.len() < 4 || input[..2] != [0, 0] {
        return Err(ParseError::Protocol);
    }
    if input[2] != 0 {
        return Err(ParseError::FragmentUnsupported);
    }
    let (address, port, consumed) = parse_address(&input[3..])?;
    Ok(UdpPacket {
        address,
        port,
        payload: &input[3 + consumed..],
    })
}

fn parse_address(input: &[u8]) -> Result<(Address, u16, usize), ParseError> {
    let kind = *input.first().ok_or(ParseError::Incomplete)?;
    let (address, offset) = match kind {
        1 => {
            let bytes: [u8; 4] = input
                .get(1..5)
                .ok_or(ParseError::Incomplete)?
                .try_into()
                .map_err(|_| ParseError::Incomplete)?;
            (Address::Ipv4(Ipv4Addr::from(bytes)), 5)
        }
        4 => {
            let bytes: [u8; 16] = input
                .get(1..17)
                .ok_or(ParseError::Incomplete)?
                .try_into()
                .map_err(|_| ParseError::Incomplete)?;
            (Address::Ipv6(Ipv6Addr::from(bytes)), 17)
        }
        3 => {
            let length = *input.get(1).ok_or(ParseError::Incomplete)? as usize;
            if length == 0 {
                return Err(ParseError::Address);
            }
            let bytes = input.get(2..2 + length).ok_or(ParseError::Incomplete)?;
            let domain = std::str::from_utf8(bytes).map_err(|_| ParseError::Address)?;
            if !valid_domain(domain) {
                return Err(ParseError::Address);
            }
            (Address::Domain(domain.to_owned()), 2 + length)
        }
        _ => return Err(ParseError::Address),
    };
    let port_bytes: [u8; 2] = input
        .get(offset..offset + 2)
        .ok_or(ParseError::Incomplete)?
        .try_into()
        .map_err(|_| ParseError::Incomplete)?;
    let port = u16::from_be_bytes(port_bytes);
    if port == 0 {
        return Err(ParseError::Port);
    }
    Ok((address, port, offset + 2))
}

fn valid_domain(domain: &str) -> bool {
    domain.len() <= 253
        && domain.is_ascii()
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    Incomplete,
    Protocol,
    Command,
    BindUnsupported,
    FragmentUnsupported,
    Address,
    Port,
    TrailingBytes,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Options {
    listen: String,
    max_connections: usize,
    max_udp_associations: usize,
    max_request_bytes: usize,
    reject_fragments: bool,
}

fn validate_config(config: &[u8], _base: &[u8]) -> Result<(), String> {
    let text = std::str::from_utf8(config).map_err(|_| "config is not UTF-8".to_owned())?;
    let options: Options = toml::from_str(text).map_err(|error| error.to_string())?;
    if options.listen.is_empty()
        || options.max_connections == 0
        || options.max_udp_associations == 0
        || options.max_request_bytes < 262
        || !options.reject_fragments
    {
        return Err("SOCKS5 options are inconsistent".into());
    }
    Ok(())
}

unsafe extern "C" fn open(
    instance: u64,
    _operation: u64,
    _metadata: *const abi::SnolFlowMetadataV1,
    _wake: SnolWakeHandle,
    _output: *mut u64,
) -> u32 {
    snolc_sdk::catch_status(|| {
        if !INSTANCES.contains(instance) {
            return abi::STATUS_INVALID;
        }
        abi::STATUS_UNSUPPORTED
    })
}

static ADAPTER: SnolAdapterApiV1 = SnolAdapterApiV1 {
    struct_size: size_of::<SnolAdapterApiV1>() as u32,
    reserved: 0,
    open: Some(open),
    accept: Some(snolc_sdk::module::unsupported_adapter_accept),
    attach: Some(snolc_sdk::module::unsupported_adapter_attach),
    complete: Some(snolc_sdk::module::unsupported_adapter_complete),
    close_flow: Some(snolc_sdk::module::unsupported_adapter_close),
};

snolc_sdk::declare_module! {
    name: "adapter-socks5",
    description: "name = \"adapter-socks5\"\nroles = [\"client\"]\nplatforms = [\"linux\", \"android\", \"bsd\", \"macos\", \"windows\"]\nconnect = true\nudp_associate = true\nbind = false\nfragments = false\n",
    class_mask: abi::CLASS_ADAPTER,
    validate: validate_config,
    byte_io: std::ptr::null(),
    datagram_io: std::ptr::null(),
    adapter: &ADAPTER,
    protection: std::ptr::null(),
    carrier: std::ptr::null(),
    policy: std::ptr::null(),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_connect_and_rejects_bind() {
        let request = parse_request(&[
            5, 1, 0, 3, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', 1,
            187,
        ])
        .unwrap();
        assert_eq!(request.command, Command::Connect);
        assert_eq!(request.port, 443);
        let mut bind = vec![5, 2, 0, 1, 127, 0, 0, 1, 0, 80];
        assert_eq!(parse_request(&bind), Err(ParseError::BindUnsupported));
        bind[1] = 1;
        assert!(parse_request(&bind).is_ok());
    }

    #[test]
    fn udp_rejects_fragments_without_consuming_payload() {
        let packet = [0, 0, 0, 1, 127, 0, 0, 1, 0, 53, 1, 2, 3];
        assert_eq!(parse_udp(&packet).unwrap().payload, &[1, 2, 3]);
        let mut fragmented = packet;
        fragmented[2] = 1;
        assert_eq!(parse_udp(&fragmented), Err(ParseError::FragmentUnsupported));
    }
}
