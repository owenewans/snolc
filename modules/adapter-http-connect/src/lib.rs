#![deny(unsafe_op_in_unsafe_fn)]

use std::net::{Ipv4Addr, Ipv6Addr};

use serde::Deserialize;
use snolc_sdk::abi::{self, SnolAdapterApiV1, SnolWakeHandle};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Host {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Domain(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectRequest<'a> {
    pub host: Host,
    pub port: u16,
    pub trailing: &'a [u8],
}

pub fn parse_connect(
    input: &[u8],
    max_header_bytes: usize,
) -> Result<ConnectRequest<'_>, ParseError> {
    let end = input
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|offset| offset + 4)
        .ok_or({
            if input.len() >= max_header_bytes {
                ParseError::HeaderTooLarge
            } else {
                ParseError::Incomplete
            }
        })?;
    if end > max_header_bytes {
        return Err(ParseError::HeaderTooLarge);
    }
    let header = std::str::from_utf8(&input[..end]).map_err(|_| ParseError::Protocol)?;
    if header.contains("\r\n ") || header.contains("\r\n\t") {
        return Err(ParseError::Protocol);
    }
    let line = header.split("\r\n").next().ok_or(ParseError::Protocol)?;
    let mut parts = line.split(' ');
    if parts.next() != Some("CONNECT") {
        return Err(ParseError::Method);
    }
    let authority = parts.next().ok_or(ParseError::Authority)?;
    if parts.next() != Some("HTTP/1.1") || parts.next().is_some() {
        return Err(ParseError::Protocol);
    }
    let (host, port) = parse_authority(authority)?;
    Ok(ConnectRequest {
        host,
        port,
        trailing: &input[end..],
    })
}

fn parse_authority(authority: &str) -> Result<(Host, u16), ParseError> {
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let close = rest.find(']').ok_or(ParseError::Authority)?;
        if rest.as_bytes().get(close + 1) != Some(&b':') {
            return Err(ParseError::Authority);
        }
        let address = rest[..close]
            .parse::<Ipv6Addr>()
            .map_err(|_| ParseError::Authority)?;
        (Host::Ipv6(address), &rest[close + 2..])
    } else {
        let (name, port) = authority.rsplit_once(':').ok_or(ParseError::Authority)?;
        let host = if let Ok(address) = name.parse::<Ipv4Addr>() {
            Host::Ipv4(address)
        } else if valid_domain(name) {
            Host::Domain(name.to_owned())
        } else {
            return Err(ParseError::Authority);
        };
        (host, port)
    };
    let port = port.parse::<u16>().map_err(|_| ParseError::Authority)?;
    if port == 0 {
        return Err(ParseError::Authority);
    }
    Ok((host, port))
}

fn valid_domain(domain: &str) -> bool {
    !domain.is_empty()
        && domain.len() <= 253
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
    HeaderTooLarge,
    Method,
    Authority,
    Protocol,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Options {
    listen: String,
    max_connections: usize,
    max_header_bytes: usize,
}

fn validate_config(config: &[u8], _base: &[u8]) -> Result<(), String> {
    let text = std::str::from_utf8(config).map_err(|_| "config is not UTF-8".to_owned())?;
    let options: Options = toml::from_str(text).map_err(|error| error.to_string())?;
    if options.listen.is_empty() || options.max_connections == 0 || options.max_header_bytes < 64 {
        return Err("HTTP CONNECT options are inconsistent".into());
    }
    Ok(())
}

unsafe extern "C" fn open(
    instance: u64,
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
    name: "adapter-http-connect",
    description: "name = \"adapter-http-connect\"\nroles = [\"client\"]\nprotocol = \"HTTP/1.1 CONNECT\"\nforward_proxy = false\n",
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
    fn parses_ipv6_and_preserves_trailing_bytes() {
        let request = parse_connect(
            b"CONNECT [2001:db8::1]:443 HTTP/1.1\r\nHost: ignored\r\n\r\nhello",
            1024,
        )
        .unwrap();
        assert_eq!(request.host, Host::Ipv6("2001:db8::1".parse().unwrap()));
        assert_eq!(request.port, 443);
        assert_eq!(request.trailing, b"hello");
    }

    #[test]
    fn rejects_forward_proxy_and_oversized_headers() {
        assert_eq!(
            parse_connect(b"GET http://example.com HTTP/1.1\r\n\r\n", 1024),
            Err(ParseError::Method)
        );
        assert_eq!(
            parse_connect(&[b'a'; 64], 64),
            Err(ParseError::HeaderTooLarge)
        );
    }
}
