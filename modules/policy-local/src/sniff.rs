#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Observed {
    Tls { sni: Option<String> },
    Http { host: Option<String> },
    Ssh,
    Quic,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Classification {
    NeedMore,
    Complete(Observed),
}

pub fn classify_tcp(prefix: &[u8], complete: bool) -> Classification {
    if prefix.starts_with(b"SSH-") {
        return if prefix.windows(2).any(|window| window == b"\r\n") {
            Classification::Complete(Observed::Ssh)
        } else if complete {
            Classification::Complete(Observed::Unknown)
        } else {
            Classification::NeedMore
        };
    }
    if prefix.first() == Some(&0x16) {
        return classify_tls(prefix, complete);
    }
    if looks_like_http(prefix) {
        return classify_http(prefix, complete);
    }
    if complete || prefix.len() >= 8 {
        Classification::Complete(Observed::Unknown)
    } else {
        Classification::NeedMore
    }
}

pub fn classify_udp(prefix: &[u8]) -> Observed {
    if prefix.first().is_some_and(|byte| byte & 0xc0 == 0xc0) {
        Observed::Quic
    } else {
        Observed::Unknown
    }
}

fn classify_tls(prefix: &[u8], complete: bool) -> Classification {
    let Some(record_length) = be_u16(prefix, 3) else {
        return incomplete(complete);
    };
    let record_end = 5usize.saturating_add(record_length as usize);
    if prefix.len() < record_end {
        return incomplete(complete);
    }
    let record = &prefix[5..record_end];
    if record.first() != Some(&1) {
        return Classification::Complete(Observed::Tls { sni: None });
    }
    let Some(handshake_length) = be_u24(record, 1) else {
        return Classification::Complete(Observed::Tls { sni: None });
    };
    if handshake_length.saturating_add(4) > record.len() {
        return Classification::Complete(Observed::Tls { sni: None });
    }
    let hello = &record[4..4 + handshake_length];
    let Some(mut offset) = 34usize.checked_add(1) else {
        return Classification::Complete(Observed::Tls { sni: None });
    };
    let Some(session_length) = hello.get(34).copied() else {
        return Classification::Complete(Observed::Tls { sni: None });
    };
    offset = match offset.checked_add(session_length as usize) {
        Some(offset) => offset,
        None => return Classification::Complete(Observed::Tls { sni: None }),
    };
    let Some(cipher_length) = be_u16(hello, offset) else {
        return Classification::Complete(Observed::Tls { sni: None });
    };
    offset = match offset.checked_add(2 + cipher_length as usize) {
        Some(offset) => offset,
        None => return Classification::Complete(Observed::Tls { sni: None }),
    };
    let Some(compression_length) = hello.get(offset).copied() else {
        return Classification::Complete(Observed::Tls { sni: None });
    };
    offset = match offset.checked_add(1 + compression_length as usize) {
        Some(offset) => offset,
        None => return Classification::Complete(Observed::Tls { sni: None }),
    };
    let Some(extensions_length) = be_u16(hello, offset) else {
        return Classification::Complete(Observed::Tls { sni: None });
    };
    offset += 2;
    let extensions_end = match offset.checked_add(extensions_length as usize) {
        Some(end) if end <= hello.len() => end,
        _ => return Classification::Complete(Observed::Tls { sni: None }),
    };
    while offset + 4 <= extensions_end {
        let kind = be_u16(hello, offset).unwrap_or(u16::MAX);
        let length = be_u16(hello, offset + 2).unwrap_or(0) as usize;
        offset += 4;
        let Some(extension) = hello.get(offset..offset.saturating_add(length)) else {
            return Classification::Complete(Observed::Tls { sni: None });
        };
        if kind == 0 {
            return Classification::Complete(Observed::Tls {
                sni: parse_sni(extension),
            });
        }
        offset += length;
    }
    Classification::Complete(Observed::Tls { sni: None })
}

fn parse_sni(extension: &[u8]) -> Option<String> {
    let list_length = be_u16(extension, 0)? as usize;
    if list_length + 2 != extension.len() {
        return None;
    }
    let mut offset = 2;
    while offset + 3 <= extension.len() {
        let kind = extension[offset];
        let length = be_u16(extension, offset + 1)? as usize;
        offset += 3;
        let name = extension.get(offset..offset.checked_add(length)?)?;
        if kind == 0 {
            let name = std::str::from_utf8(name).ok()?.to_ascii_lowercase();
            return valid_domain(&name).then_some(name);
        }
        offset += length;
    }
    None
}

fn classify_http(prefix: &[u8], complete: bool) -> Classification {
    let Some(end) = prefix.windows(4).position(|window| window == b"\r\n\r\n") else {
        return incomplete(complete);
    };
    let Ok(header) = std::str::from_utf8(&prefix[..end + 4]) else {
        return Classification::Complete(Observed::Unknown);
    };
    let mut lines = header.split("\r\n");
    let Some(request) = lines.next() else {
        return Classification::Complete(Observed::Unknown);
    };
    if !request.ends_with(" HTTP/1.0") && !request.ends_with(" HTTP/1.1") {
        return Classification::Complete(Observed::Unknown);
    }
    let host = lines.find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("host")
            .then(|| normalize_host(value.trim()))
            .flatten()
    });
    Classification::Complete(Observed::Http { host })
}

fn normalize_host(value: &str) -> Option<String> {
    let host = if value.starts_with('[') {
        value.split_once(']')?.0.trim_start_matches('[')
    } else {
        value.split(':').next()?
    };
    let host = host.to_ascii_lowercase();
    valid_domain(&host).then_some(host)
}

fn looks_like_http(prefix: &[u8]) -> bool {
    const METHODS: [&[u8]; 9] = [
        b"GET ",
        b"POST ",
        b"PUT ",
        b"HEAD ",
        b"DELETE ",
        b"OPTIONS ",
        b"PATCH ",
        b"TRACE ",
        b"CONNECT ",
    ];
    METHODS
        .iter()
        .any(|method| method.starts_with(prefix) || prefix.starts_with(method))
}

fn incomplete(complete: bool) -> Classification {
    if complete {
        Classification::Complete(Observed::Unknown)
    } else {
        Classification::NeedMore
    }
}

fn be_u16(input: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        input.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn be_u24(input: &[u8], offset: usize) -> Option<usize> {
    let bytes = input.get(offset..offset + 3)?;
    Some((bytes[0] as usize) << 16 | (bytes[1] as usize) << 8 | bytes[2] as usize)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_http_host_and_ssh() {
        assert_eq!(
            classify_tcp(b"GET / HTTP/1.1\r\nHost: Example.COM:443\r\n\r\n", false),
            Classification::Complete(Observed::Http {
                host: Some("example.com".into())
            })
        );
        assert_eq!(
            classify_tcp(b"SSH-2.0-OpenSSH_9.0\r\n", false),
            Classification::Complete(Observed::Ssh)
        );
    }

    #[test]
    fn parses_tls_client_hello_sni() {
        let name = b"example.com";
        let mut extension = vec![0, (name.len() + 3) as u8, 0, 0, name.len() as u8];
        extension.extend_from_slice(name);
        let mut extensions = vec![0, 0, 0, extension.len() as u8];
        extensions.extend_from_slice(&extension);
        let mut hello = vec![3, 3];
        hello.extend_from_slice(&[0; 32]);
        hello.extend_from_slice(&[0, 0, 2, 0x13, 1, 1, 0]);
        hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello.extend_from_slice(&extensions);
        let mut handshake = vec![1, 0, 0, hello.len() as u8];
        handshake.extend_from_slice(&hello);
        let mut record = vec![0x16, 3, 1];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        assert_eq!(
            classify_tcp(&record, false),
            Classification::Complete(Observed::Tls {
                sni: Some("example.com".into())
            })
        );
    }

    #[test]
    fn quic_requires_long_header_bits() {
        assert_eq!(classify_udp(&[0xc0]), Observed::Quic);
        assert_eq!(classify_udp(&[0x40]), Observed::Unknown);
    }
}
