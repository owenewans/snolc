use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ipnet::IpNet;
use serde::Deserialize;

use crate::error::{Error, Result};
use crate::protection::ProtectionMode;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub role: Role,
    pub remote: Option<String>,
    pub bind: Option<String>,
    pub carrier: Carrier,
    pub protection: Protection,
    pub heartbeat: u64,
    pub reconnect: Option<i32>,
    pub limits: Option<Limits>,
    pub routing: Option<PathBuf>,
    pub tun: Option<Tun>,
    pub socks: Option<Socks>,
    pub http: Option<Http>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Client,
    Server,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum Carrier {
    Ssh {
        transport: Transport,
    },
    Http {
        transport: Transport,
        host: String,
        path: String,
        tls: Option<CarrierTls>,
    },
    Webrtc {
        transport: Transport,
    },
    Socks {
        transport: Transport,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Tcp,
    Udp,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(tag = "mode", rename_all = "lowercase", deny_unknown_fields)]
pub enum CarrierTls {
    /// A real, publicly trusted certificate obtained autonomously from Let's
    /// Encrypt (TLS-ALPN-01). `bind`/`remote` must use port 443 for this: the
    /// CA always validates the TLS-ALPN-01 challenge against port 443 of the
    /// domain's resolved address, independent of what port the service would
    /// otherwise prefer.
    Acme { domain: String, cache: PathBuf },
    /// REALITY-style camouflage: the client sends a syntactically valid TLS
    /// 1.3 ClientHello for `donor`'s SNI carrying a time-windowed HMAC tag in
    /// the session_id field. A server that recognizes the tag switches to the
    /// snolc protocol; anyone else (a real browser, a scanner, active probing
    /// by a censor) is spliced byte-for-byte to `donor` and gets `donor`'s
    /// genuine TLS session back, indistinguishable from contacting it
    /// directly.
    Steal {
        donor: String,
        /// Which TLS ClientHello shape the client sends for this
        /// camouflage. `none` is the built-in hand-shaped hello (no extra
        /// native dependency); the others drive a real BoringSSL handshake
        /// (via `boring`) configured to match that browser's real
        /// cipher/extension/ALPN shape byte-for-byte, so the same library a
        /// real browser uses produces the observable bytes.
        fingerprint: Fingerprint,
        secret: String,
        mirror: MirrorConfig,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Fingerprint {
    None,
    Chrome131,
    Firefox133,
}

/// Response caching for a mirrored (spliced) connection: identical requests
/// get replayed from memory instead of re-contacting the target. Never
/// persisted to disk.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MirrorConfig {
    pub cache: bool,
    pub ttl: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Protection {
    pub mode: ProtectionMode,
    pub key: Option<String>,
    pub clients: Option<Vec<ClientKey>>,
    pub unknown: Option<UnknownClient>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ClientKey {
    pub key: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(tag = "mode", rename_all = "lowercase", deny_unknown_fields)]
pub enum UnknownClient {
    Error,
    Site {
        target: String,
        mirror: MirrorConfig,
    },
    File {
        path: PathBuf,
    },
    Service {
        target: String,
        mirror: MirrorConfig,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub connections: usize,
    pub streams: usize,
    pub fragments: usize,
    pub memory: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Tun {
    pub name: String,
    pub address: Vec<IpNet>,
    pub mtu: u16,
    pub auto: bool,
    pub descriptor: Option<i32>,
    pub include: Option<Vec<IpNet>>,
    pub exclude: Option<Vec<IpNet>>,
    pub strict_route: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Socks {
    pub pass: Option<String>,
    pub user: Option<String>,
    pub host: IpAddr,
    pub port: u16,
    pub listen: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Http {
    pub pass: Option<String>,
    pub user: Option<String>,
    pub host: IpAddr,
    pub port: u16,
    pub tls: Option<InboundTls>,
    pub listen: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct InboundTls {
    pub enabled: bool,
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let source = fs::read_to_string(path)?;
        let mut config: Self =
            yaml_serde::from_str(&source).map_err(|error| Error::Config(error.to_string()))?;
        config.validate()?;

        if let Some(routing) = &mut config.routing
            && routing.is_relative()
        {
            let parent = path.parent().unwrap_or_else(|| Path::new("."));
            *routing = parent.join(&*routing);
        }

        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.heartbeat == 0 {
            return Err(config_error("heartbeat must be greater than zero"));
        }
        self.carrier.validate()?;
        self.protection.validate(self.role)?;

        if let Some(tun) = &self.tun {
            tun.validate()?;
        }
        if let Some(socks) = &self.socks {
            validate_auth(&socks.user, &socks.pass, "socks")?;
            validate_port(socks.port, "socks")?;
        }
        if let Some(http) = &self.http {
            validate_auth(&http.user, &http.pass, "http")?;
            validate_port(http.port, "http")?;
            if let Some(tls) = &http.tls {
                tls.validate()?;
            }
        }

        match self.role {
            Role::Client => self.validate_client(),
            Role::Server => self.validate_server(),
        }
    }

    fn validate_client(&self) -> Result<()> {
        let remote = self
            .remote
            .as_deref()
            .ok_or_else(|| config_error("client remote is required"))?;
        validate_endpoint(remote, "remote")?;
        if self
            .carrier
            .tls()
            .is_some_and(CarrierTls::requires_port_443)
            && !remote.ends_with(":443")
        {
            return Err(config_error("acme carrier requires port 443"));
        }
        if self.bind.is_some() {
            return Err(config_error("client cannot set bind"));
        }
        match self.reconnect {
            None => return Err(config_error("client reconnect is required")),
            Some(value) if value < -1 => {
                return Err(config_error("client reconnect must be -1, 0, or positive"));
            }
            Some(_) => {}
        }
        if self.limits.is_some() {
            return Err(config_error("client cannot set server limits"));
        }
        if !self.has_active_inbound() {
            return Err(config_error("client requires an active inbound"));
        }
        Ok(())
    }

    fn validate_server(&self) -> Result<()> {
        let bind = self
            .bind
            .as_deref()
            .ok_or_else(|| config_error("server bind is required"))?;
        validate_endpoint(bind, "bind")?;
        if self
            .carrier
            .tls()
            .is_some_and(CarrierTls::requires_port_443)
            && !bind.ends_with(":443")
        {
            return Err(config_error("acme carrier requires port 443"));
        }
        if self.remote.is_some() {
            return Err(config_error("server cannot set remote"));
        }
        if self.reconnect.is_some() {
            return Err(config_error("server cannot set reconnect"));
        }
        if self.tun.is_some() || self.socks.is_some() || self.http.is_some() {
            return Err(config_error("server cannot define an inbound"));
        }
        let limits = self
            .limits
            .as_ref()
            .ok_or_else(|| config_error("server limits are required"))?;
        limits.validate()
    }

    fn has_active_inbound(&self) -> bool {
        self.tun.is_some()
            || self.socks.as_ref().is_some_and(|inbound| inbound.listen)
            || self.http.as_ref().is_some_and(|inbound| inbound.listen)
    }
}

impl Carrier {
    fn validate(&self) -> Result<()> {
        match self {
            Self::Ssh { transport } | Self::Http { transport, .. } | Self::Socks { transport }
                if *transport != Transport::Tcp =>
            {
                Err(config_error("selected carrier requires TCP"))
            }
            Self::Webrtc { transport } if *transport != Transport::Udp => {
                Err(config_error("WebRTC requires UDP"))
            }
            Self::Http {
                host, path, tls, ..
            } => {
                validate_hostname(host, "HTTP carrier host")?;
                if !path.starts_with('/')
                    || path
                        .bytes()
                        .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
                {
                    return Err(config_error("HTTP carrier path is invalid"));
                }
                if let Some(tls) = tls {
                    tls.validate()?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    pub const fn tls(&self) -> Option<&CarrierTls> {
        match self {
            Self::Http { tls, .. } => tls.as_ref(),
            _ => None,
        }
    }
}

impl CarrierTls {
    fn validate(&self) -> Result<()> {
        match self {
            Self::Acme { domain, cache, .. } => {
                validate_hostname(domain, "TLS domain")?;
                if cache.as_os_str().is_empty() {
                    return Err(config_error("acme cache directory cannot be empty"));
                }
                Ok(())
            }
            Self::Steal {
                donor,
                secret,
                mirror,
                ..
            } => {
                validate_hostname(donor, "TLS donor")?;
                validate_key(secret, "steal secret")?;
                mirror.validate()
            }
        }
    }

    /// Whether this mode requires binding/dialing port 443 specifically.
    /// TLS-ALPN-01 validation always targets port 443 of the domain's
    /// resolved address, regardless of the port the service would otherwise
    /// run on.
    pub const fn requires_port_443(&self) -> bool {
        matches!(self, Self::Acme { .. })
    }
}

impl MirrorConfig {
    fn validate(&self) -> Result<()> {
        if self.cache && self.ttl == 0 {
            return Err(config_error("mirror cache ttl must be greater than zero"));
        }
        Ok(())
    }
}

impl Protection {
    fn validate(&self, role: Role) -> Result<()> {
        match role {
            Role::Client => {
                validate_key(
                    self.key
                        .as_deref()
                        .ok_or_else(|| config_error("client private key is required"))?,
                    "client private key",
                )?;
                if self.clients.is_some() || self.unknown.is_some() {
                    return Err(config_error(
                        "client cannot define server authentication fields",
                    ));
                }
            }
            Role::Server => {
                if self.key.is_some() {
                    return Err(config_error("server cannot define a client private key"));
                }
                let clients = self
                    .clients
                    .as_ref()
                    .ok_or_else(|| config_error("server clients are required"))?;
                if clients.is_empty() {
                    return Err(config_error("server clients cannot be empty"));
                }
                for client in clients {
                    validate_key(&client.key, "client public key")?;
                }
                if let Some(unknown) = &self.unknown {
                    unknown.validate()?;
                } else {
                    return Err(config_error("unknown-client behavior is required"));
                }
            }
        }
        Ok(())
    }
}

impl UnknownClient {
    fn validate(&self) -> Result<()> {
        match self {
            Self::Error | Self::File { .. } => Ok(()),
            Self::Site { target, mirror } | Self::Service { target, mirror } => {
                validate_endpoint(target, "unknown-client target")?;
                mirror.validate()
            }
        }
    }
}

impl Limits {
    fn validate(&self) -> Result<()> {
        if self.connections == 0 || self.streams == 0 || self.fragments == 0 || self.memory == 0 {
            return Err(config_error("all server limits must be greater than zero"));
        }
        let minimum = self
            .streams
            .checked_mul(yamux::DEFAULT_CREDIT as usize)
            .ok_or_else(|| config_error("server stream memory limit overflows"))?;
        if self.memory < minimum {
            return Err(config_error(
                "server memory must provide 256kb for every yamux stream",
            ));
        }
        Ok(())
    }
}

impl Tun {
    fn validate(&self) -> Result<()> {
        if self.name.is_empty() || self.name.len() > 15 || self.name.as_bytes().contains(&0) {
            return Err(config_error("tun name must contain 1 to 15 non-NUL bytes"));
        }
        if self.mtu < 1280 {
            return Err(config_error("tun MTU must be at least 1280"));
        }
        if !self
            .address
            .iter()
            .any(|network| matches!(network, IpNet::V4(_)))
            || !self
                .address
                .iter()
                .any(|network| matches!(network, IpNet::V6(_)))
        {
            return Err(config_error("tun requires IPv4 and IPv6 addresses"));
        }
        if self.descriptor.is_some_and(|descriptor| descriptor < 0) {
            return Err(config_error("tun descriptor cannot be negative"));
        }
        #[cfg(target_os = "android")]
        if self.descriptor.is_none() {
            return Err(config_error("tun descriptor is required on Android"));
        }
        Ok(())
    }
}

impl InboundTls {
    fn validate(&self) -> Result<()> {
        if self.enabled && (self.cert.is_none() || self.key.is_none()) {
            return Err(config_error("enabled inbound TLS requires cert and key"));
        }
        if !self.enabled && (self.cert.is_some() || self.key.is_some()) {
            return Err(config_error(
                "disabled inbound TLS cannot define cert or key",
            ));
        }
        Ok(())
    }
}

fn validate_auth(user: &Option<String>, pass: &Option<String>, name: &str) -> Result<()> {
    if user.is_some() != pass.is_some() {
        return Err(config_error(&format!(
            "{name} user and pass must be set together"
        )));
    }
    Ok(())
}

fn validate_port(port: u16, name: &str) -> Result<()> {
    if port == 0 {
        return Err(config_error(&format!("{name} port cannot be zero")));
    }
    Ok(())
}

fn validate_endpoint(endpoint: &str, field: &str) -> Result<()> {
    let (host, port) = if endpoint.starts_with('[') {
        let closing = endpoint
            .find(']')
            .ok_or_else(|| config_error(&format!("{field} has an invalid IPv6 address")))?;
        let host = &endpoint[1..closing];
        let port = endpoint
            .get(closing + 1..)
            .and_then(|tail| tail.strip_prefix(':'))
            .ok_or_else(|| config_error(&format!("{field} has no port")))?;
        (host, port)
    } else {
        endpoint
            .rsplit_once(':')
            .ok_or_else(|| config_error(&format!("{field} has no port")))?
    };

    if host.is_empty() {
        return Err(config_error(&format!("{field} has no host")));
    }
    let port = port
        .parse::<u16>()
        .map_err(|_| config_error(&format!("{field} has an invalid port")))?;
    validate_port(port, field)
}

fn validate_hostname(host: &str, field: &str) -> Result<()> {
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() || host.len() > 253 {
        return Err(config_error(&format!("{field} is invalid")));
    }
    for label in host.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(config_error(&format!("{field} is invalid")));
        }
    }
    Ok(())
}

fn validate_key(value: &str, field: &str) -> Result<()> {
    let decoded = STANDARD
        .decode(value)
        .map_err(|_| config_error(&format!("{field} is not base64")))?;
    if decoded.len() != 32 {
        return Err(config_error(&format!("{field} must contain 32 bytes")));
    }
    Ok(())
}

fn config_error(message: &str) -> Error {
    Error::Config(message.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    fn parse(source: &str) -> Result<Config> {
        let config: Config =
            yaml_serde::from_str(source).map_err(|error| Error::Config(error.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    #[test]
    fn accepts_a_complete_client() {
        let source = format!(
            r#"
role: client
remote: example.com:443
bind: null
carrier:
  kind: http
  transport: tcp
  host: example.com
  path: /api/events
  tls:
    mode: steal
    donor: example.com
    fingerprint: chrome131
    secret: {KEY}
    mirror:
      cache: true
      ttl: 60
protection:
  mode: chacha poly
  key: {KEY}
  clients: null
  unknown: null
heartbeat: 15
reconnect: -1
limits: null
routing: rules.yml
tun: null
socks:
  pass: null
  user: null
  host: 127.0.0.1
  port: 1080
  listen: true
http: null
"#
        );
        assert_eq!(parse(&source).unwrap().role, Role::Client);
    }

    #[test]
    fn rejects_wrong_carrier_transport() {
        let source = format!(
            r#"
role: client
remote: example.com:443
bind: null
carrier:
  kind: ssh
  transport: udp
protection:
  mode: no
  key: {KEY}
  clients: null
  unknown: null
heartbeat: 15
reconnect: 0
limits: null
routing: null
tun: null
socks:
  pass: null
  user: null
  host: 127.0.0.1
  port: 1080
  listen: true
http: null
"#
        );
        assert!(parse(&source).is_err());
    }

    #[test]
    fn rejects_a_server_with_an_inbound() {
        let source = format!(
            r#"
role: server
remote: null
bind: "[::]:443"
carrier:
  kind: webrtc
  transport: udp
protection:
  mode: AES-GCM
  key: null
  clients:
    - key: {KEY}
  unknown:
    mode: error
heartbeat: 15
reconnect: null
limits:
  connections: 10
  streams: 50
  fragments: 100
  memory: 13107200
routing: null
tun: null
socks:
  pass: null
  user: null
  host: 127.0.0.1
  port: 1080
  listen: false
http: null
"#
        );
        assert!(parse(&source).is_err());
    }

    #[test]
    fn rejects_unknown_fields() {
        let source = "role: client\ndefault: true\n";
        assert!(yaml_serde::from_str::<Config>(source).is_err());
    }
}
