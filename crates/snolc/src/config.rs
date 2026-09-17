use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};

use serde::Deserialize;
use thiserror::Error;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub wire_version: u32,
    pub paths: Paths,
    pub engine: EngineConfig,
    pub stack: StackConfig,
    pub yamux: YamuxConfig,
    pub logging: LoggingConfig,
    pub control: ControlConfig,
    pub tunnels: Vec<TunnelConfig>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Paths {
    pub packages: PathBuf,
    pub state: PathBuf,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineConfig {
    pub max_sessions: usize,
    pub max_flows: usize,
    pub max_pending_sessions: usize,
    pub max_pending_opens: usize,
    pub max_managed_bytes: usize,
    pub max_commands: usize,
    pub max_events: usize,
    pub max_io_chunk: usize,
    pub max_ingress_packets_per_tick: usize,
    pub connect_timeout_ms: u64,
    pub handshake_timeout_ms: u64,
    pub shutdown_timeout_ms: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StackConfig {
    pub ipv4: bool,
    pub ipv6: bool,
    pub mtu: usize,
    pub tcp_socket_rx_bytes: usize,
    pub tcp_socket_tx_bytes: usize,
    pub udp_socket_rx_bytes: usize,
    pub udp_socket_tx_bytes: usize,
    pub udp_metadata_slots: usize,
    pub packet_queue_bytes: usize,
    pub max_udp_payload_bytes: usize,
    pub reassembly_slots: usize,
    pub reassembly_timeout_ms: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct YamuxConfig {
    pub max_streams_per_session: usize,
    pub receive_window_bytes: usize,
    pub split_send_size: usize,
    pub read_after_close: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "mode", rename_all = "lowercase", deny_unknown_fields)]
pub enum LoggingConfig {
    Off,
    File {
        source: LogSource,
        levels: Option<Vec<LogLevel>>,
        file: String,
        limit: String,
        logs: Option<String>,
        queue_bytes: usize,
        max_record_bytes: usize,
        flush_interval_ms: u64,
        on_io_error: LogIoError,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum LogSource {
    Toml,
    Env,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Warning,
    Error,
    Debug,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogIoError {
    Event,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "mode", rename_all = "lowercase", deny_unknown_fields)]
pub enum ControlConfig {
    Off,
    Unix {
        path: PathBuf,
        max_request_bytes: usize,
        max_connections: usize,
    },
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelConfig {
    pub name: String,
    pub role: Role,
    pub adapters: Vec<PathBuf>,
    pub protection: PathBuf,
    pub carrier: PathBuf,
    pub policy: PathBuf,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Client,
    Server,
}

impl Config {
    pub fn parse(input: &str, containing_directory: &Path) -> Result<Self, ConfigError> {
        let mut config: Self = toml::from_str(input)?;
        config.resolve_paths(containing_directory);
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.wire_version != snolc_abi::WIRE_VERSION {
            return Err(ConfigError::Invalid("wire_version must be 1"));
        }
        if !self.stack.ipv4 && !self.stack.ipv6 {
            return Err(ConfigError::Invalid(
                "at least one IP version must be enabled",
            ));
        }
        if self.stack.mtu < 1280 {
            return Err(ConfigError::Invalid("stack MTU must be at least 1280"));
        }
        if self.stack.max_udp_payload_bytes != crate::wire::MAX_UDP_PAYLOAD {
            return Err(ConfigError::Invalid("max UDP payload must be 65507"));
        }
        if self.stack.reassembly_slots != 4 {
            return Err(ConfigError::Invalid("reassembly slots must be 4"));
        }
        let capacities = [
            self.engine.max_sessions,
            self.engine.max_flows,
            self.engine.max_pending_sessions,
            self.engine.max_pending_opens,
            self.engine.max_managed_bytes,
            self.engine.max_commands,
            self.engine.max_events,
            self.engine.max_io_chunk,
            self.engine.max_ingress_packets_per_tick,
            self.stack.tcp_socket_rx_bytes,
            self.stack.tcp_socket_tx_bytes,
            self.stack.udp_socket_rx_bytes,
            self.stack.udp_socket_tx_bytes,
            self.stack.udp_metadata_slots,
            self.stack.packet_queue_bytes,
            self.stack.reassembly_slots,
            self.yamux.max_streams_per_session,
            self.yamux.receive_window_bytes,
            self.yamux.split_send_size,
        ];
        if capacities.contains(&0) {
            return Err(ConfigError::Invalid("capacities must be nonzero"));
        }
        if self.engine.max_io_chunk > self.stack.tcp_socket_rx_bytes
            || self.engine.max_io_chunk > self.stack.tcp_socket_tx_bytes
        {
            return Err(ConfigError::Invalid(
                "max_io_chunk exceeds a TCP socket buffer",
            ));
        }
        if self.stack.udp_socket_rx_bytes < self.stack.max_udp_payload_bytes
            || self.stack.udp_socket_tx_bytes < self.stack.max_udp_payload_bytes
        {
            return Err(ConfigError::Invalid(
                "UDP socket cannot hold a maximum datagram",
            ));
        }
        if self.yamux.max_streams_per_session < 2 {
            return Err(ConfigError::Invalid(
                "yamux needs one policy and one user stream",
            ));
        }
        let required_window = self
            .yamux
            .max_streams_per_session
            .checked_mul(256 * 1024)
            .ok_or(ConfigError::Overflow)?;
        if self.yamux.receive_window_bytes < required_window {
            return Err(ConfigError::Invalid("yamux receive window is too small"));
        }
        let all_windows = self
            .yamux
            .receive_window_bytes
            .checked_mul(self.engine.max_sessions)
            .ok_or(ConfigError::Overflow)?;
        if all_windows > self.engine.max_managed_bytes {
            return Err(ConfigError::Invalid("yamux windows exceed managed memory"));
        }
        let user_streams = self.yamux.max_streams_per_session - 1;
        let required_flows = self
            .engine
            .max_sessions
            .checked_mul(user_streams)
            .ok_or(ConfigError::Overflow)?;
        if self.engine.max_flows < required_flows {
            return Err(ConfigError::Invalid(
                "flow limit cannot serve configured yamux streams",
            ));
        }
        if [
            self.engine.connect_timeout_ms,
            self.engine.handshake_timeout_ms,
            self.engine.shutdown_timeout_ms,
            self.stack.reassembly_timeout_ms,
        ]
        .contains(&0)
        {
            return Err(ConfigError::Invalid("timeouts must be nonzero"));
        }
        self.validate_logging()?;
        if let ControlConfig::Unix {
            max_request_bytes,
            max_connections,
            ..
        } = self.control
            && (max_request_bytes == 0
                || max_request_bytes > u32::MAX as usize
                || max_connections == 0)
        {
            return Err(ConfigError::Invalid("control limits must be nonzero"));
        }
        if self.tunnels.is_empty() {
            return Err(ConfigError::Invalid("at least one tunnel is required"));
        }
        let mut names = HashSet::new();
        for tunnel in &self.tunnels {
            if tunnel.name.is_empty() || !names.insert(tunnel.name.as_str()) {
                return Err(ConfigError::Invalid(
                    "tunnel names must be nonempty and unique",
                ));
            }
            if tunnel.adapters.is_empty() {
                return Err(ConfigError::Invalid("a tunnel requires an adapter"));
            }
        }
        Ok(())
    }

    fn validate_logging(&self) -> Result<(), ConfigError> {
        let LoggingConfig::File {
            source,
            levels,
            file,
            limit,
            logs,
            queue_bytes,
            max_record_bytes,
            flush_interval_ms,
            ..
        } = &self.logging
        else {
            return Ok(());
        };
        if *queue_bytes == 0
            || *max_record_bytes == 0
            || *queue_bytes < *max_record_bytes
            || *flush_interval_ms == 0
        {
            return Err(ConfigError::Invalid("logging limits must be nonzero"));
        }
        match source {
            LogSource::Toml => {
                let levels = levels
                    .as_ref()
                    .ok_or(ConfigError::Invalid("TOML logging levels are required"))?;
                if levels.is_empty() {
                    return Err(ConfigError::Invalid("logging levels cannot be empty"));
                }
                let mut unique = HashSet::new();
                if !levels.iter().all(|level| unique.insert(*level)) {
                    return Err(ConfigError::Invalid("logging levels must be unique"));
                }
                if *max_record_bytes as u64 > parse_size(limit)? {
                    return Err(ConfigError::Invalid("log record exceeds log limit"));
                }
                if file.is_empty() || logs.is_some() {
                    return Err(ConfigError::Invalid("TOML logging fields are inconsistent"));
                }
            }
            LogSource::Env => {
                let logs = logs
                    .as_ref()
                    .ok_or(ConfigError::Invalid("environment LOGS name is required"))?;
                if levels.is_some() || [logs, file, limit].iter().any(|name| name.is_empty()) {
                    return Err(ConfigError::Invalid(
                        "environment logging fields are inconsistent",
                    ));
                }
            }
        }
        Ok(())
    }

    fn resolve_paths(&mut self, base: &Path) {
        self.paths.packages = resolve(base, &self.paths.packages);
        self.paths.state = resolve(base, &self.paths.state);
        if let LoggingConfig::File {
            source: LogSource::Toml,
            file,
            ..
        } = &mut self.logging
        {
            *file = resolve(base, Path::new(file))
                .to_string_lossy()
                .into_owned();
        }
        if let ControlConfig::Unix { path, .. } = &mut self.control {
            *path = resolve(base, path);
        }
        for tunnel in &mut self.tunnels {
            for adapter in &mut tunnel.adapters {
                *adapter = resolve(base, adapter);
            }
            tunnel.protection = resolve(base, &tunnel.protection);
            tunnel.carrier = resolve(base, &tunnel.carrier);
            tunnel.policy = resolve(base, &tunnel.policy);
        }
    }
}

pub fn parse_size(input: &str) -> Result<u64, ConfigError> {
    let split = input
        .find(|character: char| !character.is_ascii_digit() && character != '.')
        .ok_or(ConfigError::Size)?;
    let (number, unit) = input.split_at(split);
    let multiplier = match unit.to_ascii_lowercase().as_str() {
        "b" => 1_u64,
        "kb" => 1_000,
        "mb" => 1_000_000,
        "gb" => 1_000_000_000,
        "kib" => 1_024,
        "mib" => 1_048_576,
        "gib" => 1_073_741_824,
        _ => return Err(ConfigError::Size),
    };
    let mut parts = number.split('.');
    let integer = parts.next().ok_or(ConfigError::Size)?;
    if integer.is_empty() || !integer.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ConfigError::Size);
    }
    let whole = integer
        .parse::<u64>()
        .map_err(|_| ConfigError::Size)?
        .checked_mul(multiplier)
        .ok_or(ConfigError::Overflow)?;
    let Some(fraction) = parts.next() else {
        return Ok(whole);
    };
    if fraction.is_empty()
        || parts.next().is_some()
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(ConfigError::Size);
    }
    let power = u32::try_from(fraction.len()).map_err(|_| ConfigError::Overflow)?;
    let denominator = 10_u64.checked_pow(power).ok_or(ConfigError::Overflow)?;
    let numerator = fraction.parse::<u64>().map_err(|_| ConfigError::Size)?;
    let fractional = numerator
        .checked_mul(multiplier)
        .ok_or(ConfigError::Overflow)?
        / denominator;
    whole.checked_add(fractional).ok_or(ConfigError::Overflow)
}

fn resolve(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }
    let mut output = base.to_path_buf();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                output.pop();
            }
            Component::Normal(part) => output.push(part),
            Component::RootDir | Component::Prefix(_) => unreachable!("relative path checked"),
        }
    }
    output
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("configuration TOML is invalid: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("configuration is invalid: {0}")]
    Invalid(&'static str),
    #[error("size is invalid")]
    Size,
    #[error("integer overflow")]
    Overflow,
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEMPLATE: &str = include_str!("../../../config/templates/snolc-server-low-memory.toml");

    #[test]
    fn low_memory_template_is_valid() {
        Config::parse(TEMPLATE, Path::new("/etc/snolc")).unwrap();
    }

    #[test]
    fn rejects_unknown_and_missing_fields() {
        let unknown = TEMPLATE.replace("max_sessions = 2", "max_sessions = 2\nsecret = 1");
        assert!(matches!(
            Config::parse(&unknown, Path::new("/etc/snolc")),
            Err(ConfigError::Toml(_))
        ));
        let missing = TEMPLATE.replace("mtu = 1280\n", "");
        assert!(matches!(
            Config::parse(&missing, Path::new("/etc/snolc")),
            Err(ConfigError::Toml(_))
        ));
    }

    #[test]
    fn decimal_sizes_use_checked_integer_math() {
        assert_eq!(parse_size("1.1gb").unwrap(), 1_100_000_000);
        assert_eq!(parse_size("1.1kib").unwrap(), 1126);
        assert!(parse_size("NaNmb").is_err());
        assert!(parse_size("-1mb").is_err());
        assert!(parse_size("18446744073709551615gb").is_err());
    }

    #[test]
    fn rejects_reassembly_slots_that_do_not_match_smoltcp() {
        let invalid = TEMPLATE.replace("reassembly_slots = 4", "reassembly_slots = 3");
        assert!(matches!(
            Config::parse(&invalid, Path::new("/etc/snolc")),
            Err(ConfigError::Invalid("reassembly slots must be 4"))
        ));
    }
}
