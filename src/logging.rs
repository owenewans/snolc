use std::collections::BTreeSet;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{Error, Result};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Level {
    Warning,
    Error,
    Debug,
}

impl Level {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Debug => "debug",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Logger {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    levels: BTreeSet<Level>,
    output: Option<Output>,
}

#[derive(Debug)]
struct Output {
    path: PathBuf,
    limit: Option<u64>,
    lock: Mutex<()>,
}

impl Logger {
    pub fn from_env() -> Result<Self> {
        let logs = env::var_os("LOGS");
        let file = env::var_os("FILE");
        let limit = env::var_os("LIMIT");
        Self::from_values(logs, file, limit)
    }

    pub fn disabled() -> Self {
        Self {
            inner: Arc::new(Inner {
                levels: BTreeSet::new(),
                output: None,
            }),
        }
    }

    pub fn record(&self, level: Level, message: &str) {
        let _ = self.write(level, message);
    }

    pub fn write(&self, level: Level, message: &str) -> Result<()> {
        if !self.inner.levels.contains(&level) {
            return Ok(());
        }
        let Some(output) = &self.inner.output else {
            return Ok(());
        };
        let _guard = output
            .lock
            .lock()
            .map_err(|_| Error::Logging("logger lock is poisoned".to_owned()))?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Logging("system time precedes Unix epoch".to_owned()))?
            .as_millis();
        let message = message.replace('\r', "\\r").replace('\n', "\\n");
        let mut record = format!("{now} {} {message}\n", level.as_str()).into_bytes();
        if let Some(limit) = output.limit {
            record = fit_record(record, limit as usize);
        }

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&output.path)
            .map_err(|error| Error::Logging(error.to_string()))?;
        file.write_all(&record)
            .and_then(|()| file.flush())
            .map_err(|error| Error::Logging(error.to_string()))?;
        drop(file);

        if let Some(limit) = output.limit {
            trim_file(&output.path, limit)?;
        }
        Ok(())
    }

    fn from_values(
        logs: Option<std::ffi::OsString>,
        file: Option<std::ffi::OsString>,
        limit: Option<std::ffi::OsString>,
    ) -> Result<Self> {
        let Some(logs) = logs else {
            return Ok(Self::disabled());
        };
        let logs = logs
            .into_string()
            .map_err(|_| Error::Logging("LOGS is not valid UTF-8".to_owned()))?;
        let levels = parse_levels(&logs)?;
        let Some(file) = file else {
            return Ok(Self {
                inner: Arc::new(Inner {
                    levels,
                    output: None,
                }),
            });
        };
        if file.is_empty() {
            return Err(Error::Logging("FILE is empty".to_owned()));
        }
        let path = PathBuf::from(file);
        let limit = limit
            .map(|value| {
                value
                    .into_string()
                    .map_err(|_| Error::Logging("LIMIT is not valid UTF-8".to_owned()))
                    .and_then(|value| parse_limit(&value))
            })
            .transpose()?;

        OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|error| Error::Logging(error.to_string()))?;
        if let Some(limit) = limit {
            trim_file(&path, limit)?;
        }

        Ok(Self {
            inner: Arc::new(Inner {
                levels,
                output: Some(Output {
                    path,
                    limit,
                    lock: Mutex::new(()),
                }),
            }),
        })
    }
}

fn parse_levels(value: &str) -> Result<BTreeSet<Level>> {
    if value.is_empty() {
        return Err(Error::Logging("LOGS is empty".to_owned()));
    }
    value
        .split(',')
        .map(|item| match item.trim() {
            "warning" => Ok(Level::Warning),
            "error" => Ok(Level::Error),
            "debug" => Ok(Level::Debug),
            _ => Err(Error::Logging("LOGS contains an unknown level".to_owned())),
        })
        .collect()
}

pub fn parse_limit(value: &str) -> Result<u64> {
    let (number, multiplier) = if let Some(number) = value.strip_suffix("kb") {
        (number, 1024_u128)
    } else if let Some(number) = value.strip_suffix("mb") {
        (number, 1024_u128.pow(2))
    } else if let Some(number) = value.strip_suffix("gb") {
        (number, 1024_u128.pow(3))
    } else {
        return Err(Error::Logging("LIMIT has an unsupported unit".to_owned()));
    };

    let (whole, fraction, scale) = match number.split_once('.') {
        Some((whole, fraction)) if !fraction.is_empty() => {
            let scale = 10_u128
                .checked_pow(fraction.len() as u32)
                .ok_or_else(|| Error::Logging("LIMIT is too precise".to_owned()))?;
            (whole, fraction, scale)
        }
        Some(_) => return Err(Error::Logging("LIMIT has an invalid number".to_owned())),
        None => (number, "0", 1),
    };
    if whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(Error::Logging("LIMIT has an invalid number".to_owned()));
    }

    let whole = whole
        .parse::<u128>()
        .map_err(|_| Error::Logging("LIMIT is too large".to_owned()))?;
    let fraction = fraction
        .parse::<u128>()
        .map_err(|_| Error::Logging("LIMIT is too large".to_owned()))?;
    let units = whole
        .checked_mul(scale)
        .and_then(|value| value.checked_add(fraction))
        .ok_or_else(|| Error::Logging("LIMIT is too large".to_owned()))?;
    let bytes = units
        .checked_mul(multiplier)
        .map(|value| value / scale)
        .ok_or_else(|| Error::Logging("LIMIT is too large".to_owned()))?;
    if bytes == 0 || bytes > u64::MAX as u128 {
        return Err(Error::Logging(
            "LIMIT is outside the supported range".to_owned(),
        ));
    }
    Ok(bytes as u64)
}

fn fit_record(mut record: Vec<u8>, limit: usize) -> Vec<u8> {
    if record.len() <= limit {
        return record;
    }
    if limit == 1 {
        return vec![b'\n'];
    }
    record.truncate(limit - 1);
    while std::str::from_utf8(&record).is_err() {
        record.pop();
    }
    record.push(b'\n');
    record
}

fn trim_file(path: &Path, limit: u64) -> Result<()> {
    let length = fs::metadata(path)
        .map_err(|error| Error::Logging(error.to_string()))?
        .len();
    if length <= limit {
        return Ok(());
    }

    let mut source = File::open(path).map_err(|error| Error::Logging(error.to_string()))?;
    source
        .seek(SeekFrom::Start(length - limit))
        .map_err(|error| Error::Logging(error.to_string()))?;
    let mut retained = Vec::with_capacity(limit as usize);
    source
        .read_to_end(&mut retained)
        .map_err(|error| Error::Logging(error.to_string()))?;
    if let Some(newline) = retained.iter().position(|byte| *byte == b'\n') {
        retained.drain(..=newline);
    } else {
        retained.clear();
    }

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut random = [0_u8; 8];
    getrandom::fill(&mut random).map_err(|error| Error::Logging(error.to_string()))?;
    let temporary = parent.join(format!(
        ".snolc-log-{}-{:016x}.tmp",
        std::process::id(),
        u64::from_ne_bytes(random)
    ));

    let result = (|| -> std::io::Result<()> {
        let mut target = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        target.write_all(&retained)?;
        target.flush()?;
        fs::rename(&temporary, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(|error| Error::Logging(error.to_string()))
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::*;

    #[test]
    fn parses_fractional_limits_without_floating_point() {
        assert_eq!(parse_limit("2kb").unwrap(), 2 * 1024);
        assert_eq!(parse_limit("8mb").unwrap(), 8 * 1024 * 1024);
        assert_eq!(parse_limit("1gb").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(parse_limit("1.1gb").unwrap(), 1_181_116_006);
        assert!(parse_limit("1GB").is_err());
        assert!(parse_limit("0kb").is_err());
    }

    #[test]
    fn appends_and_removes_old_complete_records() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("snolc.log");
        fs::write(&path, "old record that must disappear\n").unwrap();
        let logger = Logger::from_values(
            Some(OsString::from("error")),
            Some(path.clone().into_os_string()),
            Some(OsString::from("0.05kb")),
        )
        .unwrap();

        logger.write(Level::Error, "new-record").unwrap();
        let contents = fs::read_to_string(path).unwrap();
        assert!(!contents.contains("old record"));
        assert!(contents.contains("new-record"));
        assert!(contents.len() <= 51);
    }

    #[test]
    fn does_not_create_a_file_without_logs() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("snolc.log");
        let logger = Logger::from_values(None, Some(path.clone().into_os_string()), None).unwrap();
        logger.write(Level::Error, "ignored").unwrap();
        assert!(!path.exists());
    }
}
