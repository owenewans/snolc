use std::io;

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid command: {0}")]
    Usage(String),
    #[error("invalid configuration: {0}")]
    Config(String),
    #[error("logging failure: {0}")]
    Logging(String),
    #[error("insufficient permissions: {0}")]
    Permission(String),
    #[error("interface failure: {0}")]
    Interface(String),
    #[error("carrier failure: {0}")]
    Carrier(String),
    #[error("wire protocol failure: {0}")]
    Protocol(String),
    #[error("authentication failure: {0}")]
    Authentication(String),
    #[error("routing failure: {0}")]
    Routing(String),
    #[error("I/O failure: {0}")]
    Io(#[from] io::Error),
    #[error("runtime failure: {0}")]
    Runtime(String),
}

impl Error {
    pub const fn code(&self) -> u8 {
        match self {
            Self::Usage(_) => 2,
            Self::Config(_) => 3,
            Self::Logging(_) => 4,
            Self::Permission(_) => 5,
            Self::Interface(_) => 6,
            Self::Carrier(_) => 7,
            Self::Protocol(_) => 8,
            Self::Authentication(_) => 9,
            Self::Routing(_) => 10,
            Self::Io(_) => 11,
            Self::Runtime(_) => 12,
        }
    }
}
