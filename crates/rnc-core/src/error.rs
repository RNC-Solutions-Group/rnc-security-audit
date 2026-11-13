//! Explicit library errors. No error variant carries matched credential bytes.

use std::fmt;
use std::io;

#[derive(Debug)]
pub enum CoreError {
    Locator(&'static str),
    Rule(String),
    Input(String),
    Limit(&'static str),
    Json(String),
    Io(io::Error),
}

impl fmt::Display for CoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Locator(message) => write!(formatter, "locator contract violated: {message}"),
            Self::Rule(message) => write!(formatter, "rule bundle invalid: {message}"),
            Self::Input(message) => write!(formatter, "input acquisition failed: {message}"),
            Self::Limit(message) => write!(formatter, "scan limit reached: {message}"),
            Self::Json(message) => write!(formatter, "JSON error: {message}"),
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
        }
    }
}

impl std::error::Error for CoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for CoreError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for CoreError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error.to_string())
    }
}
