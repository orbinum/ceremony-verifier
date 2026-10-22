//! One error type for the whole crate: every failure names what was wrong.

use std::fmt;

/// Why an input was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The bytes are not a well-formed snarkjs file (truncated, bad magic, bad section table…).
    Format(String),
    /// A value is well formed but not acceptable (non-canonical field element, point off-curve…).
    Invalid(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Format(m) => write!(f, "format: {m}"),
            Error::Invalid(m) => write!(f, "invalid: {m}"),
        }
    }
}

impl std::error::Error for Error {}

/// The crate's result type.
pub type Result<T> = std::result::Result<T, Error>;

/// A [`Error::Format`] failure.
pub fn format<T>(message: impl Into<String>) -> Result<T> {
    Err(Error::Format(message.into()))
}

/// An [`Error::Invalid`] failure.
pub fn invalid<T>(message: impl Into<String>) -> Result<T> {
    Err(Error::Invalid(message.into()))
}
