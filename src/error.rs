//! Error types. Every refusal carries a stable machine-readable `code` (audit, tests) and a readable `reason`.
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    Security,
    Path,
    Git,
    Command,
    Network,
    Permission,
}

#[derive(Debug, Clone)]
pub struct SecurityError {
    pub category: Category,
    pub code: String,
    pub reason: String,
}

impl SecurityError {
    pub fn new(category: Category, code: &str, reason: impl Into<String>) -> Self {
        Self {
            category,
            code: code.to_string(),
            reason: reason.into(),
        }
    }
    pub fn path(code: &str, reason: impl Into<String>) -> Self {
        Self::new(Category::Path, code, reason)
    }
    pub fn git(code: &str, reason: impl Into<String>) -> Self {
        Self::new(Category::Git, code, reason)
    }
    pub fn command(code: &str, reason: impl Into<String>) -> Self {
        Self::new(Category::Command, code, reason)
    }
    pub fn network(code: &str, reason: impl Into<String>) -> Self {
        Self::new(Category::Network, code, reason)
    }
    pub fn permission(code: &str, reason: impl Into<String>) -> Self {
        Self::new(Category::Permission, code, reason)
    }
}

impl fmt::Display for SecurityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.reason)
    }
}

impl std::error::Error for SecurityError {}

pub type SecResult<T> = std::result::Result<T, SecurityError>;

impl From<SecurityError> for Error {
    fn from(e: SecurityError) -> Self {
        Error::Security(e)
    }
}

#[derive(Debug)]
pub enum Error {
    /// Invalid configuration: fail closed at startup.
    Config(String),
    /// Operation refused by a security policy.
    Security(SecurityError),
    /// Tool arguments rejected by the schema.
    InvalidArgs(String),
    /// Unexpected internal failure; only `kind` reaches the LLM / audit (never paths or traces).
    Internal { kind: String, detail: String },
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn config(msg: impl Into<String>) -> Self {
        Error::Config(msg.into())
    }
    pub fn internal(kind: &str, detail: impl Into<String>) -> Self {
        Error::Internal {
            kind: kind.to_string(),
            detail: detail.into(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Config(m) => write!(f, "{m}"),
            Error::Security(e) => write!(f, "{e}"),
            Error::InvalidArgs(m) => write!(f, "invalid arguments : {m}"),
            Error::Internal { kind, detail } => write!(f, "{kind}: {detail}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::internal("OSError", e.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::internal("JSONDecodeError", e.to_string())
    }
}
