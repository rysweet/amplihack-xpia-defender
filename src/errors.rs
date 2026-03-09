//! Error types for XPIA defense.

use thiserror::Error;

/// All errors that can occur in the XPIA defense system.
#[derive(Debug, Error)]
#[must_use = "XPIA errors indicate security failures — do not discard"]
pub enum XPIAError {
    /// A pattern failed to compile in guaranteed-linear mode.
    /// This is always a bug — all patterns must compile.
    #[error("Pattern compilation failed: {0}")]
    PatternCompilation(String),

    /// Validation logic encountered an internal error.
    /// Fail-closed: this results in content being blocked.
    #[error("Validation error: {0}")]
    Validation(String),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Configuration(String),

    /// JSON serialization/deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// URL parsing error.
    #[error("URL parse error: {0}")]
    UrlParse(#[from] url::ParseError),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
