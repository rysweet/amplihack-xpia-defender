//! # amplihack-xpia-defender
//!
//! Standalone Rust library for detecting Cross-Prompt Injection Attacks (XPIA)
//! in LLM agent systems.
//!
//! ## Design principles
//!
//! - **Fail-closed**: errors in validation block content, never allow through.
//! - **No fallbacks**: pattern compilation failure is a hard error.
//! - **Guaranteed-linear**: all regex uses Rust's `regex` crate (no ReDoS).
//! - **Two-tier matching**: Aho-Corasick pre-filter → regex confirmation.

pub mod engine;
pub mod errors;
pub mod health;
pub mod patterns;
pub mod types;

// Re-export the main public API
pub use engine::XPIADefender;
pub use errors::XPIAError;
pub use health::{check_xpia_health, HealthReport};
pub use patterns::{PatternRegistry, PromptPatterns, URLPatterns};
pub use types::*;
