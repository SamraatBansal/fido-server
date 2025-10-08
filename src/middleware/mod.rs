//! Middleware module

pub mod cors;
pub mod error_handler;
pub mod rate_limiting;
pub mod security;

pub use cors::cors_config;
pub use error_handler::ErrorHandler;
pub use rate_limiting::{rate_limiter, strict_rate_limiter};
pub use security::security_headers;