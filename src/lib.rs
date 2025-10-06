//! FIDO Server Library - Minimal TDD Implementation
//! 
//! A simplified FIDO2/WebAuthn conformant server implementation in Rust.

pub mod error;
pub mod services;

pub use error::{AppError, Result};
pub use services::FidoService;