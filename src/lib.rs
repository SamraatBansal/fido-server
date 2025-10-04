//! FIDO Server Library
//!
//! A FIDO2/WebAuthn conformant server implementation in Rust.

pub mod config;
pub mod error;

pub use error::{AppError, Result};