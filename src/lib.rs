//! FIDO Server Library
//!
//! A FIDO2/WebAuthn conformant server implementation in Rust.

pub mod config;
pub mod controllers;
pub mod error;
pub mod routes;
pub mod schema;
pub mod services;

pub use error::{AppError, Result};