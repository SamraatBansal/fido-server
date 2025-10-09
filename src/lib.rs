//! FIDO2/WebAuthn Conformance Test Server
//! 
//! This library provides a comprehensive FIDO2/WebAuthn server implementation
//! designed for conformance testing with full test coverage.

pub mod config;
pub mod controllers;
pub mod services;
pub mod db;
pub mod schema;
pub mod error;
pub mod middleware;
pub mod utils;
pub mod routes;

#[cfg(test)]
pub mod test_utils;

pub use error::{AppError, AppResult};