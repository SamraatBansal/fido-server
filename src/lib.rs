//! FIDO Server Library
//!
//! A FIDO2/WebAuthn conformant server implementation in Rust.

// Generated schema by diesel
pub mod schema;

pub mod config;
pub mod controllers;
pub mod db;
pub mod error;
pub mod middleware;
pub mod models;
pub mod routes;
pub mod schemas;
pub mod services;
pub mod utils;

pub use error::{AppError, Result};
