//! FIDO Server Library
//!
//! A FIDO2/WebAuthn conformant server implementation in Rust.

pub mod config;
pub mod controllers;
pub mod db;
pub mod error;
pub mod middleware;
pub mod routes;
pub mod schema;
pub mod services;
pub mod utils;
pub mod webauthn;

#[cfg(diesel)]
include!(concat!(env!("OUT_DIR"), "/diesel_schema.rs"));

pub use error::{AppError, Result};
