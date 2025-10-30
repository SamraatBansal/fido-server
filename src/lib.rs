//! FIDO Server Library
//!
//! A FIDO2/WebAuthn conformant server implementation in Rust.

pub mod app;
pub mod config;
pub mod controllers;
pub mod db;
pub mod error;
pub mod middleware;
pub mod models;
pub mod routes;
pub mod schema;
pub mod services;
pub mod utils;

pub use app::{AppState, create_server};
pub use error::{AppError, Result};
