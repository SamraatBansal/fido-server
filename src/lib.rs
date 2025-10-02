//! FIDO Server Library
//!
//! A FIDO2/WebAuthn conformant server implementation in Rust.

use config::Config;
use storage::Storage;

pub mod auth;
pub mod config;
pub mod credential;
pub mod error;
pub mod mapping;
pub mod storage;
pub mod webauthn;

pub use error::AppError;

#[derive(Clone)]
pub struct AppState {
    pub storage: Storage,
    pub config: Config,
}