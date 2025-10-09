//! Common test utilities and fixtures for FIDO2/WebAuthn testing

pub mod fixtures;
pub mod helpers;
pub mod mocks;
pub mod test_data;

pub use fixtures::*;
pub use helpers::*;
pub use mocks::*;
pub use test_data::*;

// Re-export common testing dependencies
pub use actix_web::{
    dev::ServiceResponse,
    http::{header::ContentType, StatusCode},
    test, App,
};
pub use serde_json::{json, Value};
pub use uuid::Uuid;