//! Common test utilities and shared functionality for all test suites

pub mod fixtures;
pub mod mock_server;
pub mod database;
pub mod test_helpers;
pub mod assertions;

pub use fixtures::*;
pub use mock_server::*;
pub use database::*;
pub use test_helpers::*;
pub use assertions::*;

// Re-export common dependencies for tests
pub use actix_web::{http::StatusCode, test, App};
pub use reqwest::Client;
pub use serde_json::{json, Value};
pub use uuid::Uuid;