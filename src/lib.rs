// Core modules
pub mod config;
pub mod domain;
pub mod error;
pub mod models;
pub mod services;
pub mod utils;

// API modules
pub mod api;
pub mod handlers;

// Infrastructure modules
pub mod adapters;
pub mod core;
pub mod db;
pub mod middleware;
pub mod ports;
pub mod routes;
pub mod schema;

// Test utilities (only in test builds)
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

// Re-exports for convenience
pub use config::AppConfig;
pub use error::{AppError, AppResult};
pub use models::*;