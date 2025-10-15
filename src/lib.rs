pub mod config;
pub mod controllers;
pub mod db;
pub mod error;
pub mod middleware;
pub mod routes;
pub mod services;
pub mod schema;
pub mod utils;

// Re-export commonly used types
pub use error::{AppError, AppResult};
pub use config::Settings;

// Test utilities (only available in test builds)
#[cfg(test)]
pub mod test_utils;