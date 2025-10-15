pub mod api;
pub mod config;
pub mod core;
pub mod domain;
pub mod error;
pub mod ports;
pub mod adapters;
pub mod utils;

#[cfg(feature = "test-utils")]
pub mod test_utils;

pub use error::{AppError, Result};