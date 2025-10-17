//! Error handling module

pub mod types;
pub mod handlers;

pub use types::{AppError, Result};
pub use handlers::*;
