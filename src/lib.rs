pub mod api_types;
pub mod config;
pub mod database;
pub mod error;
pub mod handlers;
pub mod models;
pub mod schema;
pub mod webauthn_service;

pub use config::AppConfig;
pub use database::{create_pool, DatabaseService};
pub use error::{AppError, Result};
pub use webauthn_service::WebAuthnService;