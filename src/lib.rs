//! FIDO Server Library
//!
//! A FIDO2/WebAuthn conformant server implementation in Rust.

use actix_web::{web, App};
use crate::controllers::health_check;
use crate::routes::{configure_api_routes, configure_health_routes};
use crate::middleware::{configure_cors, security_headers};

pub mod config;
pub mod controllers;
pub mod db;
pub mod error;
pub mod middleware;
pub mod routes;
pub mod schema;
pub mod services;
pub mod utils;

pub use error::{AppError, Result};

/// Configure the Actix-web application
pub fn configure_app() -> App<()> {
    App::new()
        // Add middleware
        .wrap(security_headers())
        .wrap(configure_cors())
        // Configure routes
        .service(configure_health_routes())
        .service(configure_api_routes())
        // Legacy health endpoints for backward compatibility
        .route("/health", web::get().to(health_check))
        .route("/api/v1/health", web::get().to(health_check))
}