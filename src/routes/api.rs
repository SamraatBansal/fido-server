//! API routes configuration

use actix_web::web;
use crate::controllers::{authentication, registration, health};

/// Configure all API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api")
            // Registration endpoints
            .route("/attestation/options", web::post().to(registration::attestation_options))
            .route("/attestation/result", web::post().to(registration::attestation_result))
            // Authentication endpoints
            .route("/assertion/options", web::post().to(authentication::assertion_options))
            .route("/assertion/result", web::post().to(authentication::assertion_result))
            // Health check
            .route("/health", web::get().to(health::health_check))
    );
}