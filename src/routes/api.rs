//! API routes configuration

use actix_web::web;

use crate::controllers::*;

/// Configure all API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg
        // Health check
        .route("/health", web::get().to(health_check))
        // Registration endpoints
        .route("/attestation/options", web::post().to(start_registration))
        .route("/attestation/result", web::post().to(finish_registration))
        // Authentication endpoints
        .route("/assertion/options", web::post().to(start_authentication))
        .route("/assertion/result", web::post().to(finish_authentication));
}