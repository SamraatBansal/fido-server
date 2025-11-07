//! API routes configuration

use actix_web::web;
use crate::controllers::{authentication, health, registration};

/// Configure all API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg
        // Health check endpoint
        .route("/health", web::get().to(health::health_check))
        
        // Registration endpoints matching FIDO conformance API spec
        .route("/attestation/options", web::post().to(registration::begin_registration))
        .route("/attestation/result", web::post().to(registration::complete_registration))
        
        // Authentication endpoints matching FIDO conformance API spec
        .route("/assertion/options", web::post().to(authentication::begin_authentication))
        .route("/assertion/result", web::post().to(authentication::complete_authentication));
}