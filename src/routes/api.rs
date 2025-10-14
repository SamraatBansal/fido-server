//! API routes configuration

use actix_web::web;
use crate::controllers::{attestation, assertion, health};

/// Configure all API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg
        // Health check endpoint
        .route("/health", web::get().to(health::health_check))
        
        // Registration (Attestation) endpoints
        .route("/attestation/options", web::post().to(attestation::attestation_options))
        .route("/attestation/result", web::post().to(attestation::attestation_result))
        
        // Authentication (Assertion) endpoints  
        .route("/assertion/options", web::post().to(assertion::assertion_options))
        .route("/assertion/result", web::post().to(assertion::assertion_result));
}