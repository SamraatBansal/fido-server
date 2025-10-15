//! API routes configuration

use actix_web::web;
use crate::controllers::{registration, authentication};

/// Configure all API routes
pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("")
            // Registration endpoints
            .route("/attestation/options", web::post().to(registration::attestation_options))
            .route("/attestation/result", web::post().to(registration::attestation_result))
            // Authentication endpoints
            .route("/assertion/options", web::post().to(authentication::assertion_options))
            .route("/assertion/result", web::post().to(authentication::assertion_result))
    );
}