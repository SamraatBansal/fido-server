//! API routes configuration

use actix_web::web;
use crate::controllers::webauthn::*;
use crate::services::{WebAuthnService, WebAuthnConfig};
use std::sync::Arc;

/// Configure all API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    // Initialize WebAuthn service
    let webauthn_config = WebAuthnConfig::default();
    let webauthn_service = Arc::new(
        WebAuthnService::new(webauthn_config)
            .expect("Failed to initialize WebAuthn service")
    );

    cfg.app_data(web::Data::new(webauthn_service))
        .service(
            web::scope("/attestation")
                .route("/options", web::post().to(registration_challenge_handler))
                .route("/result", web::post().to(registration_verification_handler))
        )
        .service(
            web::scope("/assertion")
                .route("/options", web::post().to(authentication_challenge_handler))
                .route("/result", web::post().to(authentication_verification_handler))
        );
}