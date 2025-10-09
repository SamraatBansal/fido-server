//! API routes configuration

use actix_web::web;
use crate::controllers;
use crate::services::{WebAuthnService, UserService};

/// Configure all API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    // Create services
    let webauthn_service = WebAuthnService::new("localhost", "FIDO Server", "http://localhost:8080")
        .expect("Failed to create WebAuthn service");
    let user_service = UserService::new();

    cfg.service(
        web::scope("")
            .app_data(web::Data::new(webauthn_service))
            .app_data(web::Data::new(user_service))
            .route("/attestation/options", web::post().to(controllers::attestation::attestation_options))
            .route("/attestation/result", web::post().to(controllers::attestation::attestation_result))
            .route("/assertion/options", web::post().to(controllers::assertion::assertion_options))
            .route("/assertion/result", web::post().to(controllers::assertion::assertion_result))
    );
}