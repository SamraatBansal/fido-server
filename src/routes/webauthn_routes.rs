//! WebAuthn routes

use actix_web::web;
use crate::controllers::{attestation_options, attestation_result, assertion_options, assertion_result};

/// Configure WebAuthn routes
pub fn configure_webauthn_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/webauthn")
            .route("/register/challenge", web::post().to(attestation_options))
            .route("/register/verify", web::post().to(attestation_result))
            .route("/authenticate/challenge", web::post().to(assertion_options))
            .route("/authenticate/verify", web::post().to(assertion_result))
    );
}

/// Configure legacy routes for backward compatibility with the specification
pub fn configure_legacy_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("")
            .route("/attestation/options", web::post().to(attestation_options))
            .route("/attestation/result", web::post().to(attestation_result))
            .route("/assertion/options", web::post().to(assertion_options))
            .route("/assertion/result", web::post().to(assertion_result))
    );
}