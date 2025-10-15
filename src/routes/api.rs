//! API routes configuration

use actix_web::web;
use super::webauthn;

/// Configure all API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api")
            .route("/attestation/options", web::post().to(webauthn::attestation_options))
            .route("/attestation/result", web::post().to(webauthn::attestation_result))
            .route("/assertion/options", web::post().to(webauthn::assertion_options))
            .route("/assertion/result", web::post().to(webauthn::assertion_result))
    );
}