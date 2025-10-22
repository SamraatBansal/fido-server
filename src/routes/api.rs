//! API routes configuration

use crate::controllers::{attestation, assertion, health};
use crate::services::WebAuthnService;
use actix_web::web;
use std::sync::Arc;

/// Configure API routes
pub fn configure_routes(cfg: &mut web::ServiceConfig, webauthn_service: Arc<dyn WebAuthnService>) {
    cfg.service(
        web::scope("/api")
            .app_data(web::Data::new(webauthn_service))
            .route("/health", web::get().to(health::health_check))
            .service(
                web::scope("/attestation")
                    .route("/options", web::post().to(attestation::AttestationController::options))
                    .route("/result", web::post().to(attestation::AttestationController::result)),
            )
            .service(
                web::scope("/assertion")
                    .route("/options", web::post().to(assertion::AssertionController::options))
                    .route("/result", web::post().to(assertion::AssertionController::result)),
            ),
    );
}

/// Configure routes without /api prefix (for FIDO conformance testing)
pub fn configure_fido_routes(cfg: &mut web::ServiceConfig, webauthn_service: Arc<dyn WebAuthnService>) {
    cfg.service(
        web::scope("")
            .app_data(web::Data::new(webauthn_service))
            .route("/health", web::get().to(health::health_check))
            .service(
                web::scope("/attestation")
                    .route("/options", web::post().to(attestation::AttestationController::options))
                    .route("/result", web::post().to(attestation::AttestationController::result)),
            )
            .service(
                web::scope("/assertion")
                    .route("/options", web::post().to(assertion::AssertionController::options))
                    .route("/result", web::post().to(assertion::AssertionController::result)),
            ),
    );
}