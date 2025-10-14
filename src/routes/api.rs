//! API routes configuration

use actix_web::web;
use crate::controllers::{registration, authentication, health};

/// Configure all API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/v1")
            .route("/health", web::get().to(health::health_check))
            .service(
                web::scope("/webauthn")
                    .route("/registration/attestation-options", web::post().to(registration::attestation_options))
                    .route("/registration/attestation-result", web::post().to(registration::attestation_result))
                    .route("/authentication/assertion-options", web::post().to(authentication::assertion_options))
                    .route("/authentication/assertion-result", web::post().to(authentication::assertion_result))
            )
    )
    // Legacy routes for backward compatibility
    .service(
        web::scope("")
            .route("/attestation/options", web::post().to(registration::attestation_options))
            .route("/attestation/result", web::post().to(registration::attestation_result))
            .route("/assertion/options", web::post().to(authentication::assertion_options))
            .route("/assertion/result", web::post().to(authentication::assertion_result))
    );
}