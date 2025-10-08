//! API routes configuration

use actix_web::web;

use crate::controllers::WebAuthnController;

/// Configure all API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/v1")
            .service(
                web::scope("/webauthn")
                    .route("/attestation/options", web::post().to(WebAuthnController::start_registration))
                    .route("/attestation/result", web::post().to(WebAuthnController::finish_registration))
                    .route("/assertion/options", web::post().to(WebAuthnController::start_authentication))
                    .route("/assertion/result", web::post().to(WebAuthnController::finish_authentication))
            )
    );
}