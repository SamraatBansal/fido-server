//! API routes configuration

use actix_web::web;
use crate::controllers::{WebAuthnController, attestation_options_handler, attestation_result_handler, assertion_options_handler, assertion_result_handler};
use crate::services::WebAuthnService;

/// Configure all API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    // Initialize WebAuthn service
    let webauthn_service = WebAuthnService::new(
        "Example Corporation".to_string(),
        "localhost".to_string(),
        "http://localhost:3000".to_string(),
    );
    
    let webauthn_controller = WebAuthnController::new(webauthn_service);

    cfg.app_data(web::Data::new(webauthn_controller))
        .service(
            web::scope("/attestation")
                .route("/options", web::post().to(attestation_options_handler))
                .route("/result", web::post().to(attestation_result_handler))
        )
        .service(
            web::scope("/assertion")
                .route("/options", web::post().to(assertion_options_handler))
                .route("/result", web::post().to(assertion_result_handler))
        );
}