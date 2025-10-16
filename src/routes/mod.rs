//! API routes configuration

use actix_web::{web, Scope};
use std::sync::Arc;

use crate::controllers::{attestation_options, attestation_result, assertion_options, assertion_result};
use crate::services::WebAuthnService;

/// Configure WebAuthn API routes
pub fn configure_webauthn_routes(
    webauthn_service: Arc<dyn WebAuthnService>,
) -> Scope {
    web::scope("/api")
        .app_data(web::Data::new(webauthn_service))
        .route("/attestation/options", web::post().to(attestation_options))
        .route("/attestation/result", web::post().to(attestation_result))
        .route("/assertion/options", web::post().to(assertion_options))
        .route("/assertion/result", web::post().to(assertion_result))
}

/// Configure WebAuthn API routes
pub fn configure_webauthn_routes(
    webauthn_service: Arc<dyn WebAuthnService>,
) -> Scope {
    web::scope("")
        .app_data(web::Data::new(webauthn_service))
        .route("/attestation/options", web::post().to(attestation_options))
        .route("/attestation/result", web::post().to(attestation_result))
        .route("/assertion/options", web::post().to(assertion_options))
        .route("/assertion/result", web::post().to(assertion_result))
}

/// Configure all application routes
pub fn configure_routes(
    webauthn_service: Arc<dyn WebAuthnService>,
) -> Scope {
    configure_webauthn_routes(webauthn_service)
}