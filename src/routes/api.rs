//! API routes configuration

use actix_web::{web, Scope};
use crate::controllers::{
    attestation_options_handler, attestation_result_handler,
    assertion_options_handler, assertion_result_handler,
    RegistrationController, AuthenticationController,
};
use crate::services::DefaultWebAuthnService;

/// Configure API routes
pub fn configure_routes() -> Scope {
    let webauthn_service = web::Data::new(DefaultWebAuthnService::new());
    let registration_controller = web::Data::new(RegistrationController::new(DefaultWebAuthnService::new()));
    let authentication_controller = web::Data::new(AuthenticationController::new(DefaultWebAuthnService::new()));

    web::scope("/api")
        .app_data(registration_controller)
        .app_data(authentication_controller)
        .app_data(webauthn_service)
        .service(
            web::scope("/v1")
                // Registration endpoints
                .route("/attestation/options", web::post().to(attestation_options_handler::<DefaultWebAuthnService>))
                .route("/attestation/result", web::post().to(attestation_result_handler::<DefaultWebAuthnService>))
                // Authentication endpoints
                .route("/assertion/options", web::post().to(assertion_options_handler::<DefaultWebAuthnService>))
                .route("/assertion/result", web::post().to(assertion_result_handler::<DefaultWebAuthnService>))
        )
}