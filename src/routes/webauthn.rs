use actix_web::{web, Scope};

use crate::controllers::{
    authentication::AuthenticationController, registration::WebAuthnController,
};

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/webauthn")
            .route(
                "/register/start",
                web::post().to(WebAuthnController::start_attestation),
            )
            .route(
                "/register/finish",
                web::post().to(WebAuthnController::finish_attestation),
            )
            .route(
                "/login/start",
                web::post().to(AuthenticationController::start_assertion),
            )
            .route(
                "/login/finish",
                web::post().to(AuthenticationController::finish_assertion),
            ),
    );
}
