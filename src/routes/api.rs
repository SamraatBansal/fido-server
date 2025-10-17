//! API routes configuration

use actix_web::web;
use crate::controllers::{
    WebAuthnController, attestation_options_handler, attestation_result_handler,
    assertion_options_handler, assertion_result_handler
};
use crate::infrastructure::repositories::{MockUserRepository, MockCredentialRepository, MockChallengeRepository};
use crate::domain::services::{WebAuthnServiceImpl, CryptoServiceImpl};
use std::sync::Arc;

/// Configure all API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    // Initialize mock repositories
    let user_repo = Arc::new(MockUserRepository::new());
    let credential_repo = Arc::new(MockCredentialRepository::new());
    let challenge_repo = Arc::new(MockChallengeRepository::new());
    
    // Initialize services
    let _crypto_service = Arc::new(CryptoServiceImpl::new());
    let webauthn_service = Arc::new(WebAuthnServiceImpl::new(
        user_repo.clone(),
        credential_repo.clone(),
        challenge_repo.clone(),
        "Example Corporation".to_string(),
        "localhost".to_string(),
        "http://localhost:3000".to_string(),
    ));
    
    // Initialize controller
    let webauthn_controller = web::Data::new(WebAuthnController::new(webauthn_service));

    cfg.service(
        web::scope("/attestation")
            .route("/options", web::post().to(attestation_options_handler))
            .route("/result", web::post().to(attestation_result_handler))
    )
    .service(
        web::scope("/assertion")
            .route("/options", web::post().to(assertion_options_handler))
            .route("/result", web::post().to(assertion_result_handler))
    )
    .app_data(webauthn_controller);
}