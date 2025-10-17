//! API routes configuration

use actix_web::web;
use crate::controllers::webauthn_controller::*;
use std::sync::Arc;
use crate::services::webauthn_service::WebAuthnService;

/// Configure all API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    // Initialize WebAuthn service
    let webauthn_service = Arc::new(WebAuthnService::new(
        "Example Corporation".to_string(),
        "localhost".to_string(),
        "http://localhost:8080".to_string(),
    ));
    
    let controller = Arc::new(WebAuthnController::new(webauthn_service));

    cfg.app_data(web::Data::new(controller))
        // Registration endpoints
        .service(registration_challenge)
        .service(registration_result)
        // Authentication endpoints  
        .service(authentication_challenge)
        .service(authentication_result);
}