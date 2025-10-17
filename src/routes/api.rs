//! API routes configuration

use actix_web::web;
use crate::controllers::{attestation_options, attestation_result, assertion_options, assertion_result};
use crate::services::WebAuthnService;

/// Configure all API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api")
            .app_data(web::Data::new(WebAuthnService::new(
                "Example Corporation",
                "example.com", 
                "http://localhost:3000"
            ).unwrap()))
            .route("/attestation/options", web::post().to(attestation_options))
            .route("/attestation/result", web::post().to(attestation_result))
            .route("/assertion/options", web::post().to(assertion_options))
            .route("/assertion/result", web::post().to(assertion_result))
    );
}