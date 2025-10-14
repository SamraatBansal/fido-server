//! API routes configuration

use actix_web::web;
use crate::controllers::{registration, authentication};

/// Configure all API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("")
            // Registration endpoints
            .route("/attestation/options", web::post().to(registration::registration_challenge))
            .route("/attestation/result", web::post().to(registration::registration_verification))
            // Authentication endpoints
            .route("/assertion/options", web::post().to(authentication::authentication_challenge))
            .route("/assertion/result", web::post().to(authentication::authentication_verification))
    );
}