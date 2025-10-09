//! API routes configuration

use actix_web::web;
use crate::controllers;

/// Configure all API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/v1")
            .route("/attestation/options", web::post().to(controllers::attestation_options))
            .route("/attestation/result", web::post().to(controllers::attestation_result))
            .route("/assertion/options", web::post().to(controllers::assertion_options))
            .route("/assertion/result", web::post().to(controllers::assertion_result))
    );
}