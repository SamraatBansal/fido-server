//! API routes configuration

use actix_web::web;
use crate::controllers;

/// Configure all API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg
        // Health check
        .service(
            web::resource("/health")
                .route(web::get().to(controllers::health_check))
        )
        // Registration endpoints
        .service(
            web::resource("/attestation/options")
                .route(web::post().to(controllers::attestation_options))
        )
        .service(
            web::resource("/attestation/result")
                .route(web::post().to(controllers::attestation_result))
        )
        // Authentication endpoints
        .service(
            web::resource("/assertion/options")
                .route(web::post().to(controllers::assertion_options))
        )
        .service(
            web::resource("/assertion/result")
                .route(web::post().to(controllers::assertion_result))
        );
}