//! API routes configuration

use actix_web::web;
use crate::controllers::{begin_attestation, finish_attestation, begin_assertion, finish_assertion};

/// Configure all API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/attestation")
            .route("/options", web::post().to(begin_attestation))
            .route("/result", web::post().to(finish_attestation))
    )
    .service(
        web::scope("/assertion")
            .route("/options", web::post().to(begin_assertion))
            .route("/result", web::post().to(finish_assertion))
    );
}