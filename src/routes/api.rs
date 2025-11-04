//! API routes configuration

use actix_web::web;
use crate::controllers::{begin_registration, finish_registration, begin_authentication, finish_authentication};

/// Configure all API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/webauthn")
            .route("/attestation/options", web::post().to(begin_registration))
            .route("/attestation/result", web::post().to(finish_registration))
            .route("/assertion/options", web::post().to(begin_authentication))
            .route("/assertion/result", web::post().to(finish_authentication))
    );
}