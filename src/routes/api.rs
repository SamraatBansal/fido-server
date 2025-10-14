//! API routes configuration

use actix_web::web;
use crate::controllers::registration;

/// Configure all API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/attestation")
            .route("/options", web::post().to(registration::attestation_options))
            .route("/result", web::post().to(registration::attestation_result))
    );
}