//! API routes configuration

use actix_web::web;
use crate::controllers::{health_check, start_registration, finish_registration, start_authentication, finish_authentication};

/// Configure all API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/v1")
            .route("/health", web::get().to(health_check))
            .service(
                web::scope("/webauthn")
                    .route("/register/start", web::post().to(start_registration))
                    .route("/register/finish", web::post().to(finish_registration))
                    .route("/authenticate/start", web::post().to(start_authentication))
                    .route("/authenticate/finish", web::post().to(finish_authentication))
            )
    );
}