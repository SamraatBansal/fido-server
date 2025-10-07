//! API routes configuration

use actix_web::web;
use crate::controllers::{register_start, register_finish, authenticate_start, authenticate_finish};
use crate::controllers::health::HealthController;

/// Configure all API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/v1")
            .route("/register/start", web::post().to(register_start))
            .route("/register/finish", web::post().to(register_finish))
            .route("/authenticate/start", web::post().to(authenticate_start))
            .route("/authenticate/finish", web::post().to(authenticate_finish))
    )
    .route("/health", web::get().to(HealthController::health));
}