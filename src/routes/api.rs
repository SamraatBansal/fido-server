//! API routes configuration

use actix_web::web;
use crate::controllers::health;

/// Configure all API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("")
            .route("/health", web::get().to(health::health_check))
    );
}