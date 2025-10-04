//! Health check routes

use actix_web::{web, Scope};

use crate::controllers::health;

/// Configure health check routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/health")
            .route("", web::get().to(health::health_check))
            .route("/ready", web::get().to(health::readiness_check))
            .route("/live", web::get().to(health::liveness_check))
    );
}