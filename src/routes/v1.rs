//! API v1 routes

use actix_web::{web, Scope};

/// Configure v1 API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/v1")
            .route("/health", web::get().to(health_check))
    );
}

/// Health check endpoint
async fn health_check() -> &'static str {
    "OK"
}