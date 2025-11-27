//! API routes configuration

use crate::controllers::health;
use actix_web::web;

/// Configure all API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg
        // Health check endpoint
        .route("/health", web::get().to(health::health_check));
}