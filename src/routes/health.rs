//! Health check routes

use actix_web::{web, Scope};
use crate::controllers::health_check;

/// Configure health routes
pub fn configure_health_routes() -> Scope {
    web::scope("/health")
        .route("", web::get().to(health_check))
}