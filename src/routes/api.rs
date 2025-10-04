//! API routes

use actix_web::{web, Scope};
use crate::controllers::{health_check, start_authentication, finish_authentication, start_registration, finish_registration};

/// Configure API routes
pub fn configure_api_routes() -> Scope {
    web::scope("/api/v1")
        // Health check
        .route("/health", web::get().to(health_check))
        
        // Authentication flow
        .route("/auth/start", web::post().to(start_authentication))
        .route("/auth/finish", web::post().to(finish_authentication))
        
        // Registration flow
        .route("/register/start", web::post().to(start_registration))
        .route("/register/finish", web::post().to(finish_registration))
}