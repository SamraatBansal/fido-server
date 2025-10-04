//! API routes configuration

use actix_web::web;

/// Configure all API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/v1")
            // Health check endpoints
            .route("/health", web::get().to(crate::controllers::health::health_check))
            .route("/health/simple", web::get().to(crate::controllers::health::simple_health_check))
            .route("/ready", web::get().to(crate::controllers::health::readiness_check))
            .route("/live", web::get().to(crate::controllers::health::liveness_check))
            
            // Registration endpoints
            .route("/register/start", web::post().to(crate::controllers::registration::start_registration))
            .route("/register/finish", web::post().to(crate::controllers::registration::finish_registration))
            
            // Authentication endpoints
            .route("/auth/start", web::post().to(crate::controllers::auth::start_authentication))
            .route("/auth/finish", web::post().to(crate::controllers::auth::finish_authentication))
            .route("/auth/validate", web::post().to(crate::controllers::auth::validate_session))
            .route("/auth/logout", web::post().to(crate::controllers::auth::logout))
            .route("/auth/me", web::get().to(crate::controllers::auth::get_current_user))
    );
}