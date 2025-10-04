//! API v1 routes

use actix_web::{web, Scope};

use crate::controllers::{registration, authentication, credentials};

/// Configure v1 API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/v1")
            // Registration endpoints
            .route("/register/start", web::post().to(registration::start_registration))
            .route("/register/finish", web::post().to(registration::finish_registration))
            
            // Authentication endpoints
            .route("/authenticate/start", web::post().to(authentication::start_authentication))
            .route("/authenticate/finish", web::post().to(authentication::finish_authentication))
            
            // Credential management endpoints (require authentication)
            .service(
                web::scope("/credentials")
                    .route("", web::get().to(credentials::list_credentials))
                    .route("/{credential_id}", web::delete().to(credentials::delete_credential))
            )
    );
}