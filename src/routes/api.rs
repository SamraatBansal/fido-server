//! API routes configuration

use actix_web::{web, middleware::ErrorHandlers, http::StatusCode};
use crate::controllers::{registration, authentication};

/// Configure all API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.app_data(web::JsonConfig::default().error_handler(|err, _req| {
        let error_msg = err.to_string();
        actix_web::error::InternalError::from_response(
            err,
            actix_web::HttpResponse::BadRequest().json(serde_json::json!({
                "status": "failed",
                "errorMessage": format!("Invalid JSON: {}", error_msg)
            }))
        ).into()
    }))
    .service(
        web::scope("")
            // Registration endpoints
            .route("/attestation/options", web::post().to(registration::registration_challenge))
            .route("/attestation/result", web::post().to(registration::registration_verification))
            // Authentication endpoints
            .route("/assertion/options", web::post().to(authentication::authentication_challenge))
            .route("/assertion/result", web::post().to(authentication::authentication_verification))
    );
}