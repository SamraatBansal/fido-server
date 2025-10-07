//! API routes configuration

use actix_web::web;
use crate::controllers::{register_start, register_finish, authenticate_start, authenticate_finish};
use crate::controllers::health::HealthController;

/// Configure all API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/v1")
            .route("/register/start", web::post().to(register_start))
            .route("/register/start", web::get().to(method_not_allowed))
            .route("/register/start", web::put().to(method_not_allowed))
            .route("/register/start", web::delete().to(method_not_allowed))
            .route("/register/finish", web::post().to(register_finish))
            .route("/register/finish", web::get().to(method_not_allowed))
            .route("/register/finish", web::put().to(method_not_allowed))
            .route("/register/finish", web::delete().to(method_not_allowed))
            .route("/authenticate/start", web::post().to(authenticate_start))
            .route("/authenticate/start", web::get().to(method_not_allowed))
            .route("/authenticate/start", web::put().to(method_not_allowed))
            .route("/authenticate/start", web::delete().to(method_not_allowed))
            .route("/authenticate/finish", web::post().to(authenticate_finish))
            .route("/authenticate/finish", web::get().to(method_not_allowed))
            .route("/authenticate/finish", web::put().to(method_not_allowed))
            .route("/authenticate/finish", web::delete().to(method_not_allowed))
    )
    .route("/health", web::get().to(HealthController::health));
}

/// Handler for unsupported HTTP methods
async fn method_not_allowed() -> actix_web::HttpResponse {
    actix_web::HttpResponse::MethodNotAllowed().json(serde_json::json!({
        "error": "Method not allowed",
        "status": 405
    }))
}