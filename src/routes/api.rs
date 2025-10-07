//! API routes configuration

use actix_web::web;
use crate::controllers::{register_start, register_finish, authenticate_start, authenticate_finish};
use crate::controllers::health::HealthController;
use crate::services::{WebAuthnService, ChallengeService, UserService, CredentialService};
use crate::services::challenge::InMemoryChallengeStore;
use crate::services::user::InMemoryUserRepository;
use crate::services::credential::InMemoryCredentialRepository;
use std::sync::Arc;

/// Configure all API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    // Create shared services
    let challenge_service = ChallengeService::new(InMemoryChallengeStore::new());
    let user_service = UserService::new(InMemoryUserRepository::new());
    let credential_service = CredentialService::new(InMemoryCredentialRepository::new());
    
    let webauthn_service = Arc::new(WebAuthnService::new(
        challenge_service,
        user_service,
        credential_service,
        "localhost".to_string(),
        "Test RP".to_string(),
        "https://localhost".to_string(),
    ));

    cfg.service(
        web::scope("/api/v1")
            .app_data(web::Data::new(webauthn_service.clone()))
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