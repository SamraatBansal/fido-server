//! Registration controller

use actix_web::{web, HttpResponse, Result};
use crate::error::AppError;
use crate::services::{WebAuthnService, ChallengeService, UserService, CredentialService};
use crate::services::challenge::InMemoryChallengeStore;
use crate::services::user::InMemoryUserRepository;
use crate::services::credential::InMemoryCredentialRepository;
use crate::schema::registration::{RegistrationStartRequest, RegistrationFinishRequest};
use base64::Engine;

/// Registration controller
pub struct RegistrationController {
    webauthn_service: WebAuthnService,
}

impl RegistrationController {
    /// Create a new registration controller
    pub fn new() -> Self {
        let challenge_service = ChallengeService::new(InMemoryChallengeStore::new());
        let user_service = UserService::new(InMemoryUserRepository::new());
        let credential_service = CredentialService::new(InMemoryCredentialRepository::new());
        
        let webauthn_service = WebAuthnService::new(
            challenge_service,
            user_service,
            credential_service,
            "localhost".to_string(),
            "Test RP".to_string(),
            "https://localhost".to_string(),
        );
        
        Self { webauthn_service }
    }

    /// Start registration endpoint
    pub async fn start_registration(
        &self,
        req: web::Json<RegistrationStartRequest>,
    ) -> Result<HttpResponse> {
        let result = self
            .webauthn_service
            .start_registration(req.username.clone(), req.display_name.clone())
            .await;

        match result {
            Ok(response) => Ok(HttpResponse::Ok().json(response)),
            Err(AppError::ValidationError(msg)) => {
                Ok(HttpResponse::BadRequest().json(serde_json::json!({
                    "error": msg,
                    "status": 400
                })))
            }
            Err(_) => {
                Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Internal server error",
                    "status": 500
                })))
            }
        }
    }

    /// Finish registration endpoint
    pub async fn finish_registration(
        &self,
        req: web::Json<RegistrationFinishRequest>,
    ) -> Result<HttpResponse> {
        // For now, we'll implement a basic version that validates the challenge
        let credential_id = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&req.credential.id)
            .unwrap_or_default();
            
        let result = self
            .webauthn_service
            .finish_registration(
                req.challenge_id.clone(),
                credential_id,
                vec![], // client_data_json placeholder
                vec![], // attestation_object placeholder
            )
            .await;

        match result {
            Ok(response) => Ok(HttpResponse::Created().json(response)),
            Err(AppError::NotFound(msg)) => {
                Ok(HttpResponse::NotFound().json(serde_json::json!({
                    "error": msg,
                    "status": 404
                })))
            }
            Err(AppError::BadRequest(msg)) => {
                Ok(HttpResponse::BadRequest().json(serde_json::json!({
                    "error": msg,
                    "status": 400
                })))
            }
            Err(_) => {
                Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Internal server error",
                    "status": 500
                })))
            }
        }
    }
}

/// Default registration start endpoint for actix-web
pub async fn register_start(req: web::Json<RegistrationStartRequest>) -> Result<HttpResponse> {
    let controller = RegistrationController::new();
    controller.start_registration(req).await
}

/// Default registration finish endpoint for actix-web
pub async fn register_finish(req: web::Json<RegistrationFinishRequest>) -> Result<HttpResponse> {
    let controller = RegistrationController::new();
    controller.finish_registration(req).await
}