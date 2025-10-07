//! Authentication controller

use actix_web::{web, HttpResponse, Result};
use crate::error::{AppError, Result as AppResult};
use crate::services::{WebAuthnService, ChallengeService, UserService, CredentialService};
use crate::services::challenge::InMemoryChallengeStore;
use crate::services::user::InMemoryUserRepository;
use crate::services::credential::InMemoryCredentialRepository;
use crate::schema::authentication::{AuthenticationStartRequest, AuthenticationFinishRequest};
use serde_json::Value;

/// Authentication controller
pub struct AuthenticationController {
    webauthn_service: WebAuthnService,
}

impl AuthenticationController {
    /// Create a new authentication controller
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

    /// Start authentication endpoint
    pub async fn start_authentication(
        &self,
        req: web::Json<AuthenticationStartRequest>,
    ) -> Result<HttpResponse> {
        let result = self
            .webauthn_service
            .start_authentication(req.username.clone())
            .await;

        match result {
            Ok(response) => Ok(HttpResponse::Ok().json(response)),
            Err(AppError::NotFound(msg)) => {
                Ok(HttpResponse::NotFound().json(serde_json::json!({
                    "error": msg,
                    "status": 404
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

    /// Finish authentication endpoint
    pub async fn finish_authentication(
        &self,
        req: web::Json<AuthenticationFinishRequest>,
    ) -> Result<HttpResponse> {
        // For now, we'll implement a basic version that validates the challenge
        let credential_id = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&req.credential.id)
            .unwrap_or_default();
            
        let user_handle = req.credential.response.user_handle
            .as_ref()
            .and_then(|uh| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(uh).ok());
            
        let result = self
            .webauthn_service
            .finish_authentication(
                req.challenge_id.clone(),
                credential_id,
                vec![], // client_data_json placeholder
                vec![], // authenticator_data placeholder
                vec![], // signature placeholder
                user_handle,
            )
            .await;

        match result {
            Ok(response) => Ok(HttpResponse::Ok().json(response)),
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

/// Default authentication start endpoint for actix-web
pub async fn authenticate_start(req: web::Json<AuthenticationStartRequest>) -> Result<HttpResponse> {
    let controller = AuthenticationController::new();
    controller.start_authentication(req).await
}

/// Default authentication finish endpoint for actix-web
pub async fn authenticate_finish(req: web::Json<AuthenticationFinishRequest>) -> Result<HttpResponse> {
    let controller = AuthenticationController::new();
    controller.finish_authentication(req).await
}