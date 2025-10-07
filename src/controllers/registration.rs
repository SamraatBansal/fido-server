//! Registration controller

use actix_web::{web, HttpResponse, Result};
use crate::error::AppError;
use crate::services::WebAuthnService;
use crate::schema::registration::{RegistrationStartRequest, RegistrationFinishRequest};
use base64::Engine;
use std::sync::Arc;

/// Registration controller
pub struct RegistrationController {
    webauthn_service: Arc<WebAuthnService>,
}

impl RegistrationController {
    /// Create a new registration controller
    pub fn new(webauthn_service: Arc<WebAuthnService>) -> Self {
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
            .unwrap_or_else(|e| {
                println!("DEBUG: Failed to decode credential ID '{}': {:?}", req.credential.id, e);
                vec![]
            });
            
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
                println!("DEBUG: Registration NotFound: {}", msg);
                Ok(HttpResponse::NotFound().json(serde_json::json!({
                    "error": msg,
                    "status": 404
                })))
            }
            Err(AppError::BadRequest(msg)) => {
                println!("DEBUG: Registration BadRequest: {}", msg);
                Ok(HttpResponse::BadRequest().json(serde_json::json!({
                    "error": msg,
                    "status": 400
                })))
            }
            Err(err) => {
                println!("DEBUG: Registration Internal Error: {:?}", err);
                Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Internal server error",
                    "status": 500
                })))
            }
        }
    }
}

/// Default registration start endpoint for actix-web
pub async fn register_start(
    req: web::Json<RegistrationStartRequest>,
    webauthn_service: web::Data<Arc<WebAuthnService>>,
) -> Result<HttpResponse> {
    let controller = RegistrationController::new(webauthn_service.get_ref().clone());
    controller.start_registration(req).await
}

/// Default registration finish endpoint for actix-web
pub async fn register_finish(
    req: web::Json<RegistrationFinishRequest>,
    webauthn_service: web::Data<Arc<WebAuthnService>>,
) -> Result<HttpResponse> {
    let controller = RegistrationController::new(webauthn_service.get_ref().clone());
    controller.finish_registration(req).await
}