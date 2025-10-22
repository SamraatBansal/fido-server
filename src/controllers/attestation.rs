//! Attestation controller for handling credential creation

use crate::error::{AppError, Result};
use crate::models::dto::{
    ServerPublicKeyCredentialCreationOptionsRequest,
    ServerPublicKeyCredential,
    ServerResponse,
};
use crate::services::WebAuthnService;
use actix_web::{web, HttpRequest, HttpResponse, ResponseError};
use std::sync::Arc;
use uuid::Uuid;

/// Controller for handling attestation operations
pub struct AttestationController {
    _webauthn_service: Arc<dyn WebAuthnService>,
}

impl AttestationController {
    /// Create a new attestation controller
    pub fn new(webauthn_service: Arc<dyn WebAuthnService>) -> Self {
        Self { _webauthn_service: webauthn_service }
    }

    /// Generate attestation options for credential creation
    pub async fn options(
        req: HttpRequest,
        webauthn_service: web::Data<Arc<dyn WebAuthnService>>,
        body: web::Bytes,
    ) -> Result<HttpResponse> {
        // Validate origin
        validate_origin(&req)?;

        // Parse JSON manually to handle errors properly
        let request: ServerPublicKeyCredentialCreationOptionsRequest = match serde_json::from_slice(&body) {
            Ok(req) => req,
            Err(e) => {
                let error_response = ServerResponse::error(format!("Invalid request format: {}", e));
                return Ok(HttpResponse::BadRequest().json(error_response));
            }
        };

        // Generate attestation options
        let response = webauthn_service
            .generate_attestation_options(request)
            .await?;

        Ok(HttpResponse::Ok().json(response))
    }

    /// Verify attestation result
    pub async fn result(
        req: HttpRequest,
        webauthn_service: web::Data<Arc<dyn WebAuthnService>>,
        credential: web::Json<ServerPublicKeyCredential>,
    ) -> Result<HttpResponse> {
        // Validate origin
        validate_origin(&req)?;

        // Verify attestation
        match webauthn_service.verify_attestation(credential.into_inner()).await {
            Ok(response) => Ok(HttpResponse::Ok().json(response)),
            Err(e) => {
                // Return the error with proper status code
                let status_code = e.status_code();
                let session_id = Uuid::new_v4().to_string(); // Generate session ID for error response
                let error_response = ServerResponse::error_with_session(e.to_string(), session_id);
                Ok(HttpResponse::build(status_code).json(error_response))
            }
        }
    }
}

/// Validate request origin for security
fn validate_origin(req: &HttpRequest) -> Result<()> {
    // In a real implementation, this would validate the Origin header
    // against allowed origins to prevent CSRF attacks
    
    if let Some(origin) = req.headers().get("Origin") {
        let origin_str = origin.to_str().map_err(|_| {
            AppError::BadRequest("Invalid Origin header".to_string())
        })?;
        
        // For now, allow localhost origins for testing
        if !origin_str.starts_with("http://localhost") && !origin_str.starts_with("https://localhost") {
            return Err(AppError::BadRequest(format!("Origin not allowed: {}", origin_str)));
        }
    }

    Ok(())
}