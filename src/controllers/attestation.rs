//! Attestation controller for handling credential creation

use crate::error::{AppError, Result};
use crate::models::dto::{
    ServerPublicKeyCredentialCreationOptionsRequest,
    ServerPublicKeyCredential,
};
use crate::services::WebAuthnService;
use actix_web::{web, HttpRequest, HttpResponse};
use std::sync::Arc;

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
        request: web::Json<ServerPublicKeyCredentialCreationOptionsRequest>,
    ) -> Result<HttpResponse> {
        // Validate origin
        validate_origin(&req)?;

        // Generate attestation options
        let response = webauthn_service
            .generate_attestation_options(request.into_inner())
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
                let error_response = ServerResponse {
                    status: "failed".to_string(),
                    error_message: e.to_string(),
                };
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