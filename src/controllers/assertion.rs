//! Assertion controller for handling credential authentication

use crate::error::{AppError, Result};
use crate::models::dto::{
    ServerPublicKeyCredentialGetOptionsRequest, ServerPublicKeyCredentialGetOptionsResponse,
    ServerPublicKeyCredential, ServerResponse,
};
use crate::services::WebAuthnService;
use actix_web::{web, HttpRequest, HttpResponse};
use std::sync::Arc;

pub struct AssertionController {
    webauthn_service: Arc<dyn WebAuthnService>,
}

impl AssertionController {
    pub fn new(webauthn_service: Arc<dyn WebAuthnService>) -> Self {
        Self { webauthn_service }
    }

    /// Generate assertion options for credential get
    pub async fn options(
        req: HttpRequest,
        webauthn_service: web::Data<Arc<dyn WebAuthnService>>,
        request: web::Json<ServerPublicKeyCredentialGetOptionsRequest>,
    ) -> Result<HttpResponse> {
        // Validate origin
        validate_origin(&req)?;

        // Generate assertion options
        let response = webauthn_service
            .generate_assertion_options(request.into_inner())
            .await?;

        Ok(HttpResponse::Ok().json(response))
    }

    /// Verify assertion result
    pub async fn result(
        req: HttpRequest,
        webauthn_service: web::Data<Arc<dyn WebAuthnService>>,
        credential: web::Json<ServerPublicKeyCredential>,
    ) -> Result<HttpResponse> {
        // Validate origin
        validate_origin(&req)?;

        // Verify assertion
        let response = webauthn_service
            .verify_assertion(credential.into_inner())
            .await?;

        Ok(HttpResponse::Ok().json(response))
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