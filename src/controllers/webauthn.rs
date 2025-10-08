//! WebAuthn controller for FIDO2 endpoints

use actix_web::{web, HttpResponse, Result};
use validator::Validate;

use crate::error::AppError;
use crate::schema::webauthn::*;
use crate::services::WebAuthnService;

/// WebAuthn controller
pub struct WebAuthnController;

impl WebAuthnController {
    /// Start registration endpoint
    pub async fn start_registration(
        webauthn_service: web::Data<WebAuthnService>,
        request: web::Json<RegistrationOptionsRequest>,
    ) -> Result<HttpResponse> {
        // Validate request
        request.validate()
            .map_err(|e| AppError::ValidationError(format!("Invalid request: {}", e)))?;

        // Process registration start
        let response = webauthn_service
            .start_registration(request.into_inner())
            .await
            .map_err(|e| AppError::WebAuthnError(e.to_string()))?;

        Ok(HttpResponse::Ok().json(response))
    }

    /// Finish registration endpoint
    pub async fn finish_registration(
        webauthn_service: web::Data<WebAuthnService>,
        request: web::Json<RegisterPublicKeyCredential>,
    ) -> Result<HttpResponse> {
        // Process registration finish
        let response = webauthn_service
            .finish_registration(request.into_inner())
            .await
            .map_err(|e| AppError::WebAuthnError(e.to_string()))?;

        Ok(HttpResponse::Ok().json(response))
    }

    /// Start authentication endpoint
    pub async fn start_authentication(
        webauthn_service: web::Data<WebAuthnService>,
        request: web::Json<AuthenticationOptionsRequest>,
    ) -> Result<HttpResponse> {
        // Validate request
        request.validate()
            .map_err(|e| AppError::ValidationError(format!("Invalid request: {}", e)))?;

        // Process authentication start
        let response = webauthn_service
            .start_authentication(request.into_inner())
            .await
            .map_err(|e| AppError::WebAuthnError(e.to_string()))?;

        Ok(HttpResponse::Ok().json(response))
    }

    /// Finish authentication endpoint
    pub async fn finish_authentication(
        webauthn_service: web::Data<WebAuthnService>,
        request: web::Json<PublicKeyCredential>,
    ) -> Result<HttpResponse> {
        // Process authentication finish
        let response = webauthn_service
            .finish_authentication(request.into_inner())
            .await
            .map_err(|e| AppError::WebAuthnError(e.to_string()))?;

        Ok(HttpResponse::Ok().json(response))
    }
}