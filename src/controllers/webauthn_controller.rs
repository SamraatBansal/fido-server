//! WebAuthn controller for handling FIDO2 endpoints

use actix_web::{web, HttpRequest, HttpResponse};
use crate::domain::models::*;
use crate::domain::services::WebAuthnService;
use crate::error::{AppError, Result};
use std::sync::Arc;

/// Controller for WebAuthn operations
pub struct WebAuthnController {
    webauthn_service: Arc<dyn WebAuthnService>,
}

impl WebAuthnController {
    pub fn new(webauthn_service: Arc<dyn WebAuthnService>) -> Self {
        Self { webauthn_service }
    }

    /// Generate attestation options for credential creation
    pub async fn attestation_options(
        &self,
        request: web::Json<ServerPublicKeyCredentialCreationOptionsRequest>,
    ) -> Result<HttpResponse> {
        let response = self.webauthn_service
            .generate_registration_options(request.into_inner())
            .await?;

        Ok(HttpResponse::Ok().json(response))
    }

    /// Verify attestation result
    pub async fn attestation_result(
        &self,
        request: web::Json<ServerPublicKeyCredential>,
    ) -> Result<HttpResponse> {
        let response = self.webauthn_service
            .verify_registration(request.into_inner())
            .await?;

        Ok(HttpResponse::Ok().json(response))
    }

    /// Generate assertion options for authentication
    pub async fn assertion_options(
        &self,
        request: web::Json<ServerPublicKeyCredentialGetOptionsRequest>,
    ) -> Result<HttpResponse> {
        let response = self.webauthn_service
            .generate_authentication_options(request.into_inner())
            .await?;

        Ok(HttpResponse::Ok().json(response))
    }

    /// Verify assertion result
    pub async fn assertion_result(
        &self,
        request: web::Json<ServerPublicKeyCredential>,
    ) -> Result<HttpResponse> {
        let response = self.webauthn_service
            .verify_authentication(request.into_inner())
            .await?;

        Ok(HttpResponse::Ok().json(response))
    }
}

// Dependency injection functions for Actix-web
pub async fn attestation_options_handler(
    request: web::Json<ServerPublicKeyCredentialCreationOptionsRequest>,
    controller: web::Data<WebAuthnController>,
) -> Result<HttpResponse> {
    controller.attestation_options(request).await
}

pub async fn attestation_result_handler(
    request: web::Json<ServerPublicKeyCredential>,
    controller: web::Data<WebAuthnController>,
) -> Result<HttpResponse> {
    controller.attestation_result(request).await
}

pub async fn assertion_options_handler(
    request: web::Json<ServerPublicKeyCredentialGetOptionsRequest>,
    controller: web::Data<WebAuthnController>,
) -> Result<HttpResponse> {
    controller.assertion_options(request).await
}

pub async fn assertion_result_handler(
    request: web::Json<ServerPublicKeyCredential>,
    controller: web::Data<WebAuthnController>,
) -> Result<HttpResponse> {
    controller.assertion_result(request).await
}