//! Registration controller for FIDO2/WebAuthn

use actix_web::{web, HttpRequest, HttpResponse};
use crate::error::Result;
use crate::models::{
    ServerPublicKeyCredentialCreationOptionsRequest,
    RegistrationCompletionRequest,
};
use crate::services::WebAuthnService;

/// Registration controller
pub struct RegistrationController<S: WebAuthnService> {
    webauthn_service: S,
}

impl<S: WebAuthnService> RegistrationController<S> {
    pub fn new(webauthn_service: S) -> Self {
        Self { webauthn_service }
    }

    /// Generate registration challenge options
    pub async fn attestation_options(
        &self,
        request: web::Json<ServerPublicKeyCredentialCreationOptionsRequest>,
        _req: HttpRequest,
    ) -> Result<HttpResponse> {
        let response = self
            .webauthn_service
            .generate_registration_challenge(request.into_inner())
            .await?;

        Ok(HttpResponse::Ok().json(response))
    }

    /// Complete registration with attestation result
    pub async fn attestation_result(
        &self,
        request: web::Json<RegistrationCompletionRequest>,
        _req: HttpRequest,
    ) -> Result<HttpResponse> {
        let response = self
            .webauthn_service
            .verify_registration(request.into_inner())
            .await?;

        Ok(HttpResponse::Ok().json(response))
    }
}

/// Helper functions for Actix-web routing
pub async fn attestation_options_handler<S: WebAuthnService>(
    request: web::Json<ServerPublicKeyCredentialCreationOptionsRequest>,
    req: HttpRequest,
    controller: web::Data<RegistrationController<S>>,
) -> Result<HttpResponse> {
    controller.attestation_options(request, req).await
}

pub async fn attestation_result_handler<S: WebAuthnService>(
    request: web::Json<RegistrationCompletionRequest>,
    req: HttpRequest,
    controller: web::Data<RegistrationController<S>>,
) -> Result<HttpResponse> {
    controller.attestation_result(request, req).await
}