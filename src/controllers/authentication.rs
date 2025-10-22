//! Authentication controller for FIDO2/WebAuthn

use actix_web::{web, HttpRequest, HttpResponse};
use crate::error::{AppError, Result};
use crate::models::{
    ServerPublicKeyCredentialGetOptionsRequest,
    ServerPublicKeyCredentialGetOptionsResponse,
    AuthenticationCompletionRequest,
    AuthenticationCompletionResponse,
};
use crate::services::WebAuthnService;

/// Authentication controller
pub struct AuthenticationController<S: WebAuthnService> {
    webauthn_service: S,
}

impl<S: WebAuthnService> AuthenticationController<S> {
    pub fn new(webauthn_service: S) -> Self {
        Self { webauthn_service }
    }

    /// Generate authentication challenge options
    pub async fn assertion_options(
        &self,
        request: web::Json<ServerPublicKeyCredentialGetOptionsRequest>,
        _req: HttpRequest,
    ) -> Result<HttpResponse> {
        let response = self
            .webauthn_service
            .generate_authentication_challenge(request.into_inner())
            .await?;

        Ok(HttpResponse::Ok().json(response))
    }

    /// Complete authentication with assertion result
    pub async fn assertion_result(
        &self,
        request: web::Json<AuthenticationCompletionRequest>,
        _req: HttpRequest,
    ) -> Result<HttpResponse> {
        let response = self
            .webauthn_service
            .verify_authentication(request.into_inner())
            .await?;

        Ok(HttpResponse::Ok().json(response))
    }
}

/// Helper functions for Actix-web routing
pub async fn assertion_options_handler<S: WebAuthnService>(
    request: web::Json<ServerPublicKeyCredentialGetOptionsRequest>,
    req: HttpRequest,
    controller: web::Data<AuthenticationController<S>>,
) -> Result<HttpResponse> {
    controller.assertion_options(request, req).await
}

pub async fn assertion_result_handler<S: WebAuthnService>(
    request: web::Json<AuthenticationCompletionRequest>,
    req: HttpRequest,
    controller: web::Data<AuthenticationController<S>>,
) -> Result<HttpResponse> {
    controller.assertion_result(request, req).await
}