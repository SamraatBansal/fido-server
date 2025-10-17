//! WebAuthn controllers

use actix_web::{web, HttpRequest, HttpResponse};
use crate::error::{AppError, Result};
use crate::services::WebAuthnService;
use crate::types::*;

/// WebAuthn controller with dependency injection
pub struct WebAuthnController {
    service: WebAuthnService,
}

impl WebAuthnController {
    pub fn new(service: WebAuthnService) -> Self {
        Self { service }
    }

    /// Handle attestation options request
    pub async fn attestation_options(
        &self,
        _req: HttpRequest,
        payload: web::Json<ServerPublicKeyCredentialCreationOptionsRequest>,
    ) -> Result<HttpResponse> {
        let response = self.service.generate_attestation_options(payload.into_inner()).await?;
        Ok(HttpResponse::Ok().json(response))
    }

    /// Handle attestation result verification
    pub async fn attestation_result(
        &self,
        _req: HttpRequest,
        payload: web::Json<ServerPublicKeyCredentialWithResponse>,
    ) -> Result<HttpResponse> {
        let response = self.service.verify_attestation_result(payload.into_inner()).await?;
        Ok(HttpResponse::Ok().json(response))
    }

    /// Handle assertion options request
    pub async fn assertion_options(
        &self,
        _req: HttpRequest,
        payload: web::Json<ServerPublicKeyCredentialGetOptionsRequest>,
    ) -> Result<HttpResponse> {
        let response = self.service.generate_assertion_options(payload.into_inner()).await?;
        Ok(HttpResponse::Ok().json(response))
    }

    /// Handle assertion result verification
    pub async fn assertion_result(
        &self,
        _req: HttpRequest,
        payload: web::Json<ServerPublicKeyCredentialWithResponse>,
    ) -> Result<HttpResponse> {
        let response = self.service.verify_assertion_result(payload.into_inner()).await?;
        Ok(HttpResponse::Ok().json(response))
    }
}

// Helper functions for actix-web routing
pub async fn attestation_options_handler(
    req: HttpRequest,
    payload: web::Json<ServerPublicKeyCredentialCreationOptionsRequest>,
    controller: web::Data<WebAuthnController>,
) -> Result<HttpResponse> {
    controller.attestation_options(req, payload).await
}

pub async fn attestation_result_handler(
    req: HttpRequest,
    payload: web::Json<ServerPublicKeyCredentialWithResponse>,
    controller: web::Data<WebAuthnController>,
) -> Result<HttpResponse> {
    controller.attestation_result(req, payload).await
}

pub async fn assertion_options_handler(
    req: HttpRequest,
    payload: web::Json<ServerPublicKeyCredentialGetOptionsRequest>,
    controller: web::Data<WebAuthnController>,
) -> Result<HttpResponse> {
    controller.assertion_options(req, payload).await
}

pub async fn assertion_result_handler(
    req: HttpRequest,
    payload: web::Json<ServerPublicKeyCredentialWithResponse>,
    controller: web::Data<WebAuthnController>,
) -> Result<HttpResponse> {
    controller.assertion_result(req, payload).await
}