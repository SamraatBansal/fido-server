//! Controllers for handling HTTP requests

use actix_web::{web, HttpResponse, ResponseError, Result as ActixResult};

use crate::services::webauthn::*;

pub struct WebAuthnController<W> {
    webauthn_service: W,
}

impl<W> WebAuthnController<W>
where
    W: WebAuthnService + 'static,
{
    pub fn new(webauthn_service: W) -> Self {
        Self { webauthn_service }
    }

    pub async fn attestation_options(
        &self,
        request: web::Json<ServerPublicKeyCredentialCreationOptionsRequest>,
    ) -> ActixResult<HttpResponse> {
        match self
            .webauthn_service
            .generate_registration_challenge(request.into_inner())
            .await
        {
            Ok(response) => Ok(HttpResponse::Ok().json(response)),
            Err(e) => {
                log::error!("Error generating registration challenge: {}", e);
                Ok(e.error_response())
            }
        }
    }

    pub async fn attestation_result(
        &self,
        request: web::Json<ServerPublicKeyCredential>,
    ) -> ActixResult<HttpResponse> {
        match self
            .webauthn_service
            .verify_registration_response(request.into_inner())
            .await
        {
            Ok(response) => Ok(HttpResponse::Ok().json(response)),
            Err(e) => {
                log::error!("Error verifying registration response: {}", e);
                Ok(e.error_response())
            }
        }
    }

    pub async fn assertion_options(
        &self,
        request: web::Json<ServerPublicKeyCredentialGetOptionsRequest>,
    ) -> ActixResult<HttpResponse> {
        match self
            .webauthn_service
            .generate_authentication_challenge(request.into_inner())
            .await
        {
            Ok(response) => Ok(HttpResponse::Ok().json(response)),
            Err(e) => {
                log::error!("Error generating authentication challenge: {}", e);
                Ok(e.error_response())
            }
        }
    }

    pub async fn assertion_result(
        &self,
        request: web::Json<ServerPublicKeyCredential>,
    ) -> ActixResult<HttpResponse> {
        match self
            .webauthn_service
            .verify_authentication_response(request.into_inner())
            .await
        {
            Ok(response) => Ok(HttpResponse::Ok().json(response)),
            Err(e) => {
                log::error!("Error verifying authentication response: {}", e);
                Ok(e.error_response())
            }
        }
    }
}

// Factory functions for dependency injection
pub fn make_attestation_options_handler<W>(
    controller: web::Data<WebAuthnController<W>>,
) -> impl Fn(web::Json<ServerPublicKeyCredentialCreationOptionsRequest>) -> ActixResult<HttpResponse>
where
    W: WebAuthnService + 'static,
{
    move |request| controller.attestation_options(request)
}

pub fn make_attestation_result_handler<W>(
    controller: web::Data<WebAuthnController<W>>,
) -> impl Fn(web::Json<ServerPublicKeyCredential>) -> ActixResult<HttpResponse>
where
    W: WebAuthnService + 'static,
{
    move |request| controller.attestation_result(request)
}

pub fn make_assertion_options_handler<W>(
    controller: web::Data<WebAuthnController<W>>,
) -> impl Fn(web::Json<ServerPublicKeyCredentialGetOptionsRequest>) -> ActixResult<HttpResponse>
where
    W: WebAuthnService + 'static,
{
    move |request| controller.assertion_options(request)
}

pub fn make_assertion_result_handler<W>(
    controller: web::Data<WebAuthnController<W>>,
) -> impl Fn(web::Json<ServerPublicKeyCredential>) -> ActixResult<HttpResponse>
where
    W: WebAuthnService + 'static,
{
    move |request| controller.assertion_result(request)
}