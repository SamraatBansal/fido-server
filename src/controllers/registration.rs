//! Registration controller

use actix_web::{web, HttpRequest, HttpResponse, Result};
use std::sync::Arc;
use crate::services::WebAuthnService;
use crate::models::{
    ServerPublicKeyCredentialCreationOptionsRequest, ServerPublicKeyCredentialCreationOptionsResponse,
    ServerPublicKeyCredential, RegistrationResultResponse,
};

/// Registration controller
pub struct RegistrationController {
    webauthn_service: Arc<WebAuthnService>,
}

impl RegistrationController {
    /// Create a new registration controller
    pub fn new(webauthn_service: Arc<WebAuthnService>) -> Self {
        Self { webauthn_service }
    }

    /// Generate registration options
    pub async fn generate_options(
        &self,
        request: web::Json<ServerPublicKeyCredentialCreationOptionsRequest>,
        _req: HttpRequest,
    ) -> Result<HttpResponse> {
        match self.webauthn_service.generate_registration_options(request.into_inner()).await {
            Ok(response) => Ok(HttpResponse::Ok().json(response)),
            Err(e) => {
                log::error!("Failed to generate registration options: {}", e);
                Ok(e.error_response())
            }
        }
    }

    /// Verify registration response
    pub async fn verify_registration(
        &self,
        request: web::Json<ServerPublicKeyCredential>,
        _req: HttpRequest,
    ) -> Result<HttpResponse> {
        match self.webauthn_service.verify_registration(request.into_inner()).await {
            Ok(response) => Ok(HttpResponse::Ok().json(response)),
            Err(e) => {
                log::error!("Failed to verify registration: {}", e);
                Ok(e.error_response())
            }
        }
    }
}

/// Configure registration routes
pub fn configure(cfg: &mut web::ServiceConfig, controller: Arc<RegistrationController>) {
    cfg.service(
        web::scope("/attestation")
            .route("/options", web::post().to({
                let controller = controller.clone();
                move |body, req| {
                    let controller = controller.clone();
                    async move { controller.generate_options(body, req).await }
                }
            }))
            .route("/result", web::post().to({
                let controller = controller.clone();
                move |body, req| {
                    let controller = controller.clone();
                    async move { controller.verify_registration(body, req).await }
                }
            }))
    );
}