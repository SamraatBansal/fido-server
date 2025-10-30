//! Authentication controller

use actix_web::{web, HttpRequest, HttpResponse, Result};
use std::sync::Arc;
use crate::services::WebAuthnService;
use crate::models::{
    ServerPublicKeyCredentialGetOptionsRequest, ServerPublicKeyCredentialGetOptionsResponse,
    ServerPublicKeyCredential, AuthenticationResultResponse,
};

/// Authentication controller
pub struct AuthenticationController {
    webauthn_service: Arc<WebAuthnService>,
}

impl AuthenticationController {
    /// Create a new authentication controller
    pub fn new(webauthn_service: Arc<WebAuthnService>) -> Self {
        Self { webauthn_service }
    }

    /// Generate authentication options
    pub async fn generate_options(
        &self,
        request: web::Json<ServerPublicKeyCredentialGetOptionsRequest>,
        _req: HttpRequest,
    ) -> Result<HttpResponse> {
        match self.webauthn_service.generate_authentication_options(request.into_inner()).await {
            Ok(response) => Ok(HttpResponse::Ok().json(response)),
            Err(e) => {
                log::error!("Failed to generate authentication options: {}", e);
                Ok(e.error_response())
            }
        }
    }

    /// Verify authentication response
    pub async fn verify_authentication(
        &self,
        request: web::Json<ServerPublicKeyCredential>,
        _req: HttpRequest,
    ) -> Result<HttpResponse> {
        match self.webauthn_service.verify_authentication(request.into_inner()).await {
            Ok(response) => Ok(HttpResponse::Ok().json(response)),
            Err(e) => {
                log::error!("Failed to verify authentication: {}", e);
                Ok(e.error_response())
            }
        }
    }
}

/// Configure authentication routes
pub fn configure(cfg: &mut web::ServiceConfig, controller: Arc<AuthenticationController>) {
    cfg.service(
        web::scope("/assertion")
            .route("/options", web::post().to({
                let controller = controller.clone();
                move |req, body| controller.generate_options(body, req)
            }))
            .route("/result", web::post().to({
                let controller = controller.clone();
                move |req, body| controller.verify_authentication(body, req)
            }))
    );
}