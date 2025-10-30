use actix_web::{web, HttpResponse};
use crate::dtos::*;
use crate::services::{WebAuthnService, WebAuthnServiceImpl};
use crate::error::AppError;
use std::sync::Arc;

pub struct WebAuthnController {
    webauthn_service: Arc<WebAuthnServiceImpl>,
}

impl WebAuthnController {
    pub fn new(webauthn_service: Arc<WebAuthnServiceImpl>) -> Self {
        Self { webauthn_service }
    }

    pub async fn begin_attestation(
        &self,
        request: web::Json<ServerPublicKeyCredentialCreationOptionsRequest>,
    ) -> Result<HttpResponse, AppError> {
        let response = self.webauthn_service
            .begin_registration(request.into_inner())
            .await?;
        
        Ok(HttpResponse::Ok().json(response))
    }

    pub async fn finish_attestation(
        &self,
        request: web::Json<ServerPublicKeyCredential>,
    ) -> Result<HttpResponse, AppError> {
        let response = self.webauthn_service
            .finish_registration(request.into_inner())
            .await?;
        
        Ok(HttpResponse::Ok().json(response))
    }

    pub async fn begin_assertion(
        &self,
        request: web::Json<ServerPublicKeyCredentialGetOptionsRequest>,
    ) -> Result<HttpResponse, AppError> {
        let response = self.webauthn_service
            .begin_authentication(request.into_inner())
            .await?;
        
        Ok(HttpResponse::Ok().json(response))
    }

    pub async fn finish_assertion(
        &self,
        request: web::Json<ServerPublicKeyCredential>,
    ) -> Result<HttpResponse, AppError> {
        let response = self.webauthn_service
            .finish_authentication(request.into_inner())
            .await?;
        
        Ok(HttpResponse::Ok().json(response))
    }
}

pub fn configure_routes(cfg: &mut web::ServiceConfig, controller: web::Data<WebAuthnController>) {
    cfg.service(
        web::scope("/webauthn")
            .route("/attestation/options", web::post().to({
                let controller = controller.clone();
                move |req| async move {
                    controller.begin_attestation(req).await
                }
            }))
            .route("/attestation/result", web::post().to({
                let controller = controller.clone();
                move |req| async move {
                    controller.finish_attestation(req).await
                }
            }))
            .route("/assertion/options", web::post().to({
                let controller = controller.clone();
                move |req| async move {
                    controller.begin_assertion(req).await
                }
            }))
            .route("/assertion/result", web::post().to({
                let controller = controller.clone();
                move |req| async move {
                    controller.finish_assertion(req).await
                }
            }))
    );
}

// Alternative route configuration for the exact paths specified in the requirements
pub fn configure_standard_routes(cfg: &mut web::ServiceConfig, controller: web::Data<WebAuthnController>) {
    cfg.service(
        web::scope("")
            .route("/attestation/options", web::post().to({
                let controller = controller.clone();
                move |req| async move {
                    controller.begin_attestation(req).await
                }
            }))
            .route("/attestation/result", web::post().to({
                let controller = controller.clone();
                move |req| async move {
                    controller.finish_attestation(req).await
                }
            }))
            .route("/assertion/options", web::post().to({
                let controller = controller.clone();
                move |req| async move {
                    controller.begin_assertion(req).await
                }
            }))
            .route("/assertion/result", web::post().to({
                let controller = controller.clone();
                move |req| async move {
                    controller.finish_assertion(req).await
                }
            }))
    );
}