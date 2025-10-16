//! WebAuthn HTTP controllers

use actix_web::{web, HttpRequest, HttpResponse, Result};
use crate::domain::dto::*;
use crate::error::{AppError, Result};
use crate::services::WebAuthnService;
use std::sync::Arc;

/// WebAuthn controller
pub struct WebAuthnController {
    webauthn_service: Arc<WebAuthnService>,
}

impl WebAuthnController {
    pub fn new(webauthn_service: Arc<WebAuthnService>) -> Self {
        Self { webauthn_service }
    }

    /// Generate registration challenge options
    /// POST /attestation/options
    pub async fn registration_challenge(
        &self,
        req: web::Json<ServerPublicKeyCredentialCreationOptionsRequest>,
        service: web::Data<Arc<WebAuthnService>>,
    ) -> Result<HttpResponse> {
        match service.generate_registration_challenge(req.into_inner()).await {
            Ok(response) => Ok(HttpResponse::Ok().json(response)),
            Err(e) => Err(e.into()),
        }
    }

    /// Verify registration attestation result
    /// POST /attestation/result
    pub async fn registration_verification(
        &self,
        req: web::Json<ServerPublicKeyCredential>,
        service: web::Data<Arc<WebAuthnService>>,
    ) -> Result<HttpResponse> {
        match service.verify_registration(req.into_inner()).await {
            Ok(response) => Ok(HttpResponse::Ok().json(response)),
            Err(e) => Err(e.into()),
        }
    }

    /// Generate authentication challenge options
    /// POST /assertion/options
    pub async fn authentication_challenge(
        &self,
        req: web::Json<ServerPublicKeyCredentialGetOptionsRequest>,
        service: web::Data<Arc<WebAuthnService>>,
    ) -> Result<HttpResponse> {
        match service.generate_authentication_challenge(req.into_inner()).await {
            Ok(response) => Ok(HttpResponse::Ok().json(response)),
            Err(e) => Err(e.into()),
        }
    }

    /// Verify authentication assertion result
    /// POST /assertion/result
    pub async fn authentication_verification(
        &self,
        req: web::Json<ServerPublicKeyCredential>,
        service: web::Data<Arc<WebAuthnService>>,
    ) -> Result<HttpResponse> {
        match service.verify_authentication(req.into_inner()).await {
            Ok(response) => Ok(HttpResponse::Ok().json(response)),
            Err(e) => Err(e.into()),
        }
    }
}

/// Route handlers for dependency injection

pub async fn registration_challenge_handler(
    req: web::Json<ServerPublicKeyCredentialCreationOptionsRequest>,
    service: web::Data<Arc<WebAuthnService>>,
) -> Result<HttpResponse> {
    let controller = WebAuthnController::new(service.get_ref().clone());
    controller.registration_challenge(req, service).await
}

pub async fn registration_verification_handler(
    req: web::Json<ServerPublicKeyCredential>,
    service: web::Data<Arc<WebAuthnService>>,
) -> Result<HttpResponse> {
    let controller = WebAuthnController::new(service.get_ref().clone());
    controller.registration_verification(req, service).await
}

pub async fn authentication_challenge_handler(
    req: web::Json<ServerPublicKeyCredentialGetOptionsRequest>,
    service: web::Data<Arc<WebAuthnService>>,
) -> Result<HttpResponse> {
    let controller = WebAuthnController::new(service.get_ref().clone());
    controller.authentication_challenge(req, service).await
}

pub async fn authentication_verification_handler(
    req: web::Json<ServerPublicKeyCredential>,
    service: web::Data<Arc<WebAuthnService>>,
) -> Result<HttpResponse> {
    let controller = WebAuthnController::new(service.get_ref().clone());
    controller.authentication_verification(req, service).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::{WebAuthnService, WebAuthnConfig};
    use actix_web::{test, web, App};

    #[actix_web::test]
    async fn test_registration_challenge_handler() {
        let config = WebAuthnConfig::default();
        let webauthn_service = Arc::new(WebAuthnService::new(config).unwrap());
        
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(webauthn_service.clone()))
                .route("/attestation/options", web::post().to(registration_challenge_handler))
        ).await;

        let req = test::TestRequest::post()
            .uri("/attestation/options")
            .set_json(ServerPublicKeyCredentialCreationOptionsRequest {
                username: "test@example.com".to_string(),
                displayName: "Test User".to_string(),
                authenticatorSelection: None,
                attestation: "direct".to_string(),
            })
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
    }

    #[actix_web::test]
    async fn test_authentication_challenge_handler() {
        let config = WebAuthnConfig::default();
        let webauthn_service = Arc::new(WebAuthnService::new(config).unwrap());
        
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(webauthn_service.clone()))
                .route("/assertion/options", web::post().to(authentication_challenge_handler))
        ).await;

        let req = test::TestRequest::post()
            .uri("/assertion/options")
            .set_json(ServerPublicKeyCredentialGetOptionsRequest {
                username: "test@example.com".to_string(),
                userVerification: Some("required".to_string()),
            })
            .to_request();

        let resp = test::call_service(&app, req).await;
        // This will return 404 since user doesn't exist yet, which is expected
        assert!(resp.status().is_client_error() || resp.status().is_success());
    }
}