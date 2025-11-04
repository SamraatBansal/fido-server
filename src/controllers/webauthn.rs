//! WebAuthn API controllers
//! 
//! Handles the HTTP endpoints for FIDO2/WebAuthn registration and authentication.

use actix_web::{web, HttpResponse, Result as ActixResult};
use std::sync::Arc;

use crate::error::AppError;
use crate::webauthn::*;
use crate::webauthn::service::WebAuthnService;

/// WebAuthn controller
pub struct WebAuthnController {
    webauthn_service: Arc<dyn WebAuthnService>,
}

impl WebAuthnController {
    pub fn new(webauthn_service: Arc<dyn WebAuthnService>) -> Self {
        Self { webauthn_service }
    }
}

/// Begin registration endpoint
/// POST /attestation/options
pub async fn begin_registration(
    controller: web::Data<Arc<WebAuthnController>>,
    request: web::Json<ServerPublicKeyCredentialCreationOptionsRequest>,
) -> ActixResult<HttpResponse> {
    match controller.webauthn_service.begin_registration(request.into_inner()).await {
        Ok(response) => Ok(HttpResponse::Ok().json(response)),
        Err(AppError::BadRequest(msg)) => {
            Ok(HttpResponse::BadRequest().json(ServerResponse {
                status: "failed".to_string(),
                error_message: msg,
            }))
        }
        Err(AppError::NotFound(msg)) => {
            Ok(HttpResponse::NotFound().json(ServerResponse {
                status: "failed".to_string(),
                error_message: msg,
            }))
        }
        Err(_) => {
            Ok(HttpResponse::InternalServerError().json(ServerResponse {
                status: "failed".to_string(),
                error_message: "Internal server error".to_string(),
            }))
        }
    }
}

/// Finish registration endpoint
/// POST /attestation/result
pub async fn finish_registration(
    controller: web::Data<Arc<WebAuthnController>>,
    request: web::Json<ServerPublicKeyCredential>,
) -> ActixResult<HttpResponse> {
    // Extract username from client data JSON in the credential
    let client_data_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&request.response.client_data_json)
        .unwrap_or_default();
    
    let client_data: serde_json::Value = serde_json::from_slice(&client_data_bytes)
        .unwrap_or_default();
    
    // For now, we'll need to pass the username separately or extract it from the challenge
    // Let's modify the service to handle this properly
    match controller.webauthn_service.finish_registration(request.into_inner(), "").await {
        Ok(response) => Ok(HttpResponse::Ok().json(response)),
        Err(AppError::BadRequest(msg)) => {
            Ok(HttpResponse::BadRequest().json(ServerResponse {
                status: "failed".to_string(),
                error_message: msg,
            }))
        }
        Err(AppError::NotFound(msg)) => {
            Ok(HttpResponse::NotFound().json(ServerResponse {
                status: "failed".to_string(),
                error_message: msg,
            }))
        }
        Err(_) => {
            Ok(HttpResponse::InternalServerError().json(ServerResponse {
                status: "failed".to_string(),
                error_message: "Internal server error".to_string(),
            }))
        }
    }
}

/// Begin authentication endpoint
/// POST /assertion/options
pub async fn begin_authentication(
    controller: web::Data<Arc<WebAuthnController>>,
    request: web::Json<ServerPublicKeyCredentialGetOptionsRequest>,
) -> ActixResult<HttpResponse> {
    match controller.webauthn_service.begin_authentication(request.into_inner()).await {
        Ok(response) => Ok(HttpResponse::Ok().json(response)),
        Err(AppError::BadRequest(msg)) => {
            Ok(HttpResponse::BadRequest().json(ServerResponse {
                status: "failed".to_string(),
                error_message: msg,
            }))
        }
        Err(AppError::NotFound(msg)) => {
            Ok(HttpResponse::NotFound().json(ServerResponse {
                status: "failed".to_string(),
                error_message: msg,
            }))
        }
        Err(_) => {
            Ok(HttpResponse::InternalServerError().json(ServerResponse {
                status: "failed".to_string(),
                error_message: "Internal server error".to_string(),
            }))
        }
    }
}

/// Finish authentication endpoint
/// POST /assertion/result
pub async fn finish_authentication(
    controller: web::Data<Arc<WebAuthnController>>,
    request: web::Json<ServerAssertionPublicKeyCredential>,
) -> ActixResult<HttpResponse> {
    match controller.webauthn_service.finish_authentication(request.into_inner()).await {
        Ok(response) => Ok(HttpResponse::Ok().json(response)),
        Err(AppError::BadRequest(msg)) => {
            Ok(HttpResponse::BadRequest().json(ServerResponse {
                status: "failed".to_string(),
                error_message: msg,
            }))
        }
        Err(AppError::NotFound(msg)) => {
            Ok(HttpResponse::NotFound().json(ServerResponse {
                status: "failed".to_string(),
                error_message: msg,
            }))
        }
        Err(_) => {
            Ok(HttpResponse::InternalServerError().json(ServerResponse {
                status: "failed".to_string(),
                error_message: "Internal server error".to_string(),
            }))
        }
    }
}