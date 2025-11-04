//! WebAuthn API controllers
//! 
//! Handles the HTTP endpoints for FIDO2/WebAuthn registration and authentication.

use actix_web::{web, HttpRequest, HttpResponse, Result as ActixResult};
use serde_json::json;
use std::sync::Arc;

use crate::error::{AppError, Result};
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
            Ok(HttpResponse::BadRequest().json(ServerPublicKeyCredentialCreationOptionsResponse {
                status: "failed".to_string(),
                error_message: msg,
                rp: PublicKeyCredentialRpEntity { name: String::new() },
                user: ServerPublicKeyCredentialUserEntity {
                    id: String::new(),
                    name: String::new(),
                    display_name: String::new(),
                },
                challenge: String::new(),
                pub_key_cred_params: vec![],
                timeout: None,
                exclude_credentials: vec![],
                authenticator_selection: None,
                attestation: None,
                extensions: None,
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
    query: web::Query<std::collections::HashMap<String, String>>,
) -> ActixResult<HttpResponse> {
    let username = query.get("username").cloned().unwrap_or_default();
    
    match controller.webauthn_service.finish_registration(request.into_inner(), &username).await {
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
            Ok(HttpResponse::BadRequest().json(ServerPublicKeyCredentialGetOptionsResponse {
                status: "failed".to_string(),
                error_message: msg,
                challenge: String::new(),
                timeout: None,
                rp_id: String::new(),
                allow_credentials: vec![],
                user_verification: None,
                extensions: None,
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