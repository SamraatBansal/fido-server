//! Authentication controller

use actix_web::{web, HttpResponse, Result};
use crate::schema::auth::{AuthenticationStartRequest, AuthenticationFinishRequest, RegistrationStartRequest, RegistrationFinishRequest};
use crate::services::WebAuthnService;
use serde_json::json;

/// Start authentication
pub async fn start_authentication(
    web::Json(request): web::Json<AuthenticationStartRequest>,
    webauthn_service: web::Data<std::sync::Mutex<WebAuthnService>>,
) -> Result<HttpResponse> {
    let mut service = webauthn_service.lock().unwrap();
    match service.start_authentication(request).await {
        Ok((challenge_id, options)) => {
            Ok(HttpResponse::Ok().json(json!({
                "challenge_id": challenge_id,
                "publicKey": options
            })))
        }
        Err(e) => {
            log::error!("Authentication start failed: {:?}", e);
            Ok(HttpResponse::BadRequest().json(json!({
                "error": {
                    "code": "AUTHENTICATION_START_FAILED",
                    "message": e.to_string()
                }
            })))
        }
    }
}

/// Finish authentication
pub async fn finish_authentication(
    web::Json(request): web::Json<AuthenticationFinishRequest>,
    webauthn_service: web::Data<std::sync::Mutex<WebAuthnService>>,
) -> Result<HttpResponse> {
    let mut service = webauthn_service.lock().unwrap();
    match service.finish_authentication(request.challenge_id, request.credential).await {
        Ok(result) => {
            Ok(HttpResponse::Ok().json(json!({
                "user_id": result.user_id,
                "session_token": result.session_token,
                "authenticated_at": chrono::Utc::now(),
                "authenticator_info": {
                    "sign_count": result.counter,
                    "clone_warning": false
                }
            })))
        }
        Err(e) => {
            log::error!("Authentication finish failed: {:?}", e);
            Ok(HttpResponse::Unauthorized().json(json!({
                "error": {
                    "code": "AUTHENTICATION_FAILED",
                    "message": e.to_string()
                }
            })))
        }
    }
}

/// Start registration
pub async fn start_registration(
    web::Json(request): web::Json<RegistrationStartRequest>,
    webauthn_service: web::Data<std::sync::Mutex<WebAuthnService>>,
) -> Result<HttpResponse> {
    let mut service = webauthn_service.lock().unwrap();
    match service.start_registration(request).await {
        Ok((challenge_id, options)) => {
            Ok(HttpResponse::Ok().json(json!({
                "challenge_id": challenge_id,
                "publicKey": options
            })))
        }
        Err(e) => {
            log::error!("Registration start failed: {:?}", e);
            Ok(HttpResponse::BadRequest().json(json!({
                "error": {
                    "code": "REGISTRATION_START_FAILED",
                    "message": e.to_string()
                }
            })))
        }
    }
}

/// Finish registration
pub async fn finish_registration(
    web::Json(request): web::Json<RegistrationFinishRequest>,
    webauthn_service: web::Data<std::sync::Mutex<WebAuthnService>>,
) -> Result<HttpResponse> {
    let mut service = webauthn_service.lock().unwrap();
    match service.finish_registration(request.challenge_id, request.credential).await {
        Ok(credential) => {
            Ok(HttpResponse::Created().json(json!({
                "credential_id": credential.credential_id,
                "user_id": credential.user_id,
                "created_at": credential.created_at,
                "authenticator_info": {
                    "aaguid": credential.aaguid,
                    "sign_count": credential.sign_count,
                    "clone_warning": credential.clone_warning
                }
            })))
        }
        Err(e) => {
            log::error!("Registration finish failed: {:?}", e);
            Ok(HttpResponse::BadRequest().json(json!({
                "error": {
                    "code": "REGISTRATION_FAILED",
                    "message": e.to_string()
                }
            })))
        }
    }
}