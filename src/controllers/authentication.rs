//! Authentication controller

use actix_web::{web, HttpResponse, Result};
use serde_json::json;
use std::net::IpAddr;
use std::sync::Arc;
use webauthn_rs::prelude::*;

use crate::services::fido::{FidoService, AuthenticationStartRequest, AuthenticationFinishRequest};
use crate::config::WebAuthnConfig;
use crate::schema::responses::SuccessResponse;
use crate::middleware::ClientIp;

/// Start authentication endpoint
pub async fn start_authentication(
    fido_service: web::Data<Arc<FidoService>>,
    webauthn_config: web::Data<Arc<WebAuthnConfig>>,
    req: web::Json<serde_json::Value>,
    client_ip: ClientIp,
) -> Result<HttpResponse> {
    // Parse request
    let username = req.get("username")
        .and_then(|v| v.as_str())
        .ok_or_else(|| actix_web::error::ErrorBadRequest("Missing username"))?
        .to_string();

    let user_verification = req.get("user_verification")
        .and_then(|v| v.as_str())
        .and_then(|s| match s {
            "required" => Some(UserVerificationPolicy::Required),
            "preferred" => Some(UserVerificationPolicy::Preferred),
            "discouraged" => Some(UserVerificationPolicy::Discouraged),
            _ => None,
        })
        .unwrap_or(webauthn_config.user_verification);

    let client_ip = client_ip.as_ref()
        .copied()
        .unwrap_or_else(|| "127.0.0.1".parse().unwrap());

    let request = AuthenticationStartRequest {
        username,
        user_verification,
        client_ip,
    };

    match fido_service.start_authentication(request).await {
        Ok(challenge) => {
            let response = SuccessResponse::new(challenge);
            Ok(HttpResponse::Ok().json(response))
        }
        Err(e) => {
            log::error!("Authentication start failed: {:?}", e);
            Err(actix_web::error::ErrorInternalServerError(e.to_string()))
        }
    }
}

/// Finish authentication endpoint
pub async fn finish_authentication(
    fido_service: web::Data<Arc<FidoService>>,
    req: web::Json<serde_json::Value>,
    client_ip: ClientIp,
) -> Result<HttpResponse> {
    // Parse credential from request
    let credential_data = req.get("credential")
        .ok_or_else(|| actix_web::error::ErrorBadRequest("Missing credential"))?;

    let credential: PublicKeyCredential = serde_json::from_value(credential_data.clone())
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("Invalid credential format: {}", e)))?;

    let session_id = req.get("session_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| actix_web::error::ErrorBadRequest("Missing session_id"))?
        .to_string();

    let client_ip = client_ip.as_ref()
        .copied()
        .unwrap_or_else(|| "127.0.0.1".parse().unwrap());

    let request = AuthenticationFinishRequest {
        credential,
        session_id,
        client_ip,
    };

    match fido_service.finish_authentication(request).await {
        Ok(result) => {
            let response = SuccessResponse::new(json!({
                "session_token": result.session_token,
                "user_id": result.user_id,
                "credential_id": result.credential_id
            }));
            Ok(HttpResponse::Ok().json(response))
        }
        Err(e) => {
            log::error!("Authentication finish failed: {:?}", e);
            Err(actix_web::error::ErrorInternalServerError(e.to_string()))
        }
    }
}