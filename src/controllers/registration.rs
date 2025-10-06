//! Registration controller

use actix_web::{web, HttpResponse, Result};
use serde_json::json;
use std::sync::Arc;
use webauthn_rs::prelude::*;

use crate::services::fido::{FidoService, RegistrationStartRequest, RegistrationFinishRequest};
use crate::config::WebAuthnConfig;
use crate::schema::responses::SuccessResponse;
use crate::middleware::ClientIp;

/// Start registration endpoint
pub async fn start_registration(
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

    let display_name = req.get("display_name")
        .and_then(|v| v.as_str())
        .unwrap_or(&username)
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

    let attestation_preference = req.get("attestation_preference")
        .and_then(|v| v.as_str())
        .and_then(|s| match s {
            "none" => Some(AttestationConveyancePreference::None),
            "indirect" => Some(AttestationConveyancePreference::Indirect),
            "direct" => Some(AttestationConveyancePreference::Direct),
            "enterprise" => Some(AttestationConveyancePreference::Enterprise),
            _ => None,
        })
        .unwrap_or(webauthn_config.attestation_preference);

    let client_ip = client_ip.0;

    let request = RegistrationStartRequest {
        username,
        display_name,
        user_verification,
        attestation_preference,
        client_ip,
    };

    match fido_service.start_registration(request).await {
        Ok(challenge) => {
            let response = SuccessResponse::new(challenge);
            Ok(HttpResponse::Ok().json(response))
        }
        Err(e) => {
            log::error!("Registration start failed: {:?}", e);
            Err(actix_web::error::ErrorInternalServerError(e.to_string()))
        }
    }
}

/// Finish registration endpoint
pub async fn finish_registration(
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

    let client_ip = client_ip.0;

    let request = RegistrationFinishRequest {
        credential,
        session_id,
        client_ip,
    };

    match fido_service.finish_registration(request).await {
        Ok(result) => {
            let response = SuccessResponse::new(json!({
                "credential_id": result.credential_id,
                "user_id": result.user_id,
                "attestation_verified": result.attestation_result.verified
            }));
            Ok(HttpResponse::Created().json(response))
        }
        Err(e) => {
            log::error!("Registration finish failed: {:?}", e);
            Err(actix_web::error::ErrorInternalServerError(e.to_string()))
        }
    }
}