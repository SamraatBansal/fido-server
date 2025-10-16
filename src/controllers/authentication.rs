//! Authentication controller for FIDO2/WebAuthn assertion

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use actix_web::{web, HttpRequest, HttpResponse, Result};
use webauthn_rs::prelude::*;

use crate::controllers::dto::{
    AuthenticationVerificationRequest,
    ServerPublicKeyCredentialDescriptor, ServerPublicKeyCredentialGetOptionsRequest,
    ServerPublicKeyCredentialGetOptionsResponse, ServerResponse,
};
use crate::error::AppError;
use crate::services::webauthn::WebAuthnService;

/// Generate authentication challenge (assertion options)
pub async fn assertion_options(
    webauthn_service: web::Data<WebAuthnService>,
    req: HttpRequest,
    payload: web::Json<ServerPublicKeyCredentialGetOptionsRequest>,
) -> Result<HttpResponse> {
    // Extract origin from request
    let origin = extract_origin(&req)?;
    
    // Generate challenge
    let challenge_result = webauthn_service
        .generate_authentication_challenge(&payload.username, origin)
        .await;

    match challenge_result {
        Ok((challenge, credentials)) => {
            let allow_credentials: Vec<ServerPublicKeyCredentialDescriptor> = credentials
                .into_iter()
                .map(|cred_id| ServerPublicKeyCredentialDescriptor {
                    credential_type: "public-key".to_string(),
                    id: URL_SAFE_NO_PAD.encode(&cred_id),
                    transports: None,
                })
                .collect();

            let response = ServerPublicKeyCredentialGetOptionsResponse {
                base: ServerResponse::success(),
                challenge: URL_SAFE_NO_PAD.encode(&challenge),
                timeout: Some(60000),
                rp_id: "localhost".to_string(),
                allowCredentials: allow_credentials,
                user_verification: payload.user_verification.clone(),
                extensions: None,
            };

            Ok(HttpResponse::Ok().json(response))
        }
        Err(e) => {
            tracing::error!("Failed to generate authentication challenge: {:?}", e);
            let response = ServerResponse::error("User does not exists!");
            Ok(HttpResponse::BadRequest().json(response))
        }
    }
}

/// Verify authentication assertion
pub async fn assertion_result(
    webauthn_service: web::Data<WebAuthnService>,
    req: HttpRequest,
    payload: web::Json<AuthenticationVerificationRequest>,
) -> Result<HttpResponse> {
    // Extract origin from request
    let origin = extract_origin(&req)?;
    
    // Decode base64url fields
    let client_data_json = base64::decode_config(&payload.response.client_data_json, URL_SAFE_NO_PAD)
        .map_err(|_| AppError::InvalidRequest("Invalid clientDataJSON encoding".to_string()))?;
    
    let authenticator_data = base64::decode_config(&payload.response.authenticator_data, URL_SAFE_NO_PAD)
        .map_err(|_| AppError::InvalidRequest("Invalid authenticatorData encoding".to_string()))?;

    let signature = base64::decode_config(&payload.response.signature, URL_SAFE_NO_PAD)
        .map_err(|_| AppError::InvalidRequest("Invalid signature encoding".to_string()))?;

    let user_handle = if !payload.response.user_handle.is_empty() {
        Some(
            base64::decode_config(&payload.response.user_handle, URL_SAFE_NO_PAD)
                .map_err(|_| AppError::InvalidRequest("Invalid userHandle encoding".to_string()))?,
        )
    } else {
        None
    };

    // Create webauthn credential
    let credential = PublicKeyCredential {
        id: payload.id.clone(),
        raw_id: base64::decode_config(&payload.rawId, URL_SAFE_NO_PAD)
            .map_err(|_| AppError::InvalidRequest("Invalid rawId encoding".to_string()))?,
        response: AuthenticatorAssertionResponse {
            authenticator_data,
            client_data_json,
            signature,
            user_handle,
        },
        type_: "public-key".to_string(),
        extensions: None,
    };

    // Verify assertion
    match webauthn_service.verify_authentication(&credential, origin).await {
        Ok(_) => {
            let response = ServerResponse::success();
            Ok(HttpResponse::Ok().json(response))
        }
        Err(e) => {
            tracing::error!("Failed to verify authentication: {:?}", e);
            let response = ServerResponse::error("Can not validate response signature!");
            Ok(HttpResponse::BadRequest().json(response))
        }
    }
}

/// Extract origin from HTTP request
fn extract_origin(req: &HttpRequest) -> Result<String, AppError> {
    let connection_info = req.connection_info();
    let scheme = connection_info.scheme();
    let host = connection_info.host();
    
    // For development, we'll use localhost
    let origin = if host.starts_with("localhost") {
        format!("{}://{}", scheme, host)
    } else {
        // In production, this should validate against configured RP ID
        format!("{}://{}", scheme, host)
    };

    Ok(origin)
}