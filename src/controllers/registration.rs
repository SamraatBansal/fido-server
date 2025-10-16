//! Registration controller for FIDO2/WebAuthn attestation

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use actix_web::{web, HttpRequest, HttpResponse, Result};
use log::error;

use crate::controllers::dto::{
    PublicKeyCredentialParameters,
    PublicKeyCredentialRpEntity, RegistrationVerificationRequest,
    ServerPublicKeyCredentialCreationOptionsRequest,
    ServerPublicKeyCredentialCreationOptionsResponse,
    ServerPublicKeyCredentialUserEntity, ServerResponse,
};
use crate::error::AppError;
use crate::services::webauthn::WebAuthnService;

/// Generate registration challenge (attestation options)
pub async fn attestation_options(
    webauthn_service: web::Data<WebAuthnService>,
    req: HttpRequest,
    payload: web::Json<ServerPublicKeyCredentialCreationOptionsRequest>,
) -> Result<HttpResponse, actix_web::Error> {
    // Extract origin from request
    let origin = extract_origin(&req)?;
    
    // Generate challenge
    let challenge_result = webauthn_service
        .generate_registration_challenge(&payload.username, &payload.displayName, origin)
        .await;

    match challenge_result {
        Ok((challenge, user_id)) => {
            let response = ServerPublicKeyCredentialCreationOptionsResponse {
                base: ServerResponse::success(),
                rp: PublicKeyCredentialRpEntity {
                    name: "Example Corporation".to_string(),
                    id: Some("localhost".to_string()),
                },
                user: ServerPublicKeyCredentialUserEntity {
                    id: URL_SAFE_NO_PAD.encode(user_id.as_bytes()),
                    name: payload.username.clone(),
                    display_name: payload.displayName.clone(),
                },
                challenge: URL_SAFE_NO_PAD.encode(&challenge),
                pubKeyCredParams: vec![
                    PublicKeyCredentialParameters {
                        credential_type: "public-key".to_string(),
                        alg: -7, // ES256
                    },
                    PublicKeyCredentialParameters {
                        credential_type: "public-key".to_string(),
                        alg: -257, // RS256
                    },
                ],
                timeout: Some(60000),
                excludeCredentials: vec![], // TODO: Get existing credentials for user
                authenticatorSelection: payload.authenticator_selection.clone(),
                attestation: Some(payload.attestation.clone()),
                extensions: None,
            };

            Ok(HttpResponse::Ok().json(response))
        }
        Err(e) => {
            error!("Failed to generate registration challenge: {:?}", e);
            let response = ServerResponse::error("Failed to generate challenge");
            Ok(HttpResponse::BadRequest().json(response))
        }
    }
}

/// Verify registration attestation
pub async fn attestation_result(
    webauthn_service: web::Data<WebAuthnService>,
    req: HttpRequest,
    payload: web::Json<RegistrationVerificationRequest>,
) -> Result<HttpResponse, actix_web::Error> {
    // Extract origin from request
    let origin = extract_origin(&req)?;
    
    // For now, just return success for testing
    // In a real implementation, we would verify the attestation
    match webauthn_service.verify_registration(&payload.id, origin).await {
        Ok(_) => {
            let response = ServerResponse::success();
            Ok(HttpResponse::Ok().json(response))
        }
        Err(e) => {
            error!("Failed to verify registration: {:?}", e);
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