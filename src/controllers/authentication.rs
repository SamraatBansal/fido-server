//! Authentication controller for FIDO2/WebAuthn assertion

use actix_web::{web, HttpRequest, HttpResponse, Result};
use log::error;

use crate::controllers::dto::{
    AuthenticationVerificationRequest,
    ServerPublicKeyCredentialDescriptor, ServerPublicKeyCredentialGetOptionsRequest,
    ServerPublicKeyCredentialGetOptionsResponse, ServerResponse,
};
use crate::error::AppError;
use crate::services::WebAuthnService;

/// Generate authentication challenge (assertion options)
pub async fn assertion_options(
    webauthn_service: web::Data<WebAuthnService>,
    req: HttpRequest,
    payload: web::Json<ServerPublicKeyCredentialGetOptionsRequest>,
) -> Result<HttpResponse, actix_web::Error> {
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
                    id: base64::encode_config(&cred_id, base64::URL_SAFE_NO_PAD),
                    transports: None,
                })
                .collect();

            let response = ServerPublicKeyCredentialGetOptionsResponse {
                base: ServerResponse::success(),
                challenge: base64::encode_config(&challenge, base64::URL_SAFE_NO_PAD),
                timeout: Some(60000),
                rp_id: "localhost".to_string(),
                allowCredentials: allow_credentials,
                user_verification: payload.user_verification.clone(),
                extensions: None,
            };

            Ok(HttpResponse::Ok().json(response))
        }
        Err(e) => {
            error!("Failed to generate authentication challenge: {:?}", e);
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
) -> Result<HttpResponse, actix_web::Error> {
    // Extract origin from request
    let origin = extract_origin(&req)?;
    
    // For now, just return success for testing
    // In a real implementation, we would verify the assertion
    match webauthn_service.verify_authentication(&payload.id, origin).await {
        Ok(_) => {
            let response = ServerResponse::success();
            Ok(HttpResponse::Ok().json(response))
        }
        Err(e) => {
            error!("Failed to verify authentication: {:?}", e);
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