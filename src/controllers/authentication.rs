//! Authentication controllers

use actix_web::{web, HttpResponse, Result};
use crate::error::AppError;
use crate::models::{
    ServerPublicKeyCredentialGetOptionsRequest,
    ServerPublicKeyCredentialGetOptionsResponse,
    ServerPublicKeyCredential,
    ServerResponse,
    ServerPublicKeyCredentialDescriptor,
    ServerAuthenticatorAssertionResponse,
    ServerAuthenticatorResponse,
};
use base64::{Engine as _, engine::general_purpose};
use uuid::Uuid;

/// Handle assertion options request
pub async fn assertion_options(
    req: web::Json<ServerPublicKeyCredentialGetOptionsRequest>,
) -> Result<HttpResponse> {
    // Generate challenge
    let challenge_bytes = generate_challenge();
    let challenge = general_purpose::URL_SAFE_NO_PAD.encode(&challenge_bytes);
    
    // TODO: Get user credentials from database
    let allow_credentials = vec![]; // Empty for now
    
    let response = ServerPublicKeyCredentialGetOptionsResponse {
        status: "ok".to_string(),
        errorMessage: None,
        challenge,
        timeout: Some(60000),
        rpId: "localhost".to_string(),
        allowCredentials,
        userVerification: req.userVerification.clone(),
    };
    
    Ok(HttpResponse::Ok().json(response))
}

/// Handle assertion result
pub async fn assertion_result(
    req: web::Json<ServerPublicKeyCredential>,
) -> Result<HttpResponse> {
    // TODO: Validate assertion
    // TODO: Update sign counter
    
    let response = ServerResponse::success(());
    
    Ok(HttpResponse::Ok().json(response))
}

/// Generate a cryptographically random challenge
fn generate_challenge() -> Vec<u8> {
    use rand::RngCore;
    let mut challenge = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut challenge);
    challenge.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test;

    #[actix_rt::test]
    async fn test_assertion_options_success() {
        let req = ServerPublicKeyCredentialGetOptionsRequest {
            username: Some("test@example.com".to_string()),
            userVerification: Some("required".to_string()),
        };

        let result = assertion_options(web::Json(req)).await;
        assert!(result.is_ok());
        
        let response = result.unwrap();
        assert_eq!(response.status(), actix_web::http::StatusCode::OK);
    }

    #[actix_rt::test]
    async fn test_assertion_result_success() {
        let req = ServerPublicKeyCredential {
            id: "test-credential-id".to_string(),
            rawId: "test-raw-id".to_string(),
            response: ServerAuthenticatorResponse::Assertion(
                ServerAuthenticatorAssertionResponse {
                    clientDataJSON: "test-client-data".to_string(),
                    authenticatorData: "test-auth-data".to_string(),
                    signature: "test-signature".to_string(),
                    userHandle: Some("test-user-handle".to_string()),
                }
            ),
            getClientExtensionResults: None,
            credential_type: "public-key".to_string(),
        };

        let result = assertion_result(web::Json(req)).await;
        assert!(result.is_ok());
        
        let response = result.unwrap();
        assert_eq!(response.status(), actix_web::http::StatusCode::OK);
    }
}