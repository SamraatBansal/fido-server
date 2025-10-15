//! Authentication controller for FIDO2/WebAuthn

use actix_web::{web, HttpResponse, Result};
use crate::error::AppError;
use crate::models::{
    ServerPublicKeyCredentialGetOptionsRequest,
    ServerPublicKeyCredentialGetOptionsResponse,
    ServerPublicKeyCredential,
    ServerPublicKeyCredentialDescriptor,
};
use webauthn_rs_proto::UserVerificationPolicy;
use base64::Engine;

/// Handle assertion options request (authentication challenge)
pub async fn assertion_options(
    req: web::Json<ServerPublicKeyCredentialGetOptionsRequest>,
) -> Result<HttpResponse, AppError> {
    // Validate required fields
    if req.username.is_empty() {
        return Err(AppError::ValidationError("username is required".to_string()));
    }

    // Validate user verification policy if provided
    let user_verification = req.user_verification.unwrap_or(UserVerificationPolicy::Preferred);
    
    // User verification policy is already validated by serde deserialization

    // For now, return an error for non-existent users since we haven't implemented
    // user storage yet
    // TODO: Look up user and their credentials in database
    
    // Generate a random challenge (minimum 16 bytes, base64url encoded)
    let challenge_bytes: [u8; 32] = rand::random();
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge_bytes);

    // For testing purposes, we'll return a mock response
    // In a real implementation, this would look up the user's credentials
    let response = ServerPublicKeyCredentialGetOptionsResponse {
        status: "ok".to_string(),
        error_message: String::new(),
        challenge,
        timeout: Some(20000), // 20 seconds
        rp_id: "example.com".to_string(),
        allow_credentials: vec![
            // TODO: Replace with actual user credentials from database
            ServerPublicKeyCredentialDescriptor {
                cred_type: "public-key".to_string(),
                id: "m7xl_TkTcCe0WcXI2M-4ro9vJAuwcj4m".to_string(),
                transports: None,
            }
        ],
        user_verification,
    };

    Ok(HttpResponse::Ok().json(response))
}

/// Handle assertion result (authentication verification)
pub async fn assertion_result(
    req: web::Json<ServerPublicKeyCredential>,
) -> Result<HttpResponse, AppError> {
    // Validate required fields
    if req.id.is_empty() {
        return Err(AppError::ValidationError("credential id is required".to_string()));
    }

    if req.cred_type != "public-key" {
        return Err(AppError::ValidationError("credential type must be 'public-key'".to_string()));
    }

    // Validate the assertion response
    match &req.response {
        crate::models::ServerAuthenticatorResponse::Assertion(assertion) => {
            if assertion.client_data_json.is_empty() {
                return Err(AppError::ValidationError("clientDataJSON is required".to_string()));
            }
            if assertion.authenticator_data.is_empty() {
                return Err(AppError::ValidationError("authenticatorData is required".to_string()));
            }
            if assertion.signature.is_empty() {
                return Err(AppError::ValidationError("signature is required".to_string()));
            }

            // TODO: Implement full WebAuthn assertion verification
            // For now, we'll return an error indicating incomplete implementation
            Err(AppError::WebAuthnError("Can not validate response signature!".to_string()))
        }
        _ => Err(AppError::ValidationError("Invalid response type for assertion".to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test;
    use serde_json::json;

    #[actix_web::test]
    async fn test_assertion_options_valid_request() {
        let req_data = ServerPublicKeyCredentialGetOptionsRequest {
            username: "test@example.com".to_string(),
            user_verification: Some(UserVerificationPolicy::Preferred),
        };

        let result = assertion_options(web::Json(req_data)).await;
        assert!(result.is_ok());
    }

    #[actix_web::test]
    async fn test_assertion_options_empty_username() {
        let req_data = ServerPublicKeyCredentialGetOptionsRequest {
            username: String::new(),
            user_verification: None,
        };

        let result = assertion_options(web::Json(req_data)).await;
        assert!(result.is_err());
        
        if let Err(AppError::ValidationError(msg)) = result {
            assert!(msg.contains("username"));
        } else {
            panic!("Expected ValidationError");
        }
    }

    #[actix_web::test]
    async fn test_assertion_options_default_user_verification() {
        let req_data = ServerPublicKeyCredentialGetOptionsRequest {
            username: "test@example.com".to_string(),
            user_verification: None,
        };

        let result = assertion_options(web::Json(req_data)).await;
        assert!(result.is_ok());
    }
}