//! Registration controller for FIDO2/WebAuthn

use actix_web::{web, HttpResponse, Result};
use crate::error::AppError;
use crate::models::{
    ServerPublicKeyCredentialCreationOptionsRequest,
    ServerPublicKeyCredentialCreationOptionsResponse,
    ServerPublicKeyCredential,
    PublicKeyCredentialRpEntity,
    ServerPublicKeyCredentialUserEntity,
    PublicKeyCredentialParameters,
};
use webauthn_rs_proto::AttestationConveyancePreference;
use base64::Engine;
use uuid::Uuid;

/// Handle attestation options request (registration challenge)
pub async fn attestation_options(
    req: web::Json<ServerPublicKeyCredentialCreationOptionsRequest>,
) -> Result<HttpResponse, AppError> {
    // Validate required fields
    if req.username.is_empty() {
        return Err(AppError::ValidationError("username is required".to_string()));
    }

    if req.display_name.is_empty() {
        return Err(AppError::ValidationError("displayName is required".to_string()));
    }

    // Validate attestation preference if provided
    let attestation = req.attestation.unwrap_or(AttestationConveyancePreference::None);
    
    // Generate a random challenge (minimum 16 bytes, base64url encoded)
    let challenge_bytes: [u8; 32] = rand::random();
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge_bytes);

    // Generate user ID
    let user_id_bytes = Uuid::new_v4().as_bytes().to_vec();
    let user_id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(user_id_bytes);

    // Create response
    let response = ServerPublicKeyCredentialCreationOptionsResponse {
        status: "ok".to_string(),
        error_message: String::new(),
        rp: PublicKeyCredentialRpEntity {
            name: "Example Corporation".to_string(),
            id: None,
        },
        user: ServerPublicKeyCredentialUserEntity {
            id: user_id,
            name: req.username.clone(),
            display_name: req.display_name.clone(),
        },
        challenge,
        pub_key_cred_params: vec![
            PublicKeyCredentialParameters {
                cred_type: "public-key".to_string(),
                alg: -7, // ES256
            },
        ],
        timeout: Some(10000), // 10 seconds
        exclude_credentials: vec![], // TODO: Implement credential lookup
        authenticator_selection: req.authenticator_selection.clone(),
        attestation,
    };

    Ok(HttpResponse::Ok().json(response))
}

/// Handle attestation result (registration verification)
pub async fn attestation_result(
    req: web::Json<ServerPublicKeyCredential>,
) -> Result<HttpResponse, AppError> {
    // Validate required fields
    if req.id.is_empty() {
        return Err(AppError::ValidationError("credential id is required".to_string()));
    }

    if req.cred_type != "public-key" {
        return Err(AppError::ValidationError("credential type must be 'public-key'".to_string()));
    }

    // For now, return a basic validation error since we haven't implemented
    // the full WebAuthn verification logic yet
    match &req.response {
        crate::models::ServerAuthenticatorResponse::Attestation(attestation) => {
            if attestation.client_data_json.is_empty() {
                return Err(AppError::ValidationError("clientDataJSON is required".to_string()));
            }
            if attestation.attestation_object.is_empty() {
                return Err(AppError::ValidationError("attestationObject is required".to_string()));
            }

            // TODO: Implement full WebAuthn attestation verification
            // For now, we'll return an error indicating incomplete implementation
            Err(AppError::WebAuthnError("Can not validate response signature!".to_string()))
        }
        _ => Err(AppError::ValidationError("Invalid response type for attestation".to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[actix_web::test]
    async fn test_attestation_options_valid_request() {
        let req_data = ServerPublicKeyCredentialCreationOptionsRequest {
            username: "test@example.com".to_string(),
            display_name: "Test User".to_string(),
            authenticator_selection: None,
            attestation: Some(AttestationConveyancePreference::None),
        };

        let result = attestation_options(web::Json(req_data)).await;
        assert!(result.is_ok());
    }

    #[actix_web::test]
    async fn test_attestation_options_empty_username() {
        let req_data = ServerPublicKeyCredentialCreationOptionsRequest {
            username: String::new(),
            display_name: "Test User".to_string(),
            authenticator_selection: None,
            attestation: None,
        };

        let result = attestation_options(web::Json(req_data)).await;
        assert!(result.is_err());
        
        if let Err(AppError::ValidationError(msg)) = result {
            assert!(msg.contains("username"));
        } else {
            panic!("Expected ValidationError");
        }
    }

    #[actix_web::test]
    async fn test_attestation_options_empty_display_name() {
        let req_data = ServerPublicKeyCredentialCreationOptionsRequest {
            username: "test@example.com".to_string(),
            display_name: String::new(),
            authenticator_selection: None,
            attestation: None,
        };

        let result = attestation_options(web::Json(req_data)).await;
        assert!(result.is_err());
        
        if let Err(AppError::ValidationError(msg)) = result {
            assert!(msg.contains("displayName"));
        } else {
            panic!("Expected ValidationError");
        }
    }
}