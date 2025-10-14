//! Registration controllers

use actix_web::{web, HttpResponse, Result};
use crate::error::AppError;
use crate::models::{
    ServerPublicKeyCredentialCreationOptionsRequest,
    ServerPublicKeyCredentialCreationOptionsResponse,
    ServerPublicKeyCredential,
    ServerResponse,
    PublicKeyCredentialRpEntity,
    ServerPublicKeyCredentialUserEntity,
    PublicKeyCredentialParameters,
    ServerPublicKeyCredentialDescriptor,
    AuthenticatorSelectionCriteria,
    AuthenticationExtensionsClientInputs,
};
use base64::{Engine as _, engine::general_purpose};
use chrono::Utc;
use uuid::Uuid;
use webauthn_rs::prelude::*;

/// WebAuthn configuration
pub struct WebAuthnConfig {
    pub rp_name: String,
    pub rp_id: String,
    pub rp_origin: String,
}

impl Default for WebAuthnConfig {
    fn default() -> Self {
        Self {
            rp_name: "FIDO Server".to_string(),
            rp_id: "localhost".to_string(),
            rp_origin: "http://localhost:3000".to_string(),
        }
    }
}

/// Handle attestation options request
pub async fn attestation_options(
    req: web::Json<ServerPublicKeyCredentialCreationOptionsRequest>,
) -> Result<HttpResponse> {
    let config = WebAuthnConfig::default();
    
    // Generate challenge
    let challenge_bytes = generate_challenge();
    let challenge = general_purpose::URL_SAFE_NO_PAD.encode(&challenge_bytes);
    
    // Create user handle
    let user_handle = general_purpose::URL_SAFE_NO_PAD.encode(req.username.as_bytes());
    
    // Build response
    let response = ServerPublicKeyCredentialCreationOptionsResponse {
        status: "ok".to_string(),
        errorMessage: None,
        rp: PublicKeyCredentialRpEntity {
            name: config.rp_name,
            id: config.rp_id,
        },
        user: ServerPublicKeyCredentialUserEntity {
            id: user_handle,
            name: req.username.clone(),
            displayName: req.displayName.clone(),
        },
        challenge,
        pubKeyCredParams: vec![
            PublicKeyCredentialParameters {
                alg_type: "public-key".to_string(),
                alg: -7, // ES256
            },
            PublicKeyCredentialParameters {
                alg_type: "public-key".to_string(),
                alg: -257, // RS256
            },
        ],
        timeout: Some(60000),
        excludeCredentials: vec![], // TODO: Get existing credentials for user
        authenticatorSelection: req.authenticatorSelection.clone(),
        attestation: Some(req.attestation.clone()),
        extensions: None,
    };
    
    Ok(HttpResponse::Ok().json(response))
}

/// Handle attestation result
pub async fn attestation_result(
    req: web::Json<ServerPublicKeyCredential>,
) -> Result<HttpResponse> {
    // TODO: Validate attestation
    // TODO: Store credential
    
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
    use serde_json::json;

    #[actix_rt::test]
    async fn test_attestation_options_success() {
        let req = ServerPublicKeyCredentialCreationOptionsRequest {
            username: "test@example.com".to_string(),
            displayName: "Test User".to_string(),
            authenticatorSelection: Some(AuthenticatorSelectionCriteria {
                requireResidentKey: Some(false),
                authenticatorAttachment: Some("cross-platform".to_string()),
                userVerification: Some("preferred".to_string()),
            }),
            attestation: "direct".to_string(),
        };

        let result = attestation_options(web::Json(req)).await;
        assert!(result.is_ok());
        
        let response = result.unwrap();
        assert_eq!(response.status(), actix_web::http::StatusCode::OK);
    }

    #[actix_rt::test]
    async fn test_attestation_result_success() {
        let req = ServerPublicKeyCredential {
            id: "test-credential-id".to_string(),
            rawId: "test-raw-id".to_string(),
            response: crate::models::ServerAuthenticatorResponse::Attestation(
                crate::models::ServerAuthenticatorAttestationResponse {
                    clientDataJSON: "test-client-data".to_string(),
                    attestationObject: "test-attestation".to_string(),
                }
            ),
            getClientExtensionResults: None,
            credential_type: "public-key".to_string(),
        };

        let result = attestation_result(web::Json(req)).await;
        assert!(result.is_ok());
        
        let response = result.unwrap();
        assert_eq!(response.status(), actix_web::http::StatusCode::OK);
    }
}