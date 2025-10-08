//! Authentication controller for WebAuthn assertion

use actix_web::{post, web, HttpResponse, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::error::AppError;

/// Authentication controller
pub struct AuthenticationController;

impl AuthenticationController {
    /// Create new authentication controller
    pub fn new() -> Self {
        Self
    }
}

impl Default for AuthenticationController {
    fn default() -> Self {
        Self::new()
    }
}

/// Request to start assertion (authentication challenge)
#[derive(Debug, Deserialize, Validate)]
pub struct AssertionOptionsRequest {
    #[validate(email(message = "Invalid email format"))]
    pub username: String,

    #[validate(custom(function = "crate::utils::validation::validate_user_verification"))]
    #[serde(rename = "userVerification")]
    pub user_verification: Option<String>,
}

/// Response with assertion options (challenge)
#[derive(Debug, Serialize)]
pub struct AssertionOptionsResponse {
    pub challenge: String,
    #[serde(rename = "rpId")]
    pub rp_id: String,
    #[serde(rename = "allowCredentials")]
    pub allow_credentials: Vec<AllowCredential>,
    pub timeout: u32,
    #[serde(rename = "userVerification")]
    pub user_verification: String,
}

/// Allowed credential for authentication
#[derive(Debug, Serialize)]
pub struct AllowCredential {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub id: String,
    pub transports: Vec<String>,
}

/// Request to verify assertion result
#[derive(Debug, Deserialize, Validate)]
pub struct AssertionResultRequest {
    #[validate(length(min = 1, max = 1023, message = "Credential ID must be 1-1023 characters"))]
    #[validate(custom(function = "crate::utils::validation::validate_base64url"))]
    pub id: String,

    #[validate(length(min = 1, max = 1023, message = "Raw ID must be 1-1023 characters"))]
    #[validate(custom(function = "crate::utils::validation::validate_base64url"))]
    #[serde(rename = "rawId")]
    pub raw_id: String,

    #[validate(nested)]
    pub response: AssertionResponse,

    #[validate(custom(function = "crate::utils::validation::validate_credential_type"))]
    #[serde(rename = "type")]
    pub credential_type: String,
}

/// Assertion response
#[derive(Debug, Deserialize, Validate)]
pub struct AssertionResponse {
    #[validate(length(min = 37, message = "Authenticator data must be at least 37 bytes"))]
    #[validate(custom(function = "crate::utils::validation::validate_base64url"))]
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,

    #[validate(length(min = 1, message = "Client data JSON is required"))]
    #[validate(custom(function = "crate::utils::validation::validate_base64url"))]
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,

    #[validate(length(min = 1, message = "Signature is required"))]
    #[validate(custom(function = "crate::utils::validation::validate_base64url"))]
    pub signature: String,

    #[validate(custom(function = "crate::utils::validation::validate_base64url"))]
    #[serde(rename = "userHandle")]
    pub user_handle: Option<String>,
}

/// Response for successful assertion
#[derive(Debug, Serialize)]
pub struct AssertionResultResponse {
    #[serde(rename = "credentialId")]
    pub credential_id: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "authenticatedAt")]
    pub authenticated_at: String,
    #[serde(rename = "signCount")]
    pub sign_count: u64,
    #[serde(rename = "userVerified")]
    pub user_verified: bool,
}

/// Start assertion (authentication challenge)
#[post("/api/v1/webauthn/authentication/challenge")]
pub async fn start_assertion(
    request: web::Json<AssertionOptionsRequest>,
) -> HttpResponse {
    // Validate request
    if let Err(e) = request.validate() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("Invalid request: {}", e),
            "status": 400
        }));
    }

    // TODO: Implement actual WebAuthn challenge generation
    // For now, return a mock response
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(rand::random::<[u8; 32]>());

    let response = AssertionOptionsResponse {
        challenge,
        rp_id: "localhost".to_string(),
        allow_credentials: vec![AllowCredential {
            cred_type: "public-key".to_string(),
            id: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(rand::random::<[u8; 16]>()),
            transports: vec!["internal".to_string(), "usb".to_string()],
        }],
        timeout: 300000, // 5 minutes
        user_verification: request
            .user_verification
            .clone()
            .unwrap_or_else(|| "preferred".to_string()),
    };

    HttpResponse::Ok().json(response)
}

/// Verify assertion result
#[post("/api/v1/webauthn/authentication/verify")]
pub async fn verify_assertion(
    request: web::Json<AssertionResultRequest>,
) -> Result<HttpResponse, AppError> {
    // Validate request
    request
        .validate()
        .map_err(|e| AppError::ValidationError(format!("Invalid request: {}", e)))?;

    // TODO: Implement actual WebAuthn assertion verification
    // For now, return a mock response
    let response = AssertionResultResponse {
        credential_id: request.id.clone(),
        user_id: request
            .response
            .user_handle
            .clone()
            .unwrap_or_else(|| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(uuid::Uuid::new_v4().as_bytes())),
        authenticated_at: chrono::Utc::now().to_rfc3339(),
        sign_count: 1,
        user_verified: true,
    };

    Ok(HttpResponse::Ok().json(response))
}