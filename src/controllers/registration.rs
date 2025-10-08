//! Registration controller for WebAuthn attestation

use actix_web::{post, web, HttpResponse, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::error::AppError;

/// Registration controller
pub struct RegistrationController;

impl RegistrationController {
    /// Create new registration controller
    pub fn new() -> Self {
        Self
    }
}

impl Default for RegistrationController {
    fn default() -> Self {
        Self::new()
    }
}

/// Request to start attestation (registration challenge)
#[derive(Debug, Deserialize, Validate)]
pub struct AttestationOptionsRequest {
    #[validate(email(message = "Invalid email format"))]
    #[validate(length(min = 1, max = 255, message = "Username must be 1-255 characters"))]
    pub username: String,

    #[validate(length(min = 1, max = 255, message = "Display name must be 1-255 characters"))]
    #[serde(rename = "displayName")]
    pub display_name: String,

    #[validate(custom(function = "crate::utils::validation::validate_attestation"))]
    pub attestation: Option<String>,

    #[validate(nested)]
    #[serde(rename = "authenticatorSelection")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
}

/// Authenticator selection criteria
#[derive(Debug, Deserialize, Serialize, Clone, Validate)]
pub struct AuthenticatorSelectionCriteria {
    #[validate(custom(function = "crate::utils::validation::validate_authenticator_attachment"))]
    #[serde(rename = "authenticatorAttachment")]
    pub authenticator_attachment: Option<String>,

    #[serde(rename = "requireResidentKey")]
    pub require_resident_key: Option<bool>,

    #[validate(custom(function = "crate::utils::validation::validate_user_verification"))]
    #[serde(rename = "userVerification")]
    pub user_verification: Option<String>,
}

/// Response with attestation options (challenge)
#[derive(Debug, Serialize)]
pub struct AttestationOptionsResponse {
    pub challenge: String,
    pub rp: RelyingParty,
    pub user: User,
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    pub timeout: u32,
    pub attestation: String,
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
}

/// Relying party information
#[derive(Debug, Serialize)]
pub struct RelyingParty {
    pub name: String,
    pub id: String,
}

/// User information
#[derive(Debug, Serialize)]
pub struct User {
    pub id: String,
    pub name: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
}

/// Public key credential parameters
#[derive(Debug, Serialize)]
pub struct PublicKeyCredentialParameters {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub alg: i32,
}

/// Request to verify attestation result
#[derive(Debug, Deserialize, Validate)]
pub struct AttestationResultRequest {
    #[validate(length(min = 1, max = 1023, message = "Credential ID must be 1-1023 characters"))]
    #[validate(custom(function = "crate::utils::validation::validate_base64url"))]
    pub id: String,

    #[validate(length(min = 1, max = 1023, message = "Raw ID must be 1-1023 characters"))]
    #[validate(custom(function = "crate::utils::validation::validate_base64url"))]
    #[serde(rename = "rawId")]
    pub raw_id: String,

    #[validate(nested)]
    pub response: AttestationResponse,

    #[validate(custom(function = "crate::utils::validation::validate_credential_type"))]
    #[serde(rename = "type")]
    pub credential_type: String,
}

/// Attestation response
#[derive(Debug, Deserialize, Validate)]
pub struct AttestationResponse {
    #[validate(length(min = 1, message = "Attestation object is required"))]
    #[validate(custom(function = "crate::utils::validation::validate_base64url"))]
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,

    #[validate(length(min = 1, message = "Client data JSON is required"))]
    #[validate(custom(function = "crate::utils::validation::validate_base64url"))]
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
}

/// Response for successful attestation
#[derive(Debug, Serialize)]
pub struct AttestationResultResponse {
    #[serde(rename = "credentialId")]
    pub credential_id: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "registeredAt")]
    pub registered_at: String,
    pub aaguid: String,
    #[serde(rename = "signCount")]
    pub sign_count: u64,
    #[serde(rename = "userVerified")]
    pub user_verified: bool,
}

/// Start attestation (registration challenge)
#[post("/api/v1/webauthn/registration/challenge")]
pub async fn start_attestation(
    request: web::Json<AttestationOptionsRequest>,
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

    let response = AttestationOptionsResponse {
        challenge,
        rp: RelyingParty {
            name: "FIDO Server".to_string(),
            id: "localhost".to_string(),
        },
        user: User {
            id: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(uuid::Uuid::new_v4().as_bytes()),
            name: request.username.clone(),
            display_name: request.display_name.clone(),
        },
        pub_key_cred_params: vec![
            PublicKeyCredentialParameters {
                cred_type: "public-key".to_string(),
                alg: -7, // ES256
            },
            PublicKeyCredentialParameters {
                cred_type: "public-key".to_string(),
                alg: -257, // RS256
            },
        ],
        timeout: 300000, // 5 minutes
        attestation: request.attestation.clone().unwrap_or_else(|| "none".to_string()),
        authenticator_selection: request.authenticator_selection.clone(),
    };

    HttpResponse::Ok().json(response)
}

/// Verify attestation result
#[post("/api/v1/webauthn/registration/verify")]
pub async fn verify_attestation(
    request: web::Json<AttestationResultRequest>,
) -> HttpResponse {
    // Validate request
    if let Err(e) = request.validate() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("Invalid request: {}", e),
            "status": 400
        }));
    }

    // TODO: Implement actual WebAuthn attestation verification
    // For now, return a mock response
    let response = AttestationResultResponse {
        credential_id: request.id.clone(),
        user_id: base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(uuid::Uuid::new_v4().as_bytes()),
        registered_at: chrono::Utc::now().to_rfc3339(),
        aaguid: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 16]),
        sign_count: 0,
        user_verified: true,
    };

    HttpResponse::Ok().json(response)
}