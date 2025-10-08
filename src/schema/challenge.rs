//! Challenge-related request/response schemas

use serde::{Deserialize, Serialize};
use validator::Validate;

/// Challenge response
#[derive(Debug, Serialize)]
pub struct ChallengeResponse {
    pub challenge: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: String,
    #[serde(rename = "challengeType")]
    pub challenge_type: String,
}

/// Challenge verification request
#[derive(Debug, Deserialize, Validate)]
pub struct ChallengeVerificationRequest {
    #[validate(length(min = 1, message = "Challenge is required"))]
    #[validate(custom(function = "crate::utils::validation::validate_base64url"))]
    pub challenge: String,

    #[serde(rename = "challengeType")]
    pub challenge_type: String,
}

/// Relying party information
#[derive(Debug, Serialize)]
pub struct RelyingParty {
    pub name: String,
    pub id: String,
}

/// User information for WebAuthn
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

/// Authenticator selection criteria
#[derive(Debug, Serialize, Deserialize, Validate)]
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