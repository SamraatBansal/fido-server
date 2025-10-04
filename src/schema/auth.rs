//! Authentication request and response schemas

use serde::{Deserialize, Serialize};
use validator::Validate;
use crate::schema::common::UserVerificationPolicy;

/// Request to start authentication
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct AuthenticationStartRequest {
    /// Username (optional for usernameless authentication)
    #[validate(length(min = 1, max = 255))]
    pub username: Option<String>,
    /// User verification preference
    #[serde(default)]
    pub user_verification: UserVerificationPolicy,
    /// Origin URL (for validation)
    #[validate(url)]
    pub origin: Option<String>,
    /// Additional extensions
    #[serde(default)]
    pub extensions: serde_json::Value,
}

/// Response for authentication start
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationStartResponse {
    /// Challenge ID for verification
    pub challenge_id: uuid::Uuid,
    /// Public key credential request options
    pub public_key: webauthn_rs::prelude::PublicKeyCredentialRequestOptions,
}

/// Request to finish authentication
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct AuthenticationFinishRequest {
    /// Challenge ID from start response
    #[validate(uuid)]
    pub challenge_id: uuid::Uuid,
    /// Credential from authenticator
    pub credential: AuthenticationCredential,
}

/// Authentication credential from authenticator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationCredential {
    pub id: String,
    pub raw_id: String,
    pub response: AuthenticatorAssertionResponse,
    pub authenticator_attachment: Option<String>,
    pub client_extension_results: serde_json::Value,
    pub type_: String,
}

/// Authenticator assertion response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorAssertionResponse {
    pub client_data_json: String,
    pub authenticator_data: String,
    pub signature: String,
    pub user_handle: Option<String>,
}

/// Response for successful authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationFinishResponse {
    /// User ID
    pub user_id: uuid::Uuid,
    /// Session token
    pub session_token: String,
    /// Authentication timestamp
    pub authenticated_at: chrono::DateTime<chrono::Utc>,
    /// Authenticator information
    pub authenticator_info: AuthenticationAuthenticatorInfo,
}

/// Authenticator information for authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationAuthenticatorInfo {
    /// Signature counter
    pub sign_count: u32,
    /// Whether clone warning is active
    pub clone_warning: bool,
    /// Credential ID
    pub credential_id: String,
}

/// Session validation request
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct SessionValidationRequest {
    /// Session token to validate
    #[validate(length(min = 1))]
    pub session_token: String,
}

/// Session validation response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionValidationResponse {
    /// Whether session is valid
    pub valid: bool,
    /// User ID (if valid)
    pub user_id: Option<uuid::Uuid>,
    /// Session expires at (if valid)
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Last accessed at (if valid)
    pub last_accessed_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Logout request
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct LogoutRequest {
    /// Session token to invalidate
    #[validate(length(min = 1))]
    pub session_token: String,
}

/// Logout response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogoutResponse {
    /// Whether logout was successful
    pub success: bool,
    /// Message
    pub message: String,
}