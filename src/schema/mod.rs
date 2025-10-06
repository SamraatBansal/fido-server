//! Request and Response DTOs for FIDO Server API

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// Registration start request
#[derive(Debug, Deserialize)]
pub struct RegistrationStartRequest {
    /// Username
    pub username: String,
    /// Display name
    pub display_name: String,
    /// User verification requirement
    pub user_verification: Option<String>,
    /// Attestation preference
    pub attestation: Option<String>,
    /// Resident key requirement
    pub resident_key: Option<String>,
    /// Authenticator attachment
    pub authenticator_attachment: Option<String>,
}

/// Registration start response
#[derive(Debug, Serialize)]
pub struct RegistrationStartResponse {
    /// Challenge
    pub challenge: String,
    /// User information
    pub user: User,
    /// Relying party information
    pub rp: RelyingParty,
    /// Public key credential parameters
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    /// Timeout in milliseconds
    pub timeout: u64,
    /// Attestation preference
    pub attestation: String,
    /// Authenticator selection
    pub authenticator_selection: AuthenticatorSelection,
    /// Extensions
    pub extensions: Option<serde_json::Value>,
}

/// Registration finish request
#[derive(Debug, Deserialize)]
pub struct RegistrationFinishRequest {
    /// Credential ID
    pub credential_id: String,
    /// Client data JSON
    pub client_data_json: String,
    /// Attestation object
    pub attestation_object: String,
    /// Transports
    pub transports: Option<Vec<String>>,
}

/// Registration finish response
#[derive(Debug, Serialize)]
pub struct RegistrationFinishResponse {
    /// Credential ID
    pub credential_id: String,
    /// Success status
    pub success: bool,
    /// User ID
    pub user_id: Uuid,
}

/// Authentication start request
#[derive(Debug, Deserialize)]
pub struct AuthenticationStartRequest {
    /// Username (optional for userless flows)
    pub username: Option<String>,
    /// User verification requirement
    pub user_verification: Option<String>,
}

/// Authentication start response
#[derive(Debug, Serialize)]
pub struct AuthenticationStartResponse {
    /// Challenge
    pub challenge: String,
    /// Timeout in milliseconds
    pub timeout: u64,
    /// Relying party ID
    pub rp_id: String,
    /// Allow credentials (for username-based flows)
    pub allow_credentials: Option<Vec<AllowCredential>>,
    /// User verification requirement
    pub user_verification: String,
    /// Extensions
    pub extensions: Option<serde_json::Value>,
}

/// Authentication finish request
#[derive(Debug, Deserialize)]
pub struct AuthenticationFinishRequest {
    /// Credential ID
    pub credential_id: String,
    /// Client data JSON
    pub client_data_json: String,
    /// Authenticator data
    pub authenticator_data: String,
    /// Signature
    pub signature: String,
    /// User handle
    pub user_handle: Option<String>,
}

/// Authentication finish response
#[derive(Debug, Serialize)]
pub struct AuthenticationFinishResponse {
    /// Success status
    pub success: bool,
    /// User information
    pub user: User,
    /// Credential information
    pub credential: CredentialInfo,
}

/// User information
#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    /// User ID
    pub id: Uuid,
    /// Username
    pub name: String,
    /// Display name
    pub display_name: String,
}

/// Relying party information
#[derive(Debug, Serialize)]
pub struct RelyingParty {
    /// Relying party ID
    pub id: String,
    /// Relying party name
    pub name: String,
}

/// Public key credential parameters
#[derive(Debug, Serialize)]
pub struct PublicKeyCredentialParameters {
    /// Type
    #[serde(rename = "type")]
    pub cred_type: String,
    /// Algorithm
    pub alg: i64,
}

/// Authenticator selection criteria
#[derive(Debug, Serialize)]
pub struct AuthenticatorSelection {
    /// Authenticator attachment
    pub authenticator_attachment: Option<String>,
    /// Require resident key
    pub require_resident_key: bool,
    /// Resident key requirement
    pub resident_key: String,
    /// User verification requirement
    pub user_verification: String,
}

/// Allow credential for authentication
#[derive(Debug, Serialize)]
pub struct AllowCredential {
    /// Credential ID
    pub id: String,
    /// Type
    #[serde(rename = "type")]
    pub cred_type: String,
    /// Transports
    pub transports: Option<Vec<String>>,
}

/// Credential information
#[derive(Debug, Serialize)]
pub struct CredentialInfo {
    /// Credential ID
    pub id: String,
    /// Type
    #[serde(rename = "type")]
    pub cred_type: String,
    /// Last used at
    pub last_used_at: Option<DateTime<Utc>>,
    /// Backup eligible
    pub backup_eligible: bool,
    /// Backup state
    pub backup_state: bool,
}

/// List credentials response
#[derive(Debug, Serialize)]
pub struct ListCredentialsResponse {
    /// Credentials
    pub credentials: Vec<CredentialInfo>,
    /// Total count
    pub total: usize,
}

/// Delete credential response
#[derive(Debug, Serialize)]
pub struct DeleteCredentialResponse {
    /// Success status
    pub success: bool,
    /// Message
    pub message: String,
}

/// Error response
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    /// Error code
    pub error: String,
    /// Error message
    pub message: String,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

impl ErrorResponse {
    /// Create new error response
    pub fn new(error: String, message: String) -> Self {
        Self {
            error,
            message,
            timestamp: Utc::now(),
        }
    }
}

/// Success response wrapper
#[derive(Debug, Serialize)]
pub struct SuccessResponse<T> {
    /// Success status
    pub success: bool,
    /// Data
    pub data: T,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

impl<T> SuccessResponse<T> {
    /// Create new success response
    pub fn new(data: T) -> Self {
        Self {
            success: true,
            data,
            timestamp: Utc::now(),
        }
    }
}