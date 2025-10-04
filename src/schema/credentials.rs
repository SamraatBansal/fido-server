//! Credential management request and response schemas

use serde::{Deserialize, Serialize};
use validator::Validate;
use crate::schema::common::{PaginationParams, PaginatedResponse};

/// Request to list user credentials
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct ListCredentialsRequest {
    /// Pagination parameters
    #[serde(flatten)]
    pub pagination: PaginationParams,
}

/// Response for listing credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListCredentialsResponse {
    pub credentials: Vec<CredentialInfo>,
    pub pagination: crate::schema::common::PaginationInfo,
}

/// Credential information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialInfo {
    /// Credential ID
    pub id: uuid::Uuid,
    /// Credential ID string
    pub credential_id: String,
    /// Creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Last used timestamp
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Signature counter
    pub sign_count: i64,
    /// AAGUID of authenticator
    pub aaguid: Option<String>,
    /// Backup eligible
    pub backup_eligible: bool,
    /// Backup state
    pub backup_state: bool,
    /// Clone warning
    pub clone_warning: bool,
    /// Authenticator attachment
    pub authenticator_attachment: Option<String>,
}

/// Request to delete a credential
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct DeleteCredentialRequest {
    /// Credential ID to delete
    #[validate(uuid)]
    pub credential_id: uuid::Uuid,
}

/// Response for credential deletion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteCredentialResponse {
    /// Whether deletion was successful
    pub success: bool,
    /// Message
    pub message: String,
}

/// Request to update credential metadata
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct UpdateCredentialRequest {
    /// Credential ID to update
    #[validate(uuid)]
    pub credential_id: uuid::Uuid,
    /// New display name (optional)
    #[validate(length(min = 1, max = 255))]
    pub display_name: Option<String>,
    /// New metadata (optional)
    pub metadata: Option<serde_json::Value>,
}

/// Response for credential update
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateCredentialResponse {
    /// Updated credential information
    pub credential: CredentialInfo,
    /// Message
    pub message: String,
}

/// Request to get credential details
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct GetCredentialRequest {
    /// Credential ID to get
    #[validate(uuid)]
    pub credential_id: uuid::Uuid,
}

/// Response for credential details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetCredentialResponse {
    /// Credential information
    pub credential: CredentialInfo,
    /// Additional details
    pub details: CredentialDetails,
}

/// Additional credential details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialDetails {
    /// Attestation statement (if available)
    pub attestation_statement: Option<serde_json::Value>,
    /// Public key details
    pub public_key: serde_json::Value,
    /// Usage statistics
    pub usage_stats: CredentialUsageStats,
}

/// Credential usage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialUsageStats {
    /// Total usage count
    pub total_uses: i64,
    /// First used timestamp
    pub first_used_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Last used timestamp
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Average time between uses (in hours)
    pub avg_usage_interval_hours: Option<f64>,
}