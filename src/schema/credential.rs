//! Credential-related request/response schemas

use serde::{Deserialize, Serialize};
use validator::Validate;

/// Credential information response
#[derive(Debug, Serialize)]
pub struct CredentialResponse {
    #[serde(rename = "credentialId")]
    pub credential_id: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    pub aaguid: String,
    #[serde(rename = "signCount")]
    pub sign_count: u64,
    #[serde(rename = "userVerified")]
    pub user_verified: bool,
    #[serde(rename = "backupEligible")]
    pub backup_eligible: bool,
    #[serde(rename = "backupState")]
    pub backup_state: bool,
    #[serde(rename = "attestationType")]
    pub attestation_type: String,
    pub transports: Vec<String>,
    #[serde(rename = "lastUsedAt")]
    pub last_used_at: Option<String>,
}

/// Credential list response
#[derive(Debug, Serialize)]
pub struct CredentialListResponse {
    pub credentials: Vec<CredentialResponse>,
    pub count: usize,
}

/// Allow credential for authentication
#[derive(Debug, Serialize)]
pub struct AllowCredential {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub id: String,
    pub transports: Vec<String>,
}