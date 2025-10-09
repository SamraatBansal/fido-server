//! Credential-related request/response schemas

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Credential response
#[derive(Debug, Serialize)]
pub struct CredentialResponse {
    pub id: Uuid,
    pub credential_id: String,
    pub attestation_type: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Registration result
#[derive(Debug, Serialize)]
pub struct RegistrationResult {
    pub credential_id: String,
    pub user_id: Uuid,
}

/// Authentication result
#[derive(Debug, Serialize)]
pub struct AuthenticationResult {
    pub authenticated: bool,
    pub user_id: Uuid,
    pub credential_id: String,
}