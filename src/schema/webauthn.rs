use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnConfig {
    pub rp_id: String,
    pub rp_name: String,
    pub rp_origin: String,
    pub timeout: u32,
    pub attestation_preference: String,
    pub user_verification: String,
}

impl From<crate::config::WebAuthnConfig> for WebAuthnConfig {
    fn from(config: crate::config::WebAuthnConfig) -> Self {
        Self {
            rp_id: config.rp_id,
            rp_name: config.rp_name,
            rp_origin: config.rp_origin,
            timeout: config.timeout,
            attestation_preference: config.attestation_preference,
            user_verification: config.user_verification,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionData {
    pub user_id: Option<Uuid>,
    pub username: Option<String>,
    pub challenge: Vec<u8>,
    pub session_type: SessionType,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionType {
    Registration,
    Authentication,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestContext {
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub session_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResult {
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub sign_count: u64,
    pub user_verified: bool,
    pub user_handle: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialCreationData {
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub aaguid: Option<Vec<u8>>,
    pub sign_count: u64,
    pub user_verified: bool,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub attestation_format: Option<String>,
    pub attestation_statement: Option<serde_json::Value>,
    pub transports: Option<Vec<String>>,
    pub is_resident: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEventData {
    pub action: String,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub success: bool,
    pub error_message: Option<String>,
    pub metadata: Option<serde_json::Value>,
}
