//! Authentication schemas

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Start authentication request
#[derive(Debug, Deserialize, Serialize)]
pub struct AuthenticationStartRequest {
    pub username: Option<String>,
    pub user_verification: Option<String>,
    pub origin: Option<String>,
}

/// Finish authentication request
#[derive(Debug, Deserialize, Serialize)]
pub struct AuthenticationFinishRequest {
    pub challenge_id: Uuid,
    pub credential: serde_json::Value,
}

/// Start registration request
#[derive(Debug, Deserialize, Serialize)]
pub struct RegistrationStartRequest {
    pub username: String,
    pub display_name: String,
    pub user_verification: Option<String>,
    pub attestation: Option<String>,
    pub origin: Option<String>,
}

/// Finish registration request
#[derive(Debug, Deserialize, Serialize)]
pub struct RegistrationFinishRequest {
    pub challenge_id: Uuid,
    pub credential: serde_json::Value,
}