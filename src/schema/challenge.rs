//! Challenge-related schemas

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Challenge data stored in memory/database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeData {
    pub id: Uuid,
    pub challenge: String,
    pub user_id: Option<Uuid>,
    pub challenge_type: ChallengeType,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Challenge type enumeration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChallengeType {
    Registration,
    Authentication,
}

/// Challenge response wrapper
#[derive(Debug, Serialize)]
pub struct ChallengeResponse {
    pub challenge_id: Uuid,
    pub challenge: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}
