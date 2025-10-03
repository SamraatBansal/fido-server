//! User-related request/response schemas

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// User creation request
#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub display_name: String,
}

/// User response
#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// User mapping request
#[derive(Debug, Deserialize)]
pub struct CreateUserMappingRequest {
    pub external_id: String,
    pub credential_id: String,
}

/// User mapping response
#[derive(Debug, Serialize)]
pub struct UserMappingResponse {
    pub id: Uuid,
    pub external_id: String,
    pub credential_id: String,
    pub user_id: Uuid,
    pub created_at: chrono::DateTime<chrono::Utc>,
}