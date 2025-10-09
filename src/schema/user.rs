//! User-related request/response schemas

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

/// Request to create a new user
#[derive(Debug, Deserialize, Validate)]
pub struct CreateUserRequest {
    #[validate(length(min = 3, max = 255, message = "Username must be between 3 and 255 characters"))]
    #[validate(regex(path = "crate::utils::validation::USERNAME_REGEX"))]
    pub username: String,
    
    #[validate(length(min = 1, max = 255, message = "Display name must be between 1 and 255 characters"))]
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