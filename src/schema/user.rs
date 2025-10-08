//! User-related request/response schemas

use serde::{Deserialize, Serialize};
use validator::Validate;

/// User registration request
#[derive(Debug, Deserialize, Validate)]
pub struct UserRegistrationRequest {
    #[validate(email(message = "Invalid email format"))]
    #[validate(length(min = 1, max = 255, message = "Username must be 1-255 characters"))]
    pub username: String,

    #[validate(length(min = 1, max = 255, message = "Display name must be 1-255 characters"))]
    #[serde(rename = "displayName")]
    pub display_name: String,
}

/// User response
#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: String,
    pub username: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
}

/// User lookup request
#[derive(Debug, Deserialize, Validate)]
pub struct UserLookupRequest {
    #[validate(email(message = "Invalid email format"))]
    pub username: String,
}