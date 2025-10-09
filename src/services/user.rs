//! User service

use crate::error::{FidoError, FidoResult};
use crate::db::models::User;
use uuid::Uuid;

/// User service
pub struct UserService {
    // TODO: Add user repository
}

impl UserService {
    /// Create new user service
    pub fn new() -> Self {
        Self {}
    }

    /// Create a new user
    pub async fn create_user(&self, username: &str, display_name: &str) -> FidoResult<User> {
        // TODO: Implement user creation
        Err(FidoError::Internal("Not implemented".to_string()))
    }

    /// Find user by username
    pub async fn find_by_username(&self, username: &str) -> FidoResult<Option<User>> {
        // TODO: Implement user lookup
        Ok(None)
    }

    /// Find user by ID
    pub async fn find_by_id(&self, user_id: &Uuid) -> FidoResult<Option<User>> {
        // TODO: Implement user lookup by ID
        Ok(None)
    }
}