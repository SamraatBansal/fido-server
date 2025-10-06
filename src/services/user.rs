//! User management service

use std::sync::Arc;
use uuid::Uuid;

use crate::db::models::{User, NewUser};
use crate::db::repositories::UserRepository;
use crate::error::{AppError, Result};

/// User service for managing user accounts
pub struct UserService {
    user_repo: Arc<dyn UserRepository>,
}

impl UserService {
    /// Create a new user service
    pub fn new(user_repo: Arc<dyn UserRepository>) -> Self {
        Self { user_repo }
    }

    /// Create a new user
    pub async fn create_user(&self, new_user: &NewUser) -> Result<User> {
        // Check if user already exists
        if let Some(_) = self.user_repo.find_by_username(&new_user.username).await? {
            return Err(AppError::InvalidRequest("User already exists".to_string()));
        }

        self.user_repo.create_user(new_user).await
    }

    /// Get user by username
    pub async fn get_user_by_username(&self, username: &str) -> Result<Option<User>> {
        self.user_repo.find_by_username(username).await
    }

    /// Get user by ID
    pub async fn get_user_by_id(&self, user_id: &Uuid) -> Result<Option<User>> {
        self.user_repo.find_by_id(user_id).await
    }

    /// Update user information
    pub async fn update_user(&self, user_id: &Uuid, user_data: &NewUser) -> Result<User> {
        self.user_repo.update_user(user_id, user_data).await
    }

    /// Delete a user
    pub async fn delete_user(&self, user_id: &Uuid) -> Result<()> {
        self.user_repo.delete_user(user_id).await
    }
}