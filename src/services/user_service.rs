//! User service implementation

use std::sync::Arc;
use crate::db::repositories::UserRepository;
use crate::models::User;
use crate::error::{AppError, Result};

/// User service
pub struct UserService {
    user_repo: Arc<dyn UserRepository>,
}

impl UserService {
    /// Create a new user service
    pub fn new(user_repo: Arc<dyn UserRepository>) -> Self {
        Self { user_repo }
    }

    /// Get user by username
    pub async fn get_user_by_username(&self, username: &str) -> Result<Option<User>> {
        self.user_repo.get_user_by_username(username).await
    }

    /// Get user by ID
    pub async fn get_user_by_id(&self, user_id: uuid::Uuid) -> Result<Option<User>> {
        self.user_repo.get_user_by_id(user_id).await
    }

    /// Create user
    pub async fn create_user(&self, username: &str, display_name: &str) -> Result<User> {
        // Validate input
        if username.trim().is_empty() {
            return Err(AppError::InvalidInput("Username is required".to_string()));
        }
        if display_name.trim().is_empty() {
            return Err(AppError::InvalidInput("Display name is required".to_string()));
        }
        if username.len() > 255 {
            return Err(AppError::InvalidInput("Username too long".to_string()));
        }
        if display_name.len() > 255 {
            return Err(AppError::InvalidInput("Display name too long".to_string()));
        }

        // Check if user already exists
        if self.user_repo.get_user_by_username(username).await?.is_some() {
            return Err(AppError::InvalidInput("User already exists".to_string()));
        }

        self.user_repo.create_user(username, display_name).await
    }

    /// Update user
    pub async fn update_user(&self, user: &User) -> Result<()> {
        self.user_repo.update_user(user).await
    }

    /// Delete user
    pub async fn delete_user(&self, user_id: uuid::Uuid) -> Result<()> {
        self.user_repo.delete_user(user_id).await
    }
}