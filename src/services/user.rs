//! User management service

use std::sync::Arc;
use uuid::Uuid;

use crate::db::models::{NewUser, User};
use crate::db::repositories::UserRepository;
use crate::error::{AppError, Result};

pub struct UserService {
    user_repo: Arc<dyn UserRepository>,
}

impl UserService {
    pub fn new(user_repo: Arc<dyn UserRepository>) -> Self {
        Self { user_repo }
    }

    /// Get existing user or create new one
    pub async fn get_or_create_user(&self, username: &str, display_name: &str) -> Result<User> {
        // Try to find existing user
        if let Some(user) = self.user_repo.find_by_username(username).await? {
            return Ok(user);
        }

        // Create new user
        let new_user = NewUser {
            username: username.to_string(),
            display_name: display_name.to_string(),
        };

        self.user_repo.create_user(&new_user).await
    }

    /// Get user by username
    pub async fn get_user_by_username(&self, username: &str) -> Result<Option<User>> {
        self.user_repo.find_by_username(username).await
    }

    /// Get user by ID
    pub async fn get_user_by_id(&self, id: &Uuid) -> Result<Option<User>> {
        self.user_repo.find_by_id(id).await
    }

    /// Update user
    pub async fn update_user(&self, id: &Uuid, username: &str, display_name: &str) -> Result<User> {
        let new_user = NewUser {
            username: username.to_string(),
            display_name: display_name.to_string(),
        };

        self.user_repo.update_user(id, &new_user).await
    }

    /// Delete user
    pub async fn delete_user(&self, id: &Uuid) -> Result<()> {
        self.user_repo.delete_user(id).await
    }
}