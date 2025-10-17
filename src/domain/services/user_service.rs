//! User service for user management

use crate::domain::repositories::{User, UserRepository};
use crate::error::Result;
use async_trait::async_trait;
use std::sync::Arc;
use uuid::Uuid;

#[async_trait]
pub trait UserService: Send + Sync {
    async fn get_or_create_user(&self, username: &str, display_name: &str) -> Result<User>;
    async fn find_user(&self, username: &str) -> Result<Option<User>>;
}

pub struct UserServiceImpl {
    repository: Arc<dyn UserRepository>,
}

impl UserServiceImpl {
    pub fn new(repository: Arc<dyn UserRepository>) -> Self {
        Self { repository }
    }
}

#[async_trait]
impl UserService for UserServiceImpl {
    async fn get_or_create_user(&self, username: &str, display_name: &str) -> Result<User> {
        match self.repository.find_by_username(username).await? {
            Some(user) => Ok(user),
            None => {
                let new_user = User {
                    id: Uuid::new_v4().to_string(),
                    username: username.to_string(),
                    display_name: display_name.to_string(),
                    created_at: chrono::Utc::now(),
                };
                self.repository.create_user(&new_user).await?;
                Ok(new_user)
            }
        }
    }

    async fn find_user(&self, username: &str) -> Result<Option<User>> {
        self.repository.find_by_username(username).await
    }
}