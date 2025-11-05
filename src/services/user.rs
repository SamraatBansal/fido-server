use chrono::Utc;

use std::sync::Arc;
use uuid::Uuid;

use crate::error::AppResult;
use crate::models::User;
use crate::storage::Storage;

pub struct UserService {
    storage: Arc<dyn Storage>,
}

impl UserService {
    pub fn new(storage: Arc<dyn Storage>) -> Self {
        Self { storage }
    }

    pub async fn get_or_create_user(&self, username: &str, display_name: &str) -> AppResult<User> {
        if let Some(user) = self.storage.get_user_by_username(username).await? {
            Ok(user)
        } else {
            self.create_user(username, display_name).await
        }
    }

    pub async fn get_user_by_username(&self, username: &str) -> AppResult<Option<User>> {
        self.storage.get_user_by_username(username).await
    }

    pub async fn get_user_by_id(&self, user_id: Uuid) -> AppResult<Option<User>> {
        self.storage.get_user_by_id(user_id).await
    }

    async fn create_user(&self, username: &str, display_name: &str) -> AppResult<User> {
        // Generate a random user ID for WebAuthn (must be unique per user)
        use rand::RngCore;
        let mut user_id = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut user_id);
        
        let user = User {
            id: Uuid::new_v4(),
            username: username.to_string(),
            display_name: display_name.to_string(),
            user_id: user_id.to_vec(),
            created_at: Utc::now(),
        };

        self.storage.create_user(user).await
    }
}