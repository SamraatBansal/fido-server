use crate::db::models::{NewUser, User};
use crate::db::repositories::UserRepository;
use crate::error::{AppError, Result};
use rand::Rng;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone)]
pub struct UserService {
    repository: Arc<UserRepository>,
}

impl UserService {
    pub fn new(repository: UserRepository) -> Self {
        Self {
            repository: Arc::new(repository),
        }
    }

    pub async fn create_user(&self, username: &str, display_name: &str) -> Result<User> {
        // Check if user already exists
        if self.repository.user_exists(username).await? {
            return Err(AppError::UserAlreadyExists {
                username: username.to_string(),
            });
        }

        // Generate WebAuthn user ID (random 64 bytes)
        let webauthn_user_id = crate::utils::crypto::generate_random_bytes(64);

        let new_user = NewUser {
            username: username.to_string(),
            display_name: display_name.to_string(),
            user_id: webauthn_user_id,
        };

        let user = self.repository.create_user(new_user).await?;
        Ok(user)
    }

    pub async fn get_user_by_username(&self, username: &str) -> Result<User> {
        self.repository
            .get_user_by_username(username)
            .await?
            .ok_or(AppError::UserNotFound {
                username: username.to_string(),
            })
    }

    pub async fn get_user_by_id(&self, user_id: Uuid) -> Result<User> {
        self.repository
            .get_user_by_id(user_id)
            .await?
            .ok_or(AppError::UserNotFound {
                username: format!("ID: {}", user_id),
            })
    }

    pub async fn get_user_by_webauthn_user_id(&self, webauthn_user_id: &[u8]) -> Result<Option<User>> {
        self.repository
            .get_user_by_webauthn_user_id(webauthn_user_id)
            .await
    }

    pub async fn find_or_create_user(&self, username: &str, display_name: &str) -> Result<User> {
        if let Ok(user) = self.get_user_by_username(username).await {
            // Update display name if it has changed
            if user.display_name != display_name {
                return self.update_user_display_name(user.id, display_name).await;
            }
            Ok(user)
        } else {
            self.create_user(username, display_name).await
        }
    }

    pub async fn update_user_display_name(&self, user_id: Uuid, display_name: &str) -> Result<User> {
        self.repository
            .update_user_display_name(user_id, display_name)
            .await
    }

    pub async fn deactivate_user(&self, user_id: Uuid) -> Result<()> {
        self.repository.deactivate_user(user_id).await
    }

    pub async fn user_exists(&self, username: &str) -> Result<bool> {
        self.repository.user_exists(username).await
    }

    pub fn generate_webauthn_user_id(&self) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let user_id: [u8; 64] = rng.gen();
        user_id.to_vec()
    }

    pub fn encode_user_id(&self, user_id: &[u8]) -> String {
        base64::encode_config(user_id, base64::URL_SAFE_NO_PAD)
    }

    pub fn decode_user_id(&self, encoded_user_id: &str) -> Result<Vec<u8>> {
        base64::decode_config(encoded_user_id, base64::URL_SAFE_NO_PAD)
            .map_err(|_| AppError::validation("Invalid user ID encoding"))
    }
}