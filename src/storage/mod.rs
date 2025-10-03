use crate::config::Config;
use crate::error::{AppError, Result};
use crate::models::*;
use async_trait::async_trait;
use chrono::Utc;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::collections::HashMap;
use uuid::Uuid;

pub mod inmemory;
pub mod postgres;

#[async_trait]
pub trait Storage: Send + Sync {
    async fn create_user(&self, username: &str, display_name: &str) -> Result<User>;
    async fn get_user_by_id(&self, user_id: Uuid) -> Result<Option<User>>;
    async fn get_user_by_username(&self, username: &str) -> Result<Option<User>>;
    async fn update_user(&self, user: &User) -> Result<User>;
    async fn delete_user(&self, user_id: Uuid) -> Result<()>;

    async fn create_credential(&self, credential: &Credential) -> Result<Credential>;
    async fn get_credential_by_id(&self, credential_id: &[u8]) -> Result<Option<Credential>>;
    async fn get_credentials_by_user(&self, user_id: Uuid) -> Result<Vec<Credential>>;
    async fn update_credential(&self, credential: &Credential) -> Result<Credential>;
    async fn revoke_credential(&self, credential_id: &[u8]) -> Result<()>;
    async fn delete_credential(&self, credential_id: &[u8]) -> Result<()>;

    async fn create_mapping(&self, mapping: &UserMapping) -> Result<UserMapping>;
    async fn get_mapping_by_id(&self, mapping_id: Uuid) -> Result<Option<UserMapping>>;
    async fn get_mapping_by_external_id(&self, external_id: &str, external_type: &str) -> Result<Option<UserMapping>>;
    async fn get_mapping_by_credential(&self, credential_id: &[u8]) -> Result<Option<UserMapping>>;
    async fn get_mappings_by_user(&self, user_id: Uuid) -> Result<Vec<UserMapping>>;
    async fn update_mapping(&self, mapping: &UserMapping) -> Result<UserMapping>;
    async fn delete_mapping(&self, mapping_id: Uuid) -> Result<()>;

    async fn store_registration_challenge(&self, challenge: &RegistrationChallenge) -> Result<()>;
    async fn get_registration_challenge(&self, user_id: Uuid) -> Result<Option<RegistrationChallenge>>;
    async fn delete_registration_challenge(&self, user_id: Uuid) -> Result<()>;

    async fn store_authentication_challenge(&self, challenge: &AuthenticationChallenge) -> Result<()>;
    async fn get_authentication_challenge(&self, challenge_str: &str) -> Result<Option<AuthenticationChallenge>>;
    async fn delete_authentication_challenge(&self, challenge_str: &str) -> Result<()>;
}

pub async fn create_storage(config: &Config) -> Result<Box<dyn Storage>> {
    match config.database_url.as_str() {
        url if url.starts_with("postgresql://") => {
            let pool = PgPoolOptions::new()
                .max_connections(10)
                .connect(&config.database_url)
                .await?;
            
            // Run migrations
            sqlx::migrate!("./migrations").run(&pool).await?;
            
            Ok(Box::new(postgres::PostgresStorage::new(pool)))
        }
        _ => Ok(Box::new(inmemory::InMemoryStorage::new())),
    }
}