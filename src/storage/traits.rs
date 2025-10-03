use async_trait::async_trait;
use std::sync::Arc;
use crate::error::Result;
use crate::webauthn::types::*;
use uuid::Uuid;

#[async_trait]
pub trait Storage: Send + Sync {
    async fn create_user(&self, user: User) -> Result<User>;
    async fn get_user(&self, user_id: Uuid) -> Result<Option<User>>;
    async fn get_user_by_name(&self, username: &str) -> Result<Option<User>>;
    async fn update_user(&self, user: User) -> Result<User>;
    async fn delete_user(&self, user_id: Uuid) -> Result<bool>;

    async fn create_credential(&self, credential: Credential) -> Result<Credential>;
    async fn get_credential(&self, credential_id: &str) -> Result<Option<Credential>>;
    async fn get_credentials_by_user(&self, user_id: Uuid) -> Result<Vec<Credential>>;
    async fn update_credential(&self, credential: Credential) -> Result<Credential>;
    async fn delete_credential(&self, credential_id: &str) -> Result<bool>;

    async fn create_mapping(&self, mapping: UserMapping) -> Result<UserMapping>;
    async fn get_mapping(&self, mapping_id: Uuid) -> Result<Option<UserMapping>>;
    async fn get_mapping_by_credential(&self, credential_id: &str) -> Result<Option<UserMapping>>;
    async fn get_mappings_by_user(&self, user_id: Uuid) -> Result<Vec<UserMapping>>;
    async fn get_mapping_by_external(&self, external_id: &str, external_type: &str) -> Result<Option<UserMapping>>;
    async fn delete_mapping(&self, mapping_id: Uuid) -> Result<bool>;

    async fn store_registration_challenge(&self, challenge: RegistrationChallenge) -> Result<()>;
    async fn get_registration_challenge(&self, user_id: Uuid) -> Result<Option<RegistrationChallenge>>;
    async fn delete_registration_challenge(&self, user_id: Uuid) -> Result<bool>;

    async fn store_authentication_challenge(&self, challenge: AuthenticationChallenge) -> Result<()>;
    async fn get_authentication_challenge(&self, user_id: Option<Uuid>, credential_id: Option<String>) -> Result<Option<AuthenticationChallenge>>;
    async fn delete_authentication_challenge(&self, user_id: Option<Uuid>, credential_id: Option<String>) -> Result<bool>;
}

pub type StorageArc = Arc<dyn Storage>;