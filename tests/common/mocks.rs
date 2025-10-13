//! Mock implementations for testing

use mockall::mock;
use async_trait::async_trait;

// Mock WebAuthn Service
mock! {
    pub WebAuthnService {}

    #[async_trait]
    impl WebAuthnServiceTrait for WebAuthnService {
        async fn generate_registration_challenge(
            &self,
            username: &str,
            display_name: &str,
        ) -> Result<serde_json::Value, Box<dyn std::error::Error>>;

        async fn verify_registration(
            &self,
            credential: serde_json::Value,
        ) -> Result<serde_json::Value, Box<dyn std::error::Error>>;

        async fn generate_authentication_challenge(
            &self,
            username: &str,
        ) -> Result<serde_json::Value, Box<dyn std::error::Error>>;

        async fn verify_authentication(
            &self,
            assertion: serde_json::Value,
        ) -> Result<serde_json::Value, Box<dyn std::error::Error>>;
    }
}

// Mock Challenge Store
mock! {
    pub ChallengeStore {}

    #[async_trait]
    impl ChallengeStoreTrait for ChallengeStore {
        async fn store_challenge(
            &self,
            challenge_id: &str,
            username: &str,
            challenge_data: &[u8],
            expires_at: chrono::DateTime<chrono::Utc>,
        ) -> Result<(), Box<dyn std::error::Error>>;

        async fn get_and_validate_challenge(
            &self,
            challenge_id: &str,
        ) -> Result<Vec<u8>, Box<dyn std::error::Error>>;

        async fn invalidate_challenge(
            &self,
            challenge_id: &str,
        ) -> Result<(), Box<dyn std::error::Error>>;
    }
}

// Mock Credential Store
mock! {
    pub CredentialStore {}

    #[async_trait]
    impl CredentialStoreTrait for CredentialStore {
        async fn store_credential(
            &self,
            credential: serde_json::Value,
        ) -> Result<(), Box<dyn std::error::Error>>;

        async fn get_user_credentials(
            &self,
            username: &str,
        ) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>>;

        async fn get_credential_by_id(
            &self,
            credential_id: &str,
        ) -> Result<Option<serde_json::Value>, Box<dyn std::error::Error>>;

        async fn update_credential(
            &self,
            credential_id: &str,
            update_data: serde_json::Value,
        ) -> Result<(), Box<dyn std::error::Error>>;
    }
}

// Trait definitions for mocks
#[async_trait]
pub trait WebAuthnServiceTrait: Send + Sync {
    async fn generate_registration_challenge(
        &self,
        username: &str,
        display_name: &str,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>>;

    async fn verify_registration(
        &self,
        credential: serde_json::Value,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>>;

    async fn generate_authentication_challenge(
        &self,
        username: &str,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>>;

    async fn verify_authentication(
        &self,
        assertion: serde_json::Value,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>>;
}

#[async_trait]
pub trait ChallengeStoreTrait: Send + Sync {
    async fn store_challenge(
        &self,
        challenge_id: &str,
        username: &str,
        challenge_data: &[u8],
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), Box<dyn std::error::Error>>;

    async fn get_and_validate_challenge(
        &self,
        challenge_id: &str,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>>;

    async fn invalidate_challenge(
        &self,
        challenge_id: &str,
    ) -> Result<(), Box<dyn std::error::Error>>;
}

#[async_trait]
pub trait CredentialStoreTrait: Send + Sync {
    async fn store_credential(
        &self,
        credential: serde_json::Value,
    ) -> Result<(), Box<dyn std::error::Error>>;

    async fn get_user_credentials(
        &self,
        username: &str,
    ) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>>;

    async fn get_credential_by_id(
        &self,
        credential_id: &str,
    ) -> Result<Option<serde_json::Value>, Box<dyn std::error::Error>>;

    async fn update_credential(
        &self,
        credential_id: &str,
        update_data: serde_json::Value,
    ) -> Result<(), Box<dyn std::error::Error>>;
}