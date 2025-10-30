//! Repository traits and implementations

use async_trait::async_trait;
use std::sync::Arc;
use uuid::Uuid;
use crate::models::{User, Credential, StoredChallenge, ChallengeType};

/// User repository trait
#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn create_user(&self, username: &str, display_name: &str) -> crate::error::Result<User>;
    async fn get_user_by_username(&self, username: &str) -> crate::error::Result<Option<User>>;
    async fn get_user_by_id(&self, user_id: Uuid) -> crate::error::Result<Option<User>>;
    async fn update_user(&self, user: &User) -> crate::error::Result<()>;
    async fn delete_user(&self, user_id: Uuid) -> crate::error::Result<()>;
}

/// Credential repository trait
#[async_trait]
pub trait CredentialRepository: Send + Sync {
    async fn create_credential(&self, credential: &Credential) -> crate::error::Result<()>;
    async fn get_credential_by_id(&self, credential_id: &[u8]) -> crate::error::Result<Option<Credential>>;
    async fn get_credentials_for_user(&self, user_id: Uuid) -> crate::error::Result<Vec<Credential>>;
    async fn update_credential(&self, credential: &Credential) -> crate::error::Result<()>;
    async fn delete_credential(&self, credential_id: &[u8]) -> crate::error::Result<()>;
}

/// Challenge repository trait
#[async_trait]
pub trait ChallengeRepository: Send + Sync {
    async fn store_challenge(&self, challenge: &StoredChallenge) -> crate::error::Result<()>;
    async fn get_challenge(&self, challenge: &str, challenge_type: ChallengeType) -> crate::error::Result<Option<StoredChallenge>>;
    async fn consume_challenge(&self, challenge: &str, challenge_type: ChallengeType) -> crate::error::Result<Option<StoredChallenge>>;
    async fn cleanup_expired_challenges(&self) -> crate::error::Result<u64>;
}

/// Mock implementations for testing
#[cfg(test)]
pub mod mocks {
    use super::*;
    use std::collections::HashMap;
    use tokio::sync::Mutex;

    #[derive(Clone)]
    pub struct MockUserRepository {
        users: Arc<Mutex<HashMap<String, User>>>,
    }

    impl MockUserRepository {
        pub fn new() -> Self {
            Self {
                users: Arc::new(Mutex::new(HashMap::new())),
            }
        }
    }

    #[async_trait]
    impl UserRepository for MockUserRepository {
        async fn create_user(&self, username: &str, display_name: &str) -> crate::error::Result<User> {
            let mut users = self.users.lock().await;
            let user = User {
                id: Uuid::new_v4(),
                username: username.to_string(),
                display_name: display_name.to_string(),
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            };
            users.insert(username.to_string(), user.clone());
            Ok(user)
        }

        async fn get_user_by_username(&self, username: &str) -> crate::error::Result<Option<User>> {
            let users = self.users.lock().await;
            Ok(users.get(username).cloned())
        }

        async fn get_user_by_id(&self, user_id: Uuid) -> crate::error::Result<Option<User>> {
            let users = self.users.lock().await;
            Ok(users.values().find(|u| u.id == user_id).cloned())
        }

        async fn update_user(&self, user: &User) -> crate::error::Result<()> {
            let mut users = self.users.lock().await;
            users.insert(user.username.clone(), user.clone());
            Ok(())
        }

        async fn delete_user(&self, user_id: Uuid) -> crate::error::Result<()> {
            let mut users = self.users.lock().await;
            users.retain(|_, u| u.id != user_id);
            Ok(())
        }
    }

    #[derive(Clone)]
    pub struct MockCredentialRepository {
        credentials: Arc<Mutex<HashMap<Vec<u8>, Credential>>>,
    }

    impl MockCredentialRepository {
        pub fn new() -> Self {
            Self {
                credentials: Arc::new(Mutex::new(HashMap::new())),
            }
        }
    }

    #[async_trait]
    impl CredentialRepository for MockCredentialRepository {
        async fn create_credential(&self, credential: &Credential) -> crate::error::Result<()> {
            let mut credentials = self.credentials.lock().await;
            credentials.insert(credential.credential_id.clone(), credential.clone());
            Ok(())
        }

        async fn get_credential_by_id(&self, credential_id: &[u8]) -> crate::error::Result<Option<Credential>> {
            let credentials = self.credentials.lock().await;
            Ok(credentials.get(credential_id).cloned())
        }

        async fn get_credentials_for_user(&self, user_id: Uuid) -> crate::error::Result<Vec<Credential>> {
            let credentials = self.credentials.lock().await;
            Ok(credentials.values().filter(|c| c.user_id == user_id).cloned().collect())
        }

        async fn update_credential(&self, credential: &Credential) -> crate::error::Result<()> {
            let mut credentials = self.credentials.lock().await;
            credentials.insert(credential.credential_id.clone(), credential.clone());
            Ok(())
        }

        async fn delete_credential(&self, credential_id: &[u8]) -> crate::error::Result<()> {
            let mut credentials = self.credentials.lock().await;
            credentials.remove(credential_id);
            Ok(())
        }
    }

    #[derive(Clone)]
    pub struct MockChallengeRepository {
        challenges: Arc<Mutex<HashMap<String, StoredChallenge>>>,
    }

    impl MockChallengeRepository {
        pub fn new() -> Self {
            Self {
                challenges: Arc::new(Mutex::new(HashMap::new())),
            }
        }
    }

    #[async_trait]
    impl ChallengeRepository for MockChallengeRepository {
        async fn store_challenge(&self, challenge: &StoredChallenge) -> crate::error::Result<()> {
            let mut challenges = self.challenges.lock().await;
            challenges.insert(challenge.challenge.clone(), challenge.clone());
            Ok(())
        }

        async fn get_challenge(&self, challenge: &str, _challenge_type: ChallengeType) -> crate::error::Result<Option<StoredChallenge>> {
            let challenges = self.challenges.lock().await;
            Ok(challenges.get(challenge).cloned())
        }

        async fn consume_challenge(&self, challenge: &str, _challenge_type: ChallengeType) -> crate::error::Result<Option<StoredChallenge>> {
            let mut challenges = self.challenges.lock().await;
            Ok(challenges.remove(challenge))
        }

        async fn cleanup_expired_challenges(&self) -> crate::error::Result<u64> {
            let mut challenges = self.challenges.lock().await;
            let now = chrono::Utc::now();
            let initial_count = challenges.len();
            challenges.retain(|_, c| c.expires_at > now);
            Ok((initial_count - challenges.len()) as u64)
        }
    }
}