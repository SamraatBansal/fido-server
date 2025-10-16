//! WebAuthn service for handling FIDO2 operations

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::error::AppError;

/// In-memory storage for challenges and credentials (for demo purposes)
/// In production, this should be replaced with proper database storage
type ChallengeStore = Arc<RwLock<HashMap<String, ChallengeData>>>;
type CredentialStore = Arc<RwLock<HashMap<String, CredentialData>>>;

#[derive(Debug, Clone)]
struct ChallengeData {
    challenge: Vec<u8>,
    username: String,
    expires_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
struct CredentialData {
    credential_id: Vec<u8>,
    public_key: Vec<u8>,
    username: String,
    sign_count: u64,
}

/// WebAuthn service
#[derive(Debug, Clone)]
pub struct WebAuthnService {
    challenges: ChallengeStore,
    credentials: CredentialStore,
}

impl WebAuthnService {
    /// Create a new WebAuthn service
    pub fn new() -> Result<Self, AppError> {
        Ok(Self {
            challenges: Arc::new(RwLock::new(HashMap::new())),
            credentials: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Generate registration challenge
    pub async fn generate_registration_challenge(
        &self,
        username: &str,
        display_name: &str,
        _origin: String,
    ) -> Result<(Vec<u8>, Uuid), AppError> {
        // Create user ID
        let user_id = Uuid::new_v4();

        // Generate challenge
        let challenge = vec![1, 2, 3, 4]; // Simple challenge for demo

        // Store challenge
        let challenge_id = Uuid::new_v4().to_string();
        let challenge_data = ChallengeData {
            challenge: challenge.clone(),
            username: username.to_string(),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
        };

        let mut challenges = self.challenges.write().await;
        challenges.insert(challenge_id, challenge_data);

        // Store user credential placeholder
        let mut credentials = self.credentials.write().await;
        credentials.insert(
            username.to_string(),
            CredentialData {
                credential_id: Vec::new(), // Will be set after registration
                public_key: Vec::new(),    // Will be set after registration
                username: username.to_string(),
                sign_count: 0,
            },
        );

        Ok((challenge, user_id))
    }

    /// Verify registration attestation
    pub async fn verify_registration(
        &self,
        credential_id: &str,
        _origin: String,
    ) -> Result<(), AppError> {
        // For this demo, we'll just mark the registration as successful
        // In a real implementation, you would verify the attestation
        
        // Store the credential
        let mut credentials = self.credentials.write().await;
        
        // Find and update the user credential (this is a simplified approach)
        for (_, cred_data) in credentials.iter_mut() {
            if cred_data.credential_id.is_empty() {
                cred_data.credential_id = credential_id.as_bytes().to_vec();
                cred_data.public_key = vec![1, 2, 3, 4]; // Placeholder
                break;
            }
        }

        Ok(())
    }

    /// Generate authentication challenge
    pub async fn generate_authentication_challenge(
        &self,
        username: &str,
        _origin: String,
    ) -> Result<(Vec<u8>, Vec<Vec<u8>>), AppError> {
        // Get user credentials
        let credentials = self.credentials.read().await;
        let user_credentials: Vec<Vec<u8>> = credentials
            .values()
            .filter(|cred| cred.username == username)
            .map(|cred| cred.credential_id.clone())
            .collect();

        if user_credentials.is_empty() {
            return Err(AppError::UserNotFound(username.to_string()));
        }

        // Generate challenge
        let challenge = vec![1, 2, 3, 4]; // Simple challenge for demo

        // Store challenge
        let challenge_id = Uuid::new_v4().to_string();
        let challenge_data = ChallengeData {
            challenge: challenge.clone(),
            username: username.to_string(),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
        };

        let mut challenges = self.challenges.write().await;
        challenges.insert(challenge_id, challenge_data);

        Ok((challenge, user_credentials))
    }

    /// Verify authentication assertion
    pub async fn verify_authentication(
        &self,
        credential_id: &str,
        _origin: String,
    ) -> Result<(), AppError> {
        // For this demo, we'll just mark the authentication as successful
        // In a real implementation, you would verify the assertion

        // Update sign count (simplified)
        let mut credentials = self.credentials.write().await;
        
        for cred_data in credentials.values_mut() {
            if cred_data.credential_id == credential_id.as_bytes() {
                cred_data.sign_count += 1;
                break;
            }
        }

        Ok(())
    }
}

impl Default for WebAuthnService {
    fn default() -> Self {
        Self::new().expect("Failed to create WebAuthn service")
    }
}