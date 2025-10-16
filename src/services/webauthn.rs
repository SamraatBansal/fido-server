//! WebAuthn service for handling FIDO2 operations

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use webauthn_rs::prelude::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

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
    webauthn: Arc<Webauthn>,
    challenges: ChallengeStore,
    credentials: CredentialStore,
}

impl WebAuthnService {
    /// Create a new WebAuthn service
    pub fn new() -> Result<Self, AppError> {
        let rp_name = "Example Corporation";
        let rp_id = "localhost";
        let rp_origin = "http://localhost:3000";

        let builder = WebauthnBuilder::new(rp_id, &Url::parse(rp_origin).map_err(|e| {
            AppError::Configuration(format!("Invalid origin URL: {}", e))
        })?)
        .map_err(|e| AppError::Configuration(format!("Failed to create WebAuthn: {}", e)))?;

        let webauthn = builder.build();

        Ok(Self {
            webauthn,
            challenges: Arc::new(RwLock::new(HashMap::new())),
            credentials: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Generate registration challenge
    pub async fn generate_registration_challenge(
        &self,
        username: &str,
        display_name: &str,
        origin: String,
    ) -> Result<(Vec<u8>, Uuid), AppError> {
        // Create user
        let user_id = Uuid::new_v4();
        let user = webauthn_rs::proto::User {
            id: user_id.as_bytes().to_vec(),
            name: username.to_string(),
            display_name: display_name.to_string(),
        };

        // Generate challenge
        let challenge = self
            .webauthn
            .generate_challenge();

        // Store challenge
        let challenge_id = Uuid::new_v4().to_string();
        let challenge_data = ChallengeData {
            challenge: challenge.clone(),
            username: username.to_string(),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
        };

        let mut challenges = self.challenges.write().await;
        challenges.insert(challenge_id, challenge_data);

        // Store state for verification
        // In a real implementation, this should be stored securely
        let mut credentials = self.credentials.write().await;
        credentials.insert(
            base64::encode_config(&user.id, base64::URL_SAFE_NO_PAD),
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
        credential: &PublicKeyCredential,
        origin: String,
    ) -> Result<(), AppError> {
        // For this demo, we'll skip the actual verification
        // In a real implementation, you would:
        // 1. Retrieve the stored challenge state
        // 2. Verify the attestation
        // 3. Store the credential

        // Store the credential
        let credential_id = base64::encode_config(&credential.raw_id, base64::URL_SAFE_NO_PAD);
        let mut credentials = self.credentials.write().await;
        
        // Find the user credential (this is a simplified approach)
        for (_, cred_data) in credentials.iter_mut() {
            if cred_data.credential_id.is_empty() {
                cred_data.credential_id = credential.raw_id.to_vec();
                // Extract public key from attestation (simplified)
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
        origin: String,
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
        let challenge = self
            .webauthn
            .generate_challenge();

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
        credential: &PublicKeyCredential,
        origin: String,
    ) -> Result<(), AppError> {
        // For this demo, we'll skip the actual verification
        // In a real implementation, you would:
        // 1. Retrieve the stored challenge state
        // 2. Verify the assertion
        // 3. Update the sign count

        // Update sign count (simplified)
        let credential_id = base64::encode_config(&credential.raw_id, base64::URL_SAFE_NO_PAD);
        let mut credentials = self.credentials.write().await;
        
        for cred_data in credentials.values_mut() {
            if cred_data.credential_id == credential.raw_id {
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