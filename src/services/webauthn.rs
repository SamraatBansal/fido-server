//! WebAuthn service implementation

use crate::error::{AppError, Result};
use crate::models::{
    ServerPublicKeyCredentialCreationOptionsRequest,
    ServerPublicKeyCredentialCreationOptionsResponse,
    ServerPublicKeyCredentialGetOptionsRequest,
    ServerPublicKeyCredentialGetOptionsResponse,
    RegistrationCompletionRequest,
    RegistrationCompletionResponse,
    AuthenticationCompletionRequest,
    AuthenticationCompletionResponse,
    PublicKeyCredentialRpEntity,
    ServerPublicKeyCredentialUserEntity,
    ServerResponse,
};
use base64::{Engine as _, engine::general_purpose};
use rand::{distributions::Alphanumeric, Rng};
use std::collections::HashMap;
use tokio::sync::RwLock;

/// WebAuthn service trait for testability
#[async_trait::async_trait]
pub trait WebAuthnService: Send + Sync {
    async fn generate_registration_challenge(
        &self,
        request: ServerPublicKeyCredentialCreationOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialCreationOptionsResponse>;

    async fn verify_registration(
        &self,
        request: RegistrationCompletionRequest,
    ) -> Result<RegistrationCompletionResponse>;

    async fn generate_authentication_challenge(
        &self,
        request: ServerPublicKeyCredentialGetOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialGetOptionsResponse>;

    async fn verify_authentication(
        &self,
        request: AuthenticationCompletionRequest,
    ) -> Result<AuthenticationCompletionResponse>;
}

/// In-memory WebAuthn service implementation
pub struct InMemoryWebAuthnService {
    challenges: RwLock<HashMap<String, ChallengeData>>,
    users: RwLock<HashMap<String, UserData>>,
    credentials: RwLock<HashMap<String, CredentialData>>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct ChallengeData {
    challenge: String,
    username: Option<String>,
    created_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct UserData {
    id: String,
    username: String,
    display_name: String,
    created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct CredentialData {
    id: String,
    user_id: String,
    credential_id: String,
    public_key: Vec<u8>,
    sign_count: u32,
    created_at: chrono::DateTime<chrono::Utc>,
}

impl InMemoryWebAuthnService {
    pub fn new() -> Self {
        Self {
            challenges: RwLock::new(HashMap::new()),
            users: RwLock::new(HashMap::new()),
            credentials: RwLock::new(HashMap::new()),
        }
    }

    fn generate_challenge_string(&self) -> String {
        let challenge: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();
        
        general_purpose::URL_SAFE_NO_PAD.encode(challenge.as_bytes())
    }

    async fn store_challenge(&self, challenge: String, username: Option<String>) -> String {
        let challenge_id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now();
        let expires_at = now + chrono::Duration::minutes(5);

        let data = ChallengeData {
            challenge,
            username,
            created_at: now,
            expires_at,
        };

        self.challenges.write().await.insert(challenge_id.clone(), data);
        challenge_id
    }

    #[allow(dead_code)]
    async fn cleanup_expired_challenges(&self) {
        let now = chrono::Utc::now();
        let mut challenges = self.challenges.write().await;
        
        challenges.retain(|_, data| data.expires_at > now);
    }
}

#[async_trait::async_trait]
impl WebAuthnService for InMemoryWebAuthnService {
    async fn generate_registration_challenge(
        &self,
        request: ServerPublicKeyCredentialCreationOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialCreationOptionsResponse> {
        // Validate input
        if request.username.is_empty() {
            return Err(AppError::ValidationError("Username is required".to_string()));
        }

        if request.display_name.is_empty() {
            return Err(AppError::ValidationError("Display name is required".to_string()));
        }

        // Generate challenge
        let challenge = self.generate_challenge_string();
        let _challenge_id = self.store_challenge(challenge.clone(), Some(request.username.clone())).await;

        // Create user ID (base64url encoded)
        let user_id = general_purpose::URL_SAFE_NO_PAD.encode(request.username.as_bytes());

        // Build response
        let rp = PublicKeyCredentialRpEntity {
            name: "Example Corporation".to_string(),
        };

        let user = ServerPublicKeyCredentialUserEntity {
            id: user_id,
            name: request.username.clone(),
            display_name: request.display_name,
        };

        let mut response = ServerPublicKeyCredentialCreationOptionsResponse::success(rp, user, challenge);

        // Apply request options
        if let Some(authenticator_selection) = request.authenticator_selection {
            response.authenticator_selection = Some(authenticator_selection);
        }

        if let Some(attestation) = request.attestation {
            response.attestation = Some(attestation);
        }

        Ok(response)
    }

    async fn verify_registration(
        &self,
        _request: RegistrationCompletionRequest,
    ) -> Result<RegistrationCompletionResponse> {
        // For now, just return success
        // In a real implementation, we would verify the attestation
        Ok(ServerResponse::success())
    }

    async fn generate_authentication_challenge(
        &self,
        request: ServerPublicKeyCredentialGetOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialGetOptionsResponse> {
        // Validate input
        if request.username.is_empty() {
            return Err(AppError::ValidationError("Username is required".to_string()));
        }

        // Check if user exists
        let users = self.users.read().await;
        if !users.values().any(|u| u.username == request.username) {
            return Err(AppError::NotFound("User does not exists!".to_string()));
        }

        // Generate challenge
        let challenge = self.generate_challenge_string();
        let _challenge_id = self.store_challenge(challenge.clone(), Some(request.username.clone())).await;

        // Get user credentials
        let credentials = self.credentials.read().await;
        let allow_credentials: Vec<_> = credentials
            .values()
            .filter(|cred| {
                if let Some(user) = users.get(&cred.user_id) {
                    user.username == request.username
                } else {
                    false
                }
            })
            .map(|cred| crate::models::ServerPublicKeyCredentialDescriptor {
                cred_type: "public-key".to_string(),
                id: cred.credential_id.clone(),
                transports: None,
            })
            .collect();

        let mut response = ServerPublicKeyCredentialGetOptionsResponse::success(
            challenge,
            "example.com".to_string(),
        );

        response.allow_credentials = allow_credentials;

        if let Some(user_verification) = request.user_verification {
            response.user_verification = Some(user_verification);
        }

        Ok(response)
    }

    async fn verify_authentication(
        &self,
        _request: AuthenticationCompletionRequest,
    ) -> Result<AuthenticationCompletionResponse> {
        // For now, just return success
        // In a real implementation, we would verify the assertion
        Ok(ServerResponse::success())
    }
}

/// Default WebAuthn service implementation
pub type DefaultWebAuthnService = InMemoryWebAuthnService;

#[cfg(test)]
mod webauthn_tests;