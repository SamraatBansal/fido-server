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
mod tests {
    use super::*;
    use crate::models::{
        ServerPublicKeyCredentialCreationOptionsRequest,
        ServerPublicKeyCredentialGetOptionsRequest,
        AuthenticatorSelectionCriteria,
        AttestationConveyancePreference,
        RegistrationCompletionRequest,
        AuthenticationCompletionRequest,
    };
    use serde_json::json;

    #[tokio::test]
    async fn test_generate_registration_challenge_success() {
        let service = InMemoryWebAuthnService::new();
        
        let request = ServerPublicKeyCredentialCreationOptionsRequest {
            username: "test@example.com".to_string(),
            display_name: "Test User".to_string(),
            authenticator_selection: Some(AuthenticatorSelectionCriteria::default()),
            attestation: Some(AttestationConveyancePreference::Direct),
        };

        let result = service.generate_registration_challenge(request).await;
        
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status, "ok");
        assert_eq!(response.error_message, "");
        assert_eq!(response.rp.name, "Example Corporation");
        assert_eq!(response.user.name, "test@example.com");
        assert_eq!(response.user.display_name, "Test User");
        assert!(!response.challenge.is_empty());
        assert!(response.challenge.len() >= 16);
        assert_eq!(response.pub_key_cred_params.len(), 1);
        assert_eq!(response.pub_key_cred_params[0].alg, -7);
        assert_eq!(response.pub_key_cred_params[0].cred_type, "public-key");
    }

    #[tokio::test]
    async fn test_generate_registration_challenge_missing_username() {
        let service = InMemoryWebAuthnService::new();
        
        let request = ServerPublicKeyCredentialCreationOptionsRequest {
            username: "".to_string(),
            display_name: "Test User".to_string(),
            authenticator_selection: None,
            attestation: None,
        };

        let result = service.generate_registration_challenge(request).await;
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::ValidationError(_)));
    }

    #[tokio::test]
    async fn test_verify_registration_success() {
        let service = InMemoryWebAuthnService::new();
        
        let request = RegistrationCompletionRequest {
            id: "test-credential-id".to_string(),
            cred_type: "public-key".to_string(),
            response: json!({
                "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0=",
                "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAQ"
            }),
            get_client_extension_results: Some(json!({})),
        };

        let result = service.verify_registration(request).await;
        
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status, "ok");
        assert_eq!(response.error_message, "");
    }

    #[tokio::test]
    async fn test_generate_authentication_challenge_user_not_found() {
        let service = InMemoryWebAuthnService::new();
        
        let request = ServerPublicKeyCredentialGetOptionsRequest {
            username: "nonexistent@example.com".to_string(),
            user_verification: Some("required".to_string()),
        };

        let result = service.generate_authentication_challenge(request).await;
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::NotFound(_)));
    }

    #[tokio::test]
    async fn test_verify_authentication_success() {
        let service = InMemoryWebAuthnService::new();
        
        let request = AuthenticationCompletionRequest {
            id: "test-credential-id".to_string(),
            cred_type: "public-key".to_string(),
            response: json!({
                "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0=",
                "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA",
                "signature": "MEUCIQDpo2qM4TF8Fc8z1LXf5I4QqvLp5oKjZl5XG_wR1A",
                "userHandle": ""
            }),
            get_client_extension_results: Some(json!({})),
        };

        let result = service.verify_authentication(request).await;
        
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status, "ok");
        assert_eq!(response.error_message, "");
    }

    #[tokio::test]
    async fn test_challenge_generation_entropy() {
        let service = InMemoryWebAuthnService::new();
        
        // Generate multiple challenges and verify they're unique
        let mut challenges = std::collections::HashSet::new();
        
        for _ in 0..100 {
            let challenge = service.generate_challenge_string();
            assert!(!challenge.is_empty());
            assert!(challenge.len() >= 16);
            challenges.insert(challenge);
        }
        
        // All challenges should be unique
        assert_eq!(challenges.len(), 100);
    }
}