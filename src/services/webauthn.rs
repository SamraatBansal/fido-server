//! WebAuthn service implementation

use crate::error::{AppError, Result};
use crate::schema::credential::Credential;
use crate::services::challenge::ChallengeService;
use crate::services::user::UserService;
use crate::services::credential::CredentialService;
use serde_json::{json, Value};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

/// WebAuthn service for handling registration and authentication flows
pub struct WebAuthnService {
    challenge_service: ChallengeService,
    user_service: UserService,
    credential_service: CredentialService,
    rp_id: String,
    rp_name: String,
    #[allow(dead_code)]
    origin: String,
}

impl WebAuthnService {
    /// Create a new WebAuthn service
    pub fn new(
        challenge_service: ChallengeService,
        user_service: UserService,
        credential_service: CredentialService,
        rp_id: String,
        rp_name: String,
        origin: String,
    ) -> Self {
        Self {
            challenge_service,
            user_service,
            credential_service,
            rp_id,
            rp_name,
            origin,
        }
    }

    /// Start registration process
    pub async fn start_registration(&self, username: String, display_name: String) -> Result<Value> {
        // Validate input
        self.user_service.validate_username(&username)?;
        self.user_service.validate_display_name(&display_name)?;

        // Get or create user
        let user = self.user_service.get_or_create_user(username.clone(), display_name).await?;

        // Create registration challenge
        let challenge = self.challenge_service.create_registration_challenge(user.id).await?;

        // Build credential creation options
        let options = json!({
            "challenge": URL_SAFE_NO_PAD.encode(&challenge.challenge_data),
            "rp": {
                "name": self.rp_name,
                "id": self.rp_id
            },
            "user": {
                "id": URL_SAFE_NO_PAD.encode(user.id.as_bytes()),
                "name": user.username,
                "displayName": user.display_name
            },
            "pubKeyCredParams": [
                {"type": "public-key", "alg": -7}, // ES256
                {"type": "public-key", "alg": -257} // RS256
            ],
            "timeout": 60000,
            "attestation": "none",
            "authenticatorSelection": {
                "userVerification": "preferred",
                "residentKey": "discouraged"
            }
        });

        Ok(json!({
            "challengeId": challenge.id,
            "credentialCreationOptions": options
        }))
    }

    /// Finish registration process
    pub async fn finish_registration(
        &self,
        challenge_id: String,
        credential_id: Vec<u8>,
        _client_data_json: Vec<u8>,
        _attestation_object: Vec<u8>,
    ) -> Result<Value> {
        // For now, we'll implement a minimal version that validates the challenge
        // and stores the credential. In a full implementation, we would:
        // 1. Parse and validate client data JSON
        // 2. Verify the challenge matches
        // 3. Parse and validate attestation object
        // 4. Extract the public key and other credential data
        // 5. Verify the origin and RP ID
        // 6. Store the credential

        // For this TDD implementation, we'll just validate the challenge exists
        let challenge = self.challenge_service.get_challenge(&challenge_id).await?
            .ok_or_else(|| AppError::NotFound("Challenge not found".to_string()))?;

        // Validate challenge is not expired
        if challenge.is_expired() {
            return Err(AppError::BadRequest("Challenge has expired".to_string()));
        }

        // Create a basic credential (in real implementation, extract from attestation)
        let credential = Credential::new(
            credential_id.clone(),
            challenge.user_id.ok_or_else(|| AppError::BadRequest("Invalid challenge".to_string()))?,
            vec![1, 2, 3, 4], // Mock public key
            "none".to_string(),
            vec!["internal".to_string()],
        );

        // Store the credential
        self.credential_service.register_credential(credential).await?;

        // Consume the challenge
        self.challenge_service.validate_challenge(&challenge_id, &challenge.challenge_data).await?;

        Ok(json!({
            "status": "success",
            "credentialId": URL_SAFE_NO_PAD.encode(&credential_id)
        }))
    }

    /// Start authentication process
    pub async fn start_authentication(&self, username: String) -> Result<Value> {
        // Find user
        let user = self.user_service.get_user_by_username(&username).await?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

        // Get user's credentials
        let credentials = self.credential_service.get_user_credentials(&user.id).await?;

        // Create authentication challenge
        let challenge = self.challenge_service.create_authentication_challenge(user.id).await?;

        // Build allowCredentials list
        let allow_credentials: Vec<Value> = credentials.iter().map(|cred| {
            json!({
                "type": "public-key",
                "id": URL_SAFE_NO_PAD.encode(&cred.id),
                "transports": cred.transports
            })
        }).collect();

        // Build credential request options
        let options = json!({
            "challenge": URL_SAFE_NO_PAD.encode(&challenge.challenge_data),
            "allowCredentials": allow_credentials,
            "userVerification": "preferred",
            "timeout": 60000
        });

        Ok(json!({
            "challengeId": challenge.id,
            "credentialRequestOptions": options
        }))
    }

    /// Finish authentication process
    pub async fn finish_authentication(
        &self,
        challenge_id: String,
        credential_id: Vec<u8>,
        _client_data_json: Vec<u8>,
        _authenticator_data: Vec<u8>,
        _signature: Vec<u8>,
        _user_handle: Option<Vec<u8>>,
    ) -> Result<Value> {
        // For now, we'll implement a minimal version that validates the challenge
        // and updates the credential usage. In a full implementation, we would:
        // 1. Parse and validate client data JSON
        // 2. Verify the challenge matches
        // 3. Parse authenticator data
        // 4. Verify the signature
        // 5. Check the signature counter
        // 6. Update credential usage

        // Validate challenge exists and is not expired
        let challenge = self.challenge_service.get_challenge(&challenge_id).await?
            .ok_or_else(|| AppError::NotFound("Challenge not found".to_string()))?;

        if challenge.is_expired() {
            return Err(AppError::BadRequest("Challenge has expired".to_string()));
        }

        // Get credential
        let mut credential = self.credential_service.get_credential(&credential_id).await?
            .ok_or_else(|| AppError::NotFound("Credential not found".to_string()))?;

        // Mock signature verification (in real implementation, verify the signature)
        // For now, we'll just update the counter
        credential.update_usage(credential.sign_count + 1);

        // Consume the challenge
        self.challenge_service.validate_challenge(&challenge_id, &challenge.challenge_data).await?;

        Ok(json!({
            "status": "success",
            "userId": credential.user_id.to_string()
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::challenge::InMemoryChallengeStore;
    use crate::services::user::InMemoryUserRepository;
    use crate::services::credential::InMemoryCredentialRepository;

    fn create_test_service() -> WebAuthnService {
        let challenge_service = ChallengeService::new(InMemoryChallengeStore::new());
        let user_service = UserService::new(InMemoryUserRepository::new());
        let credential_service = CredentialService::new(InMemoryCredentialRepository::new());

        WebAuthnService::new(
            challenge_service,
            user_service,
            credential_service,
            "localhost".to_string(),
            "Test RP".to_string(),
            "https://localhost".to_string(),
        )
    }

    #[tokio::test]
    async fn test_start_registration_success() {
        let service = create_test_service();

        let result = service.start_registration(
            "test@example.com".to_string(),
            "Test User".to_string(),
        ).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.get("challengeId").is_some());
        assert!(response.get("credentialCreationOptions").is_some());
    }

    #[tokio::test]
    async fn test_start_registration_invalid_username() {
        let service = create_test_service();

        let result = service.start_registration(
            "invalid-email".to_string(),
            "Test User".to_string(),
        ).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::ValidationError(_)));
    }

    #[tokio::test]
    async fn test_start_authentication_success() {
        let service = create_test_service();

        // First create a user and credential
        let user = service.user_service.create_user(
            "test@example.com".to_string(),
            "Test User".to_string(),
        ).await.unwrap();

        let credential = Credential::new(
            vec![1, 2, 3, 4],
            user.id,
            vec![5, 6, 7, 8],
            "none".to_string(),
            vec!["internal".to_string()],
        );
        service.credential_service.register_credential(credential).await.unwrap();

        // Now start authentication
        let result = service.start_authentication(
            "test@example.com".to_string(),
        ).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.get("challengeId").is_some());
        assert!(response.get("credentialRequestOptions").is_some());
    }

    #[tokio::test]
    async fn test_start_authentication_user_not_found() {
        let service = create_test_service();

        let result = service.start_authentication(
            "nonexistent@example.com".to_string(),
        ).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::NotFound(_)));
    }
}