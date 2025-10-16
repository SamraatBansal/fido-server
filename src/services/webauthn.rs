//! WebAuthn service implementation

use crate::domain::dto::*;
use crate::domain::models::*;
use crate::error::{AppError, Result};
use base64::{engine::general_purpose, Engine as _};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use validator::Validate;

/// WebAuthn service configuration
#[derive(Debug, Clone)]
pub struct WebAuthnConfig {
    pub rp_name: String,
    pub rp_id: String,
    pub rp_origin: String,
    pub timeout: u32,
}

impl Default for WebAuthnConfig {
    fn default() -> Self {
        Self {
            rp_name: "Example Corporation".to_string(),
            rp_id: "localhost".to_string(),
            rp_origin: "http://localhost:3000".to_string(),
            timeout: 60000,
        }
    }
}

/// WebAuthn service
pub struct WebAuthnService {
    config: WebAuthnConfig,
    // In-memory storage for challenges (in production, use database)
    challenges: Arc<RwLock<HashMap<String, Challenge>>>,
    // In-memory storage for users (in production, use database)
    users: Arc<RwLock<HashMap<String, User>>>,
    // In-memory storage for credentials (in production, use database)
    credentials: Arc<RwLock<HashMap<String, Vec<Credential>>>>,
}

impl WebAuthnService {
    pub fn new(config: WebAuthnConfig) -> Result<Self> {
        Ok(Self {
            config,
            challenges: Arc::new(RwLock::new(HashMap::new())),
            users: Arc::new(RwLock::new(HashMap::new())),
            credentials: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Generate registration challenge
    pub async fn generate_registration_challenge(
        &self,
        request: ServerPublicKeyCredentialCreationOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialCreationOptionsResponse> {
        // Validate request
        request.validate()?;

        // Find or create user
        let user = self.find_or_create_user(&request.username, &request.displayName).await?;

        // Generate challenge
        let challenge = general_purpose::URL_SAFE_NO_PAD.encode(&rand::random::<[u8; 32]>());

        // Store challenge
        let challenge_record = Challenge::new(
            Some(user.id.clone()),
            challenge.clone(),
            ChallengeType::Registration,
        );

        let mut challenges = self.challenges.write().await;
        challenges.insert(challenge_record.id.clone(), challenge_record);

        // Get existing credentials for exclusion
        let user_credentials = self.get_user_credentials(&user.id).await?;
        let exclude_credentials: Vec<ServerPublicKeyCredentialDescriptor> = user_credentials
            .into_iter()
            .map(|cred| ServerPublicKeyCredentialDescriptor {
                credential_type: "public-key".to_string(),
                id: general_purpose::URL_SAFE_NO_PAD.encode(&cred.credential_id),
                transports: cred.transports,
            })
            .collect();

        // Build response matching FIDO2 specification
        let response = ServerPublicKeyCredentialCreationOptionsResponse {
            status: "ok".to_string(),
            errorMessage: "".to_string(),
            rp: PublicKeyCredentialRpEntity {
                name: self.config.rp_name.clone(),
            },
            user: ServerPublicKeyCredentialUserEntity {
                id: general_purpose::URL_SAFE_NO_PAD.encode(user.id.as_bytes()),
                name: user.username,
                displayName: user.display_name,
            },
            challenge,
            pubKeyCredParams: vec![PublicKeyCredentialParameters {
                credential_type: "public-key".to_string(),
                alg: -7, // ES256
            }],
            timeout: Some(self.config.timeout),
            excludeCredentials: if exclude_credentials.is_empty() {
                None
            } else {
                Some(exclude_credentials)
            },
            authenticatorSelection: request.authenticatorSelection,
            attestation: Some(request.attestation),
            extensions: None,
        };

        Ok(response)
    }

    /// Verify registration response
    pub async fn verify_registration(
        &self,
        credential: ServerPublicKeyCredential,
    ) -> Result<ServerResponse> {
        // Validate credential
        credential.validate()?;

        let response = match credential.response {
            ServerAuthenticatorResponse::Attestation(attestation_response) => {
                attestation_response
            }
            _ => return Err(AppError::BadRequest("Expected attestation response".to_string())),
        };

        // Decode client data JSON
        let client_data_json = general_purpose::URL_SAFE_NO_PAD
            .decode(&response.clientDataJSON)
            .map_err(|_| AppError::BadRequest("Invalid clientDataJSON encoding".to_string()))?;

        let client_data: serde_json::Value = serde_json::from_slice(&client_data_json)
            .map_err(|_| AppError::BadRequest("Invalid clientDataJSON format".to_string()))?;

        // Extract challenge from client data
        let challenge = client_data
            .get("challenge")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::BadRequest("Missing challenge in clientDataJSON".to_string()))?;

        // Find and validate challenge
        let challenge_record = self.find_and_remove_challenge(challenge).await?;
        if challenge_record.is_expired() {
            return Err(AppError::ChallengeExpired);
        }

        // Get user
        let user_id = challenge_record.user_id.ok_or_else(|| {
            AppError::BadRequest("Challenge not associated with user".to_string())
        })?;
        let _user = self.get_user(&user_id).await?;

        // For now, simulate successful verification
        // In production, you'd verify the attestation object and signature
        self.store_credential(&user_id, &credential.id).await?;

        Ok(ServerResponse::success())
    }

    /// Generate authentication challenge
    pub async fn generate_authentication_challenge(
        &self,
        request: ServerPublicKeyCredentialGetOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialGetOptionsResponse> {
        // Validate request
        request.validate()?;

        // Find user
        let user = self.find_user_by_username(&request.username).await?;
        if user.is_none() {
            return Err(AppError::UserDoesNotExist);
        }
        let user = user.unwrap();

        // Get user credentials
        let user_credentials = self.get_user_credentials(&user.id).await?;
        if user_credentials.is_empty() {
            return Err(AppError::NotFound("No credentials found for user".to_string()));
        }

        // Generate challenge
        let challenge = general_purpose::URL_SAFE_NO_PAD.encode(&rand::random::<[u8; 32]>());

        // Store challenge
        let challenge_record = Challenge::new(
            Some(user.id.clone()),
            challenge.clone(),
            ChallengeType::Authentication,
        );

        let mut challenges = self.challenges.write().await;
        challenges.insert(challenge_record.id.clone(), challenge_record);

        // Build allowCredentials list
        let allow_credentials: Vec<ServerPublicKeyCredentialDescriptor> = user_credentials
            .into_iter()
            .map(|cred| ServerPublicKeyCredentialDescriptor {
                credential_type: "public-key".to_string(),
                id: general_purpose::URL_SAFE_NO_PAD.encode(&cred.credential_id),
                transports: cred.transports,
            })
            .collect();

        let response = ServerPublicKeyCredentialGetOptionsResponse {
            status: "ok".to_string(),
            errorMessage: "".to_string(),
            challenge,
            timeout: Some(self.config.timeout),
            rpId: self.config.rp_id.clone(),
            allowCredentials: Some(allow_credentials),
            userVerification: request.userVerification,
            extensions: None,
        };

        Ok(response)
    }

    /// Verify authentication response
    pub async fn verify_authentication(
        &self,
        credential: ServerPublicKeyCredential,
    ) -> Result<ServerResponse> {
        // Validate credential
        credential.validate()?;

        let response = match credential.response {
            ServerAuthenticatorResponse::Assertion(assertion_response) => assertion_response,
            _ => return Err(AppError::BadRequest("Expected assertion response".to_string())),
        };

        // Decode client data JSON
        let client_data_json = general_purpose::URL_SAFE_NO_PAD
            .decode(&response.clientDataJSON)
            .map_err(|_| AppError::BadRequest("Invalid clientDataJSON encoding".to_string()))?;

        let client_data: serde_json::Value = serde_json::from_slice(&client_data_json)
            .map_err(|_| AppError::BadRequest("Invalid clientDataJSON format".to_string()))?;

        // Extract challenge from client data
        let challenge = client_data
            .get("challenge")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::BadRequest("Missing challenge in clientDataJSON".to_string()))?;

        // Find and validate challenge
        let challenge_record = self.find_and_remove_challenge(challenge).await?;
        if challenge_record.is_expired() {
            return Err(AppError::ChallengeExpired);
        }

        // Find credential by ID
        let credential_id_bytes = general_purpose::URL_SAFE_NO_PAD
            .decode(&credential.id)
            .map_err(|_| AppError::BadRequest("Invalid credential ID encoding".to_string()))?;

        let stored_credential = self.find_credential_by_id(&credential_id_bytes).await?;
        if stored_credential.is_none() {
            return Err(AppError::NotFound("Credential not found".to_string()));
        }

        // For now, simulate successful verification
        // In production, you'd verify the signature against the stored public key
        Ok(ServerResponse::success())
    }

    // Helper methods

    async fn find_or_create_user(&self, username: &str, display_name: &str) -> Result<User> {
        let mut users = self.users.write().await;
        
        // Check if user exists
        if let Some(user) = users.values().find(|u| u.username == username) {
            return Ok(user.clone());
        }

        // Create new user
        let user = User::new(username.to_string(), display_name.to_string());
        users.insert(user.id.clone(), user.clone());
        Ok(user)
    }

    async fn find_user_by_username(&self, username: &str) -> Result<Option<User>> {
        let users = self.users.read().await;
        Ok(users.values().find(|u| u.username == username).cloned())
    }

    async fn get_user(&self, user_id: &str) -> Result<User> {
        let users = self.users.read().await;
        users
            .get(user_id)
            .cloned()
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))
    }

    async fn get_user_credentials(&self, user_id: &str) -> Result<Vec<Credential>> {
        let credentials = self.credentials.read().await;
        Ok(credentials.get(user_id).cloned().unwrap_or_default())
    }

    async fn store_credential(&self, user_id: &str, credential_id: &str) -> Result<()> {
        let credential_id_bytes = general_purpose::URL_SAFE_NO_PAD
            .decode(credential_id)
            .map_err(|_| AppError::BadRequest("Invalid credential ID encoding".to_string()))?;

        let credential = Credential::new(
            user_id.to_string(),
            credential_id_bytes,
            vec![], // Public key would be extracted from registration
            0,
            "none".to_string(),
        );

        let mut credentials = self.credentials.write().await;
        let user_credentials = credentials.entry(user_id.to_string()).or_insert_with(Vec::new);
        user_credentials.push(credential);

        Ok(())
    }

    async fn find_credential_by_id(&self, credential_id: &[u8]) -> Result<Option<Credential>> {
        let credentials = self.credentials.read().await;
        for user_credentials in credentials.values() {
            if let Some(credential) = user_credentials.iter().find(|c| c.credential_id == credential_id) {
                return Ok(Some(credential.clone()));
            }
        }
        Ok(None)
    }

    async fn find_and_remove_challenge(&self, challenge: &str) -> Result<Challenge> {
        let mut challenges = self.challenges.write().await;
        
        // Find challenge by value
        let challenge_id = challenges
            .iter()
            .find(|(_, c)| c.challenge == challenge)
            .map(|(id, _)| id.clone());

        if let Some(challenge_id) = challenge_id {
            challenges
                .remove(&challenge_id)
                .ok_or_else(|| AppError::NotFound("Challenge not found".to_string()))
        } else {
            Err(AppError::NotFound("Challenge not found".to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webauthn_config_default() {
        let config = WebAuthnConfig::default();
        assert_eq!(config.rp_name, "Example Corporation");
        assert_eq!(config.rp_id, "localhost");
        assert_eq!(config.rp_origin, "http://localhost:3000");
        assert_eq!(config.timeout, 60000);
    }

    #[tokio::test]
    async fn test_webauthn_service_creation() {
        let config = WebAuthnConfig::default();
        let service = WebAuthnService::new(config);
        assert!(service.is_ok());
    }
}