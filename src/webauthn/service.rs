//! WebAuthn service implementation
//! 
//! This module provides the core WebAuthn functionality for registration and authentication.

use crate::error::{AppError, Result};
use crate::webauthn::*;
use base64::{Engine as _, engine::general_purpose};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Trait for WebAuthn operations
#[async_trait::async_trait]
pub trait WebAuthnService: Send + Sync {
    async fn begin_registration(
        &self,
        request: ServerPublicKeyCredentialCreationOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialCreationOptionsResponse>;

    async fn finish_registration(
        &self,
        credential: ServerPublicKeyCredential,
        username: &str,
    ) -> Result<ServerResponse>;

    async fn begin_authentication(
        &self,
        request: ServerPublicKeyCredentialGetOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialGetOptionsResponse>;

    async fn finish_authentication(
        &self,
        credential: ServerAssertionPublicKeyCredential,
    ) -> Result<ServerResponse>;
}

/// In-memory challenge store for development
pub type ChallengeStore = Arc<RwLock<HashMap<String, ChallengeData>>>;

/// In-memory user store for development
pub type UserStore = Arc<RwLock<HashMap<String, User>>>;

/// In-memory credential store for development
pub type CredentialStore = Arc<RwLock<HashMap<String, Credential>>>;

/// WebAuthn service implementation
pub struct WebAuthnServiceImpl {
    config: WebAuthnConfig,
    challenge_store: ChallengeStore,
    user_store: UserStore,
    credential_store: CredentialStore,
}

impl WebAuthnServiceImpl {
    pub fn new(config: WebAuthnConfig) -> Self {
        Self {
            config,
            challenge_store: Arc::new(RwLock::new(HashMap::new())),
            user_store: Arc::new(RwLock::new(HashMap::new())),
            credential_store: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Generate a random challenge
    fn generate_challenge(&self) -> String {
        let challenge_bytes = rand::random::<[u8; 32]>();
        general_purpose::URL_SAFE_NO_PAD.encode(challenge_bytes)
    }

    /// Store a challenge
    async fn store_challenge(&self, challenge: &str, username: Option<String>, challenge_type: ChallengeType) {
        let mut challenges = self.challenge_store.write().await;
        challenges.insert(
            challenge.to_string(),
            ChallengeData {
                challenge: challenge.to_string(),
                username,
                timestamp: chrono::Utc::now(),
                challenge_type,
            },
        );
    }

    /// Validate and consume a challenge
    async fn validate_challenge(&self, challenge: &str, challenge_type: ChallengeType) -> Result<Option<String>> {
        let mut challenges = self.challenge_store.write().await;
        if let Some(challenge_data) = challenges.remove(challenge) {
            // Check if challenge is not too old (5 minutes)
            let now = chrono::Utc::now();
            let age = now.signed_duration_since(challenge_data.timestamp);
            
            if age.num_minutes() > 5 {
                return Err(AppError::BadRequest("Challenge has expired".to_string()));
            }

            // Check challenge type
            if std::mem::discriminant(&challenge_data.challenge_type) != std::mem::discriminant(&challenge_type) {
                return Err(AppError::BadRequest("Invalid challenge type".to_string()));
            }

            Ok(challenge_data.username)
        } else {
            Err(AppError::BadRequest("Invalid or already used challenge".to_string()))
        }
    }

    /// Get or create user
    async fn get_or_create_user(&self, username: &str, display_name: &str) -> Result<User> {
        let mut users = self.user_store.write().await;
        
        if let Some(user) = users.get(username) {
            Ok(user.clone())
        } else {
            let user = User {
                id: Uuid::new_v4().to_string(),
                username: username.to_string(),
                display_name: display_name.to_string(),
                created_at: chrono::Utc::now(),
            };
            users.insert(username.to_string(), user.clone());
            Ok(user)
        }
    }

    /// Get user credentials
    async fn get_user_credentials(&self, user_id: &str) -> Result<Vec<Credential>> {
        let credentials = self.credential_store.read().await;
        Ok(credentials
            .values()
            .filter(|cred| cred.user_id == user_id)
            .cloned()
            .collect())
    }

    /// Store credential
    async fn store_credential(&self, credential: Credential) -> Result<()> {
        let mut credentials = self.credential_store.write().await;
        credentials.insert(credential.id.clone(), credential);
        Ok(())
    }

    /// Get credential by ID
    async fn get_credential(&self, credential_id: &str) -> Result<Option<Credential>> {
        let credentials = self.credential_store.read().await;
        Ok(credentials.get(credential_id).cloned())
    }

    /// Update credential sign count
    async fn update_sign_count(&self, credential_id: &str, sign_count: u32) -> Result<()> {
        let mut credentials = self.credential_store.write().await;
        if let Some(credential) = credentials.get_mut(credential_id) {
            credential.sign_count = sign_count;
            credential.last_used_at = Some(chrono::Utc::now());
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl WebAuthnService for WebAuthnServiceImpl {
    async fn begin_registration(
        &self,
        request: ServerPublicKeyCredentialCreationOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialCreationOptionsResponse> {
        // Validate input
        if request.username.is_empty() {
            return Err(AppError::BadRequest("Username is required".to_string()));
        }
        if request.display_name.is_empty() {
            return Err(AppError::BadRequest("Display name is required".to_string()));
        }

        // Generate challenge
        let challenge = self.generate_challenge();
        
        // Store challenge
        self.store_challenge(&challenge, Some(request.username.clone()), ChallengeType::Registration).await;

        // Get or create user
        let user = self.get_or_create_user(&request.username, &request.display_name).await?;
        
        // Get existing credentials for exclusion
        let existing_credentials = self.get_user_credentials(&user.id).await?;
        let exclude_credentials: Vec<ServerPublicKeyCredentialDescriptor> = existing_credentials
            .into_iter()
            .map(|cred| ServerPublicKeyCredentialDescriptor {
                cred_type: "public-key".to_string(),
                id: general_purpose::URL_SAFE_NO_PAD.encode(&cred.id),
                transports: vec![],
            })
            .collect();

        // Build response
        let response = ServerPublicKeyCredentialCreationOptionsResponse {
            status: "ok".to_string(),
            error_message: "".to_string(),
            rp: PublicKeyCredentialRpEntity {
                name: self.config.rp_name.clone(),
            },
            user: ServerPublicKeyCredentialUserEntity {
                id: general_purpose::URL_SAFE_NO_PAD.encode(user.id.as_bytes()),
                name: user.username,
                display_name: user.display_name,
            },
            challenge,
            pub_key_cred_params: vec![
                PublicKeyCredentialParameters {
                    cred_type: "public-key".to_string(),
                    alg: -7, // ES256
                },
                PublicKeyCredentialParameters {
                    cred_type: "public-key".to_string(),
                    alg: -257, // RS256
                },
            ],
            timeout: Some(self.config.timeout),
            exclude_credentials,
            authenticator_selection: request.authenticator_selection,
            attestation: Some(request.attestation),
            extensions: None,
        };

        Ok(response)
    }

    async fn finish_registration(
        &self,
        credential: ServerPublicKeyCredential,
        username: &str,
    ) -> Result<ServerResponse> {
        // For now, we'll implement a simplified version
        // In a real implementation, you would verify the attestation object and client data JSON
        
        // Decode client data JSON to extract challenge
        let client_data_bytes = general_purpose::URL_SAFE_NO_PAD.decode(&credential.response.client_data_json)
            .map_err(|_| AppError::BadRequest("Invalid client data JSON".to_string()))?;
        
        let client_data: serde_json::Value = serde_json::from_slice(&client_data_bytes)
            .map_err(|_| AppError::BadRequest("Invalid client data JSON format".to_string()))?;

        let challenge = client_data.get("challenge")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::BadRequest("Missing challenge in client data".to_string()))?;

        // Validate challenge
        self.validate_challenge(challenge, ChallengeType::Registration).await?;

        // Get user
        let users = self.user_store.read().await;
        let user = users.get(username)
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))?
            .clone();

        // Store credential (simplified - in real implementation you'd extract the public key from attestation)
        let cred_id = general_purpose::URL_SAFE_NO_PAD.decode(&credential.id)
            .map_err(|_| AppError::BadRequest("Invalid credential ID".to_string()))?;

        let new_credential = Credential {
            id: credential.id.clone(),
            user_id: user.id,
            public_key: cred_id, // Simplified - should be actual public key
            sign_count: 0,
            created_at: chrono::Utc::now(),
            last_used_at: None,
        };

        self.store_credential(new_credential).await?;

        Ok(ServerResponse::success())
    }

    async fn begin_authentication(
        &self,
        request: ServerPublicKeyCredentialGetOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialGetOptionsResponse> {
        // Validate input
        if request.username.is_empty() {
            return Err(AppError::BadRequest("Username is required".to_string()));
        }

        // Get user
        let users = self.user_store.read().await;
        let user = users.get(&request.username)
            .ok_or_else(|| AppError::BadRequest("User does not exists!".to_string()))?
            .clone();

        // Generate challenge
        let challenge = self.generate_challenge();
        
        // Store challenge
        self.store_challenge(&challenge, Some(request.username.clone()), ChallengeType::Authentication).await;

        // Get user credentials
        let user_credentials = self.get_user_credentials(&user.id).await?;
        let allow_credentials: Vec<ServerPublicKeyCredentialDescriptor> = user_credentials
            .into_iter()
            .map(|cred| ServerPublicKeyCredentialDescriptor {
                cred_type: "public-key".to_string(),
                id: general_purpose::URL_SAFE_NO_PAD.encode(&cred.id),
                transports: vec![],
            })
            .collect();

        // Build response
        let response = ServerPublicKeyCredentialGetOptionsResponse {
            status: "ok".to_string(),
            error_message: "".to_string(),
            challenge,
            timeout: Some(self.config.timeout),
            rp_id: self.config.rp_id.clone(),
            allow_credentials,
            user_verification: request.user_verification,
            extensions: None,
        };

        Ok(response)
    }

    async fn finish_authentication(
        &self,
        credential: ServerAssertionPublicKeyCredential,
    ) -> Result<ServerResponse> {
        // For now, we'll implement a simplified version
        // In a real implementation, you would verify the signature and authenticator data
        
        // Decode client data JSON to extract challenge
        let client_data_bytes = general_purpose::URL_SAFE_NO_PAD.decode(&credential.response.client_data_json)
            .map_err(|_| AppError::BadRequest("Invalid client data JSON".to_string()))?;
        
        let client_data: serde_json::Value = serde_json::from_slice(&client_data_bytes)
            .map_err(|_| AppError::BadRequest("Invalid client data JSON format".to_string()))?;

        let challenge = client_data.get("challenge")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::BadRequest("Missing challenge in client data".to_string()))?;

        // Validate challenge
        let _username = self.validate_challenge(challenge, ChallengeType::Authentication).await?;

        // Get credential
        let _stored_credential = self.get_credential(&credential.id)
            .await?
            .ok_or_else(|| AppError::BadRequest("Credential not found".to_string()))?;

        // In a real implementation, you would:
        // 1. Verify the signature
        // 2. Check the authenticator data
        // 3. Update the sign count
        // 4. Verify the user verification if required

        // For now, just return success
        Ok(ServerResponse::success())
    }
}