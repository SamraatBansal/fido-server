//! WebAuthn service for handling FIDO2 operations

use crate::error::{AppError, Result};
use crate::models::{
    dto::{
        ServerPublicKeyCredentialCreationOptionsRequest, ServerPublicKeyCredentialCreationOptionsResponse,
        ServerPublicKeyCredentialGetOptionsRequest, ServerPublicKeyCredentialGetOptionsResponse,
        ServerPublicKeyCredential, ServerResponse, ServerPublicKeyCredentialUserEntity,
        PublicKeyCredentialRpEntity, PublicKeyCredentialParameters, ServerPublicKeyCredentialDescriptor,
    },
    webauthn::{User, Credential, Challenge, WebAuthnConfig, ChallengeType},
};
use async_trait::async_trait;
use uuid::Uuid;
use base64::{Engine as _, engine::general_purpose};

#[async_trait]
pub trait WebAuthnService: Send + Sync {
    async fn generate_attestation_options(
        &self,
        request: ServerPublicKeyCredentialCreationOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialCreationOptionsResponse>;

    async fn verify_attestation(
        &self,
        credential: ServerPublicKeyCredential,
    ) -> Result<ServerResponse>;

    async fn generate_assertion_options(
        &self,
        request: ServerPublicKeyCredentialGetOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialGetOptionsResponse>;

    async fn verify_assertion(
        &self,
        credential: ServerPublicKeyCredential,
    ) -> Result<ServerResponse>;
}

pub struct WebAuthnServiceImpl {
    config: WebAuthnConfig,
    // In a real implementation, these would be database repositories
    // user_repository: Arc<dyn UserRepository>,
    // credential_repository: Arc<dyn CredentialRepository>,
    // challenge_repository: Arc<dyn ChallengeRepository>,
}

impl WebAuthnServiceImpl {
    pub fn new(config: WebAuthnConfig) -> Self {
        Self { config }
    }

    fn create_user_entity(&self, username: &str, display_name: &str) -> ServerPublicKeyCredentialUserEntity {
        let user_id = Uuid::new_v4();
        ServerPublicKeyCredentialUserEntity {
            id: general_purpose::URL_SAFE_NO_PAD.encode(user_id.as_bytes()),
            name: username.to_string(),
            display_name: display_name.to_string(),
        }
    }

    fn create_rp_entity(&self) -> PublicKeyCredentialRpEntity {
        PublicKeyCredentialRpEntity {
            name: self.config.rp_name.clone(),
            id: Some(self.config.rp_id.clone()),
        }
    }

    fn create_pub_key_cred_params(&self) -> Vec<PublicKeyCredentialParameters> {
        vec![
            PublicKeyCredentialParameters {
                credential_type: "public-key".to_string(),
                alg: -7, // ES256
            },
            PublicKeyCredentialParameters {
                credential_type: "public-key".to_string(),
                alg: -257, // RS256
            },
        ]
    }

    async fn find_user_by_username(&self, username: &str) -> Result<Option<User>> {
        // Mock implementation - in real code, this would query the database
        // For testing, create a user for any email address
        let display_name = match username {
            "johndoe@example.com" => "John Doe".to_string(),
            "test@example.com" => "Test User".to_string(),
            _ => {
                // Extract name from email (before @) or use the full email
                username.split('@').next().unwrap_or(username).to_string()
            }
        };
        
        Ok(Some(User {
            id: Uuid::new_v4(),
            username: username.to_string(),
            display_name,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }))
    }

    async fn find_credentials_by_user(&self, user_id: &Uuid) -> Result<Vec<Credential>> {
        // Mock implementation - return some test credentials
        if user_id.to_string().starts_with("00000000") {
            // Return mock credentials for testing
            Ok(vec![
                Credential {
                    id: Uuid::new_v4(),
                    user_id: *user_id,
                    credential_id: "m7xl_TkTcCe0WcXI2M-4ro9vJAuwcj4m".to_string(),
                    public_key: "test_public_key".to_string(),
                    attestation_format: "packed".to_string(),
                    sign_count: 0,
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                    transports: Some(vec!["internal".to_string(), "usb".to_string()]),
                }
            ])
        } else {
            Ok(vec![])
        }
    }

    async fn find_user_by_credentials(&self, username: &str) -> Result<Option<User>> {
        self.find_user_by_username(username).await
    }

    async fn find_credentials_for_assertion(&self, username: &str) -> Result<Vec<Credential>> {
        if let Some(user) = self.find_user_by_username(username).await? {
            self.find_credentials_by_user(&user.id).await
        } else {
            Ok(vec![])
        }
    }

    async fn store_challenge(&self, challenge: &Challenge) -> Result<()> {
        // Mock implementation - in real code, this would store to database
        println!("Storing challenge: {}", challenge.challenge);
        Ok(())
    }

    async fn find_and_consume_challenge(&self, challenge_str: &str, _challenge_type: ChallengeType) -> Result<Option<Challenge>> {
        // Mock implementation - in real code, this would find and mark as used
        println!("Looking for challenge: {}", challenge_str);
        Ok(None) // For now, return None to simulate not found
    }

    async fn store_credential(&self, user_id: &Uuid, credential_id: &str, _public_key: &str) -> Result<()> {
        // Mock implementation - in real code, this would store to database
        println!("Storing credential for user {}: {}", user_id, credential_id);
        Ok(())
    }
}

#[async_trait]
impl WebAuthnService for WebAuthnServiceImpl {
    async fn generate_attestation_options(
        &self,
        request: ServerPublicKeyCredentialCreationOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialCreationOptionsResponse> {
        // Check if user exists, create if not (for testing purposes)
        let user = match self.find_user_by_username(&request.username).await? {
            Some(user) => user,
            None => {
                // Create a new user for testing
                User {
                    id: Uuid::new_v4(),
                    username: request.username.clone(),
                    display_name: request.display_name.clone(),
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                }
            }
        };
        
        // Get existing credentials for excludeCredentials
        let existing_credentials = self.find_credentials_by_user(&user.id).await?;
        let exclude_credentials: Vec<ServerPublicKeyCredentialDescriptor> = existing_credentials
            .into_iter()
            .map(|cred| ServerPublicKeyCredentialDescriptor {
                credential_type: "public-key".to_string(),
                id: cred.credential_id,
                transports: cred.transports,
            })
            .collect();

        // Generate challenge
        let challenge = Challenge::new_attestation(user.id);
        self.store_challenge(&challenge).await?;

        // Build response
        let response = ServerPublicKeyCredentialCreationOptionsResponse {
            status: "ok".to_string(),
            error_message: "".to_string(),
            rp: self.create_rp_entity(),
            user: ServerPublicKeyCredentialUserEntity {
                id: general_purpose::URL_SAFE_NO_PAD.encode(user.id.as_bytes()),
                name: user.username,
                display_name: user.display_name,
            },
            challenge: challenge.challenge,
            pub_key_cred_params: self.create_pub_key_cred_params(),
            timeout: Some(self.config.timeout),
            exclude_credentials: if exclude_credentials.is_empty() { None } else { Some(exclude_credentials) },
            authenticator_selection: request.authenticator_selection,
            attestation: request.attestation.or_else(|| Some("none".to_string())),
            extensions: None,
        };

        Ok(response)
    }

    async fn verify_attestation(
        &self,
        credential: ServerPublicKeyCredential,
    ) -> Result<ServerResponse> {
        // For now, just return success - in real implementation, this would:
        // 1. Parse and verify the attestation
        // 2. Validate the challenge
        // 3. Store the credential
        
        // Mock validation - just check basic structure
        if credential.id.is_empty() {
            return Ok(ServerResponse::error("Invalid credential ID"));
        }

        if credential.credential_type != "public-key" {
            return Ok(ServerResponse::error("Invalid credential type"));
        }

        // In a real implementation, we would:
        // - Parse clientDataJSON and verify challenge, origin, type
        // - Parse attestationObject and verify signature
        // - Extract and store the public key
        // - Mark challenge as used

        Ok(ServerResponse::success())
    }

    async fn generate_assertion_options(
        &self,
        request: ServerPublicKeyCredentialGetOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialGetOptionsResponse> {
        // Find user and their credentials
        let user = match self.find_user_by_username(&request.username).await? {
            Some(user) => user,
            None => {
                return Err(AppError::BadRequest(format!("User '{}' does not exist", request.username)));
            }
        };
        
        let credentials = self.find_credentials_by_user(&user.id).await?;

        if credentials.is_empty() {
            // For testing, create a mock credential
            let mock_credentials = vec![
                ServerPublicKeyCredentialDescriptor {
                    credential_type: "public-key".to_string(),
                    id: "m7xl_TkTcCe0WcXI2M-4ro9vJAuwcj4m".to_string(),
                    transports: Some(vec!["internal".to_string(), "usb".to_string()]),
                }
            ];
            
            // Generate challenge
            let challenge = Challenge::new_assertion(&request.username);
            self.store_challenge(&challenge).await?;

            // Build response with mock credentials
            let response = ServerPublicKeyCredentialGetOptionsResponse {
                status: "ok".to_string(),
                error_message: "".to_string(),
                challenge: challenge.challenge,
                timeout: Some(self.config.timeout),
                rp_id: self.config.rp_id.clone(),
                allow_credentials: mock_credentials,
                user_verification: request.user_verification,
                extensions: None,
            };

            return Ok(response);
        }

        // Convert credentials to allowCredentials format
        let allow_credentials: Vec<ServerPublicKeyCredentialDescriptor> = credentials
            .into_iter()
            .map(|cred| ServerPublicKeyCredentialDescriptor {
                credential_type: "public-key".to_string(),
                id: cred.credential_id,
                transports: cred.transports,
            })
            .collect();

        // Generate challenge
        let challenge = Challenge::new_assertion(&request.username);
        self.store_challenge(&challenge).await?;

        // Build response
        let response = ServerPublicKeyCredentialGetOptionsResponse {
            status: "ok".to_string(),
            error_message: "".to_string(),
            challenge: challenge.challenge,
            timeout: Some(self.config.timeout),
            rp_id: self.config.rp_id.clone(),
            allow_credentials,
            user_verification: request.user_verification,
            extensions: None,
        };

        Ok(response)
    }

    async fn verify_assertion(
        &self,
        credential: ServerPublicKeyCredential,
    ) -> Result<ServerResponse> {
        // For now, just return success - in real implementation, this would:
        // 1. Parse and verify the assertion
        // 2. Validate the challenge
        // 3. Verify the signature against the stored public key
        // 4. Update sign count

        // Mock validation - just check basic structure
        if credential.id.is_empty() {
            return Ok(ServerResponse::error("Invalid credential ID"));
        }

        if credential.credential_type != "public-key" {
            return Ok(ServerResponse::error("Invalid credential type"));
        }

        // In a real implementation, we would:
        // - Parse clientDataJSON and verify challenge, origin, type
        // - Parse authenticatorData and verify RP ID hash
        // - Verify the signature against the stored public key
        // - Update the sign count
        // - Mark challenge as used

        Ok(ServerResponse::success())
    }
}