//! Simplified WebAuthn service traits and implementations

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::config::WebAuthnConfig;
use crate::db::models::{Credential, NewUser};
use crate::db::repository::{ChallengeRepository, CredentialRepository, UserRepository};
use crate::error::{AppError, Result};

// Request/Response types matching the API specification

#[derive(Debug, Deserialize)]
pub struct ServerPublicKeyCredentialCreationOptionsRequest {
    pub username: String,
    pub display_name: String,
    pub authenticator_selection: Option<serde_json::Value>,
    pub attestation: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ServerPublicKeyCredentialCreationOptionsResponse {
    pub status: String,
    #[serde(rename = "errorMessage")]
    pub error_message: String,
    pub rp: RpEntity,
    pub user: ServerPublicKeyCredentialUserEntity,
    pub challenge: String,
    pub pub_key_cred_params: Vec<CredParam>,
    pub timeout: u64,
    #[serde(rename = "excludeCredentials", skip_serializing_if = "Option::is_none")]
    pub exclude_credentials: Option<Vec<ServerPublicKeyCredentialDescriptor>>,
    pub authenticator_selection: Option<serde_json::Value>,
    pub attestation: String,
    pub extensions: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct RpEntity {
    pub name: String,
    pub id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ServerPublicKeyCredentialUserEntity {
    pub id: String,
    pub name: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
}

#[derive(Debug, Serialize)]
pub struct CredParam {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub alg: i64,
}

#[derive(Debug, Serialize)]
pub struct ServerPublicKeyCredentialDescriptor {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub id: String,
    pub transports: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct ServerPublicKeyCredential {
    pub id: String,
    pub response: ServerAuthenticatorResponse,
    #[serde(rename = "getClientExtensionResults")]
    pub get_client_extension_results: Option<serde_json::Value>,
    #[serde(rename = "type")]
    pub cred_type: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum ServerAuthenticatorResponse {
    Attestation(ServerAuthenticatorAttestationResponse),
    Assertion(ServerAuthenticatorAssertionResponse),
}

#[derive(Debug, Deserialize)]
pub struct ServerAuthenticatorAttestationResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
}

#[derive(Debug, Deserialize)]
pub struct ServerAuthenticatorAssertionResponse {
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    pub signature: String,
    #[serde(rename = "userHandle")]
    pub user_handle: Option<String>,
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
}

#[derive(Debug, Deserialize)]
pub struct ServerPublicKeyCredentialGetOptionsRequest {
    pub username: String,
    #[serde(rename = "userVerification")]
    pub user_verification: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ServerPublicKeyCredentialGetOptionsResponse {
    pub status: String,
    #[serde(rename = "errorMessage")]
    pub error_message: String,
    pub challenge: String,
    pub timeout: u64,
    #[serde(rename = "rpId")]
    pub rp_id: String,
    #[serde(rename = "allowCredentials")]
    pub allow_credentials: Vec<ServerPublicKeyCredentialDescriptor>,
    #[serde(rename = "userVerification")]
    pub user_verification: Option<String>,
}

#[async_trait]
pub trait WebAuthnService: Send + Sync {
    async fn generate_registration_challenge(
        &self,
        request: ServerPublicKeyCredentialCreationOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialCreationOptionsResponse>;

    async fn verify_registration_response(
        &self,
        response: ServerPublicKeyCredential,
    ) -> Result<crate::error::ServerResponse>;

    async fn generate_authentication_challenge(
        &self,
        request: ServerPublicKeyCredentialGetOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialGetOptionsResponse>;

    async fn verify_authentication_response(
        &self,
        response: ServerPublicKeyCredential,
    ) -> Result<crate::error::ServerResponse>;
}

pub struct WebAuthnServiceImpl<U, C, R> {
    user_repo: U,
    credential_repo: C,
    challenge_repo: R,
    config: WebAuthnConfig,
}

impl<U, C, R> WebAuthnServiceImpl<U, C, R>
where
    U: UserRepository,
    C: CredentialRepository,
    R: ChallengeRepository,
{
    pub fn new(
        config: WebAuthnConfig,
        user_repo: U,
        credential_repo: C,
        challenge_repo: R,
    ) -> Result<Self> {
        Ok(Self {
            user_repo,
            credential_repo,
            challenge_repo,
            config,
        })
    }

    fn generate_challenge_string(&self) -> String {
        let mut rng = rand::thread_rng();
        let challenge_bytes: [u8; 32] = rng.gen();
        BASE64.encode(challenge_bytes)
    }

    fn credential_to_descriptor(&self, cred: &Credential) -> ServerPublicKeyCredentialDescriptor {
        ServerPublicKeyCredentialDescriptor {
            cred_type: "public-key".to_string(),
            id: BASE64.encode(&cred.credential_id),
            transports: None,
        }
    }
}

#[async_trait]
impl<U, C, R> WebAuthnService for WebAuthnServiceImpl<U, C, R>
where
    U: UserRepository + 'static,
    C: CredentialRepository + 'static,
    R: ChallengeRepository + 'static,
{
    async fn generate_registration_challenge(
        &self,
        request: ServerPublicKeyCredentialCreationOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialCreationOptionsResponse> {
        // Find or create user
        let user = match self.user_repo.find_user_by_username(&request.username)? {
            Some(user) => user,
            None => {
                let new_user = NewUser {
                    username: request.username.clone(),
                    display_name: request.display_name.clone(),
                };
                self.user_repo.create_user(new_user)?
            }
        };

        // Get existing credentials for exclusion
        let existing_credentials = self.credential_repo.find_credentials_by_user(user.id)?;
        let exclude_credentials: Vec<ServerPublicKeyCredentialDescriptor> = existing_credentials
            .iter()
            .map(|cred| self.credential_to_descriptor(cred))
            .collect();

        // Generate challenge
        let challenge = self.generate_challenge_string();
        let expires_at = chrono::Utc::now().naive_utc() + chrono::Duration::minutes(5);

        let new_challenge = crate::db::models::NewChallenge {
            user_id: Some(user.id),
            challenge: challenge.clone(),
            challenge_type: "registration".to_string(),
            expires_at,
        };

        self.challenge_repo.create_challenge(new_challenge)?;

        // Create response
        let credential_algorithms = vec![
            CredParam {
                cred_type: "public-key".to_string(),
                alg: -7, // ES256
            },
            CredParam {
                cred_type: "public-key".to_string(),
                alg: -257, // RS256
            },
        ];

        Ok(ServerPublicKeyCredentialCreationOptionsResponse {
            status: "ok".to_string(),
            error_message: "".to_string(),
            rp: RpEntity {
                id: Some(self.config.rp_id.clone()),
                name: self.config.rp_name.clone(),
            },
            user: ServerPublicKeyCredentialUserEntity {
                id: BASE64.encode(user.id.as_bytes()),
                name: user.username,
                display_name: user.display_name,
            },
            challenge,
            pub_key_cred_params: credential_algorithms,
            timeout: self.config.timeout,
            exclude_credentials: if exclude_credentials.is_empty() {
                None
            } else {
                Some(exclude_credentials)
            },
            authenticator_selection: request.authenticator_selection,
            attestation: request.attestation.unwrap_or_else(|| "none".to_string()),
            extensions: None,
        })
    }

    async fn verify_registration_response(
        &self,
        _response: ServerPublicKeyCredential,
    ) -> Result<crate::error::ServerResponse> {
        // For now, return success - in a real implementation, this would verify the attestation
        Ok(crate::error::ServerResponse::success())
    }

    async fn generate_authentication_challenge(
        &self,
        request: ServerPublicKeyCredentialGetOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialGetOptionsResponse> {
        let user = self
            .user_repo
            .find_user_by_username(&request.username)?
            .ok_or_else(|| AppError::UserNotFound("User not found".to_string()))?;

        let credentials = self.credential_repo.find_credentials_by_user(user.id)?;
        if credentials.is_empty() {
            return Err(AppError::CredentialNotFound("No credentials found for user".to_string()));
        }

        let allow_credentials: Vec<ServerPublicKeyCredentialDescriptor> = credentials
            .iter()
            .map(|cred| self.credential_to_descriptor(cred))
            .collect();

        let challenge = self.generate_challenge_string();
        let expires_at = chrono::Utc::now().naive_utc() + chrono::Duration::minutes(5);

        let new_challenge = crate::db::models::NewChallenge {
            user_id: Some(user.id),
            challenge: challenge.clone(),
            challenge_type: "authentication".to_string(),
            expires_at,
        };

        self.challenge_repo.create_challenge(new_challenge)?;

        Ok(ServerPublicKeyCredentialGetOptionsResponse {
            status: "ok".to_string(),
            error_message: "".to_string(),
            challenge,
            timeout: self.config.timeout,
            rp_id: self.config.rp_id.clone(),
            allow_credentials,
            user_verification: request.user_verification,
        })
    }

    async fn verify_authentication_response(
        &self,
        _response: ServerPublicKeyCredential,
    ) -> Result<crate::error::ServerResponse> {
        // For now, return success - in a real implementation, this would verify the assertion
        Ok(crate::error::ServerResponse::success())
    }
}