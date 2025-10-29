//! WebAuthn service traits and implementations

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::*;
use webauthn_rs_proto::{
    AuthenticatorSelectionCriteria, AuthenticationExtensionsClientInputs,
    PublicKeyCredentialParameters, PublicKeyCredentialRpEntity,
};

use crate::config::WebAuthnConfig;
use crate::db::models::{Credential, NewCredential, NewUser, User};
use crate::db::repository::{ChallengeRepository, CredentialRepository, UserRepository};
use crate::error::{AppError, Result};

// Request/Response types matching the API specification

#[derive(Debug, Deserialize)]
pub struct ServerPublicKeyCredentialCreationOptionsRequest {
    pub username: String,
    pub display_name: String,
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    pub attestation: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ServerPublicKeyCredentialCreationOptionsResponse {
    pub status: String,
    #[serde(rename = "errorMessage")]
    pub error_message: String,
    pub rp: PublicKeyCredentialRpEntity,
    pub user: ServerPublicKeyCredentialUserEntity,
    pub challenge: String,
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    pub timeout: u64,
    #[serde(rename = "excludeCredentials", skip_serializing_if = "Option::is_none")]
    pub exclude_credentials: Option<Vec<ServerPublicKeyCredentialDescriptor>>,
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    pub attestation: String,
    pub extensions: Option<AuthenticationExtensionsClientInputs>,
}

#[derive(Debug, Serialize)]
pub struct ServerPublicKeyCredentialUserEntity {
    pub id: String,
    pub name: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
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
    webauthn: Webauthn,
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
        let rp_origin = Url::parse(&config.rp_origin)
            .map_err(|e| AppError::Internal(format!("Invalid origin URL: {}", e)))?;

        let webauthn = WebauthnBuilder::new(&config.rp_id, &rp_origin)
            .rp_name(&config.rp_name)
            .build()
            .map_err(|e| AppError::Internal(format!("Failed to create WebAuthn instance: {}", e)))?;

        Ok(Self {
            webauthn,
            user_repo,
            credential_repo,
            challenge_repo,
            config,
        })
    }

    fn generate_challenge_string(&self) -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let challenge_bytes: [u8; 32] = rng.gen();
        BASE64.encode(challenge_bytes)
    }

    fn user_to_webauthn_user(&self, user: &User) -> User {
        User {
            id: user.id.as_bytes().to_vec(),
            name: user.username.clone(),
            display_name: user.display_name.clone(),
        }
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

        let new_challenge = NewChallenge {
            user_id: Some(user.id),
            challenge: challenge.clone(),
            challenge_type: "registration".to_string(),
            expires_at,
        };

        self.challenge_repo.create_challenge(new_challenge)?;

        // Convert to WebAuthn types
        let webauthn_user = self.user_to_webauthn_user(&user);

        let credential_algorithms = vec![
            PublicKeyCredentialParameters {
                alg: COSEAlgorithm::ES256,
                type_: webauthn_rs_proto::PublicKeyCredentialType::PublicKey,
            },
            PublicKeyCredentialParameters {
                alg: COSEAlgorithm::RS256,
                type_: webauthn_rs_proto::PublicKeyCredentialType::PublicKey,
            },
        ];

        let authenticator_selection = request.authenticator_selection.unwrap_or_default();

        Ok(ServerPublicKeyCredentialCreationOptionsResponse {
            status: "ok".to_string(),
            error_message: "".to_string(),
            rp: webauthn_rs_proto::PublicKeyCredentialRpEntity {
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
            authenticator_selection: Some(authenticator_selection),
            attestation: request.attestation.unwrap_or_else(|| "none".to_string()),
            extensions: None,
        })
    }

    async fn verify_registration_response(
        &self,
        response: ServerPublicKeyCredential,
    ) -> Result<crate::error::ServerResponse> {
        let attestation_response = match response.response {
            ServerAuthenticatorResponse::Attestation(att) => att,
            _ => return Err(AppError::InvalidInput("Expected attestation response".to_string())),
        };

        // Decode client data JSON
        let client_data_json = BASE64
            .decode(&attestation_response.client_data_json)
            .map_err(|e| AppError::InvalidInput(format!("Invalid client data JSON: {}", e)))?;

        // Decode attestation object
        let attestation_object = BASE64
            .decode(&attestation_response.attestation_object)
            .map_err(|e| AppError::InvalidInput(format!("Invalid attestation object: {}", e)))?;

        // Find and consume challenge
        let client_data: serde_json::Value = serde_json::from_slice(&client_data_json)
            .map_err(|e| AppError::InvalidInput(format!("Invalid client data JSON format: {}", e)))?;

        let challenge = client_data
            .get("challenge")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::InvalidInput("Missing challenge in client data".to_string()))?;

        let stored_challenge = self
            .challenge_repo
            .find_and_consume_challenge(challenge, "registration")?
            .ok_or_else(|| AppError::InvalidChallenge("Challenge not found or expired".to_string()))?;

        let user_id = stored_challenge
            .user_id
            .ok_or_else(|| AppError::Internal("Challenge has no user ID".to_string()))?;

        let user = self
            .user_repo
            .find_user_by_id(user_id)?
            .ok_or_else(|| AppError::UserNotFound("User not found".to_string()))?;

        // Create attestation response for webauthn-rs
        let attestation_resp = webauthn_rs::prelude::PublicKeyCredential {
            id: BASE64
                .decode(&response.id)
                .map_err(|e| AppError::InvalidInput(format!("Invalid credential ID: {}", e)))?,
            raw_id: BASE64
                .decode(&response.id)
                .map_err(|e| AppError::InvalidInput(format!("Invalid credential ID: {}", e)))?,
            response: webauthn_rs::prelude::AuthenticatorAttestationResponse {
                attestation_object,
                client_data_json,
            },
            type_: webauthn_rs_proto::PublicKeyCredentialType::PublicKey,
                extensions: webauthn_rs_proto::AuthenticationExtensionsClientOutputs::new(),
        };

        // Verify attestation
        let webauthn_user = self.user_to_webauthn_user(&user);
        let result = self
            .webauthn
            .register_credential(&attestation_resp, &webauthn_user)
            .map_err(|e| AppError::InvalidAttestation(format!("Attestation verification failed: {}", e)))?;

        // Store credential
        let new_credential = NewCredential {
            user_id,
            credential_id: result.cred_id.clone(),
            public_key: result.public_key.clone(),
            sign_count: result.counter as i64,
            attestation_format: "none".to_string(), // Simplified for now
            aaguid: None,
        };

        self.credential_repo.create_credential(new_credential)?;

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

        let new_challenge = NewChallenge {
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
        response: ServerPublicKeyCredential,
    ) -> Result<crate::error::ServerResponse> {
        let assertion_response = match response.response {
            ServerAuthenticatorResponse::Assertion(assert) => assert,
            _ => return Err(AppError::InvalidInput("Expected assertion response".to_string())),
        };

        // Decode client data JSON
        let client_data_json = BASE64
            .decode(&assertion_response.client_data_json)
            .map_err(|e| AppError::InvalidInput(format!("Invalid client data JSON: {}", e)))?;

        // Decode authenticator data
        let authenticator_data = BASE64
            .decode(&assertion_response.authenticator_data)
            .map_err(|e| AppError::InvalidInput(format!("Invalid authenticator data: {}", e)))?;

        // Decode signature
        let signature = BASE64
            .decode(&assertion_response.signature)
            .map_err(|e| AppError::InvalidInput(format!("Invalid signature: {}", e)))?;

        // Find and consume challenge
        let client_data: serde_json::Value = serde_json::from_slice(&client_data_json)
            .map_err(|e| AppError::InvalidInput(format!("Invalid client data JSON format: {}", e)))?;

        let challenge = client_data
            .get("challenge")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::InvalidInput("Missing challenge in client data".to_string()))?;

        let stored_challenge = self
            .challenge_repo
            .find_and_consume_challenge(challenge, "authentication")?
            .ok_or_else(|| AppError::InvalidChallenge("Challenge not found or expired".to_string()))?;

        // Find credential
        let credential_id = BASE64
            .decode(&response.id)
            .map_err(|e| AppError::InvalidInput(format!("Invalid credential ID: {}", e)))?;

        let credential = self
            .credential_repo
            .find_credential_by_id(&credential_id)?
            .ok_or_else(|| AppError::CredentialNotFound("Credential not found".to_string()))?;

        // Create assertion response for webauthn-rs
        let assertion_resp = webauthn_rs::prelude::PublicKeyCredential {
            id: credential.credential_id.clone(),
            raw_id: credential.credential_id.clone(),
            response: webauthn_rs::prelude::AuthenticatorAssertionResponse {
                authenticator_data,
                client_data_json,
                signature,
                user_handle: assertion_response
                    .user_handle
                    .and_then(|uh| BASE64.decode(&uh).ok()),
            },
            type_: webauthn_rs_proto::PublicKeyCredentialType::PublicKey,
            extensions: webauthn_rs_proto::AuthenticationExtensionsClientOutputs::new(),
        };

        // Verify assertion
        let authenticator = webauthn_rs::prelude::Authenticator {
            cred_id: credential.credential_id.clone(),
            public_key: credential.public_key.clone(),
            counter: credential.sign_count as u64,
        };

        let result = self
            .webauthn
            .authenticate_credential(&assertion_resp, &authenticator)
            .map_err(|e| AppError::InvalidAssertion(format!("Assertion verification failed: {}", e)))?;

        // Update sign count
        self.credential_repo
            .update_sign_count(&credential.credential_id, result.counter as i64)?;

        Ok(crate::error::ServerResponse::success())
    }
}